package engine

// Hysteria2, implemented from the protocol as realized by the
// reference implementation (sing-quic/hysteria2):
//
//   - QUIC transport with ALPN "h3"; an HTTP/3 stack rides the
//     connection purely for authentication and masquerade.
//   - Auth: HTTP POST https://hysteria/auth with headers
//     Hysteria-Auth: <password>, Hysteria-CC-RX: <client rx bps or 0>,
//     Hysteria-Padding: <random string>. Success = status 233 with
//     Hysteria-UDP and Hysteria-CC-RX response headers. Failures get
//     an ordinary 404 (masquerade).
//   - TCP: raw QUIC streams dispatched by their first varint (frame
//     type 0x401), then [addrLen varint]["host:port"][padLen][pad];
//     the server replies [status byte][msg vstring][pad varint][pad]
//     before payload flows.
//   - UDP: QUIC datagrams [sessionID(4)][packetID(2)][fragID(1)]
//     [fragTotal(1)][dest vstring][payload]; the client allocates
//     session IDs sequentially. Fragmentation mirrors the reference
//     (1200-byte datagram budget).
//   - Bandwidth/brutal congestion control is negotiated via headers
//     but is a local transport behavior; this implementation answers
//     "auto/0" and keeps quic-go's default controller, which is
//     wire-compatible. Salamander/Gecko obfuscation is not supported.

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/quic-go"
	"github.com/sagernet/quic-go/http3"
	"github.com/sagernet/quic-go/quicvarint"
)

const (
	hy2FrameTypeTCPRequest = 0x401
	hy2StatusAuthOK        = 233
	hy2URLHost             = "hysteria"
	hy2URLPath             = "/auth"
	hy2HeaderAuth          = "Hysteria-Auth"
	hy2HeaderUDP           = "Hysteria-UDP"
	hy2HeaderCCRX          = "Hysteria-CC-RX"
	hy2HeaderPadding       = "Hysteria-Padding"
	hy2MaxDatagram         = 1197
	hy2MaxUDPSize          = 4096
)

func hy2QUICConfig() *quic.Config {
	return &quic.Config{
		EnableDatagrams:                true,
		MaxIncomingStreams:             1 << 60,
		MaxIncomingUniStreams:          1 << 60,
		InitialStreamReceiveWindow:     8 << 20,
		MaxStreamReceiveWindow:         32 << 20,
		InitialConnectionReceiveWindow: 32 << 20,
		MaxConnectionReceiveWindow:    64 << 20,
		MaxIdleTimeout:                 30 * time.Second,
		KeepAlivePeriod:                10 * time.Second,
	}
}

// hy2Padding returns a random alphanumeric string in [min, max).
func hy2Padding(min, max int) string {
	const chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	n := min
	if max > min {
		n += rand.Intn(max - min)
	}
	b := make([]byte, n)
	for i := range b {
		b[i] = chars[rand.Intn(len(chars))]
	}
	return string(b)
}

// ---- varint helpers (QUIC varint encoding) ----

func hy2AppendVarint(b []byte, v uint64) []byte {
	return quicvarint.Append(b, v)
}

func hy2ReadVarint(r io.Reader) (uint64, error) {
	return quicvarint.Read(quicvarint.NewReader(r))
}

func hy2WriteVString(b *bytes.Buffer, s string) {
	b.Write(hy2AppendVarint(nil, uint64(len(s))))
	b.WriteString(s)
}

func hy2ReadVString(r io.Reader) (string, error) {
	n, err := hy2ReadVarint(r)
	if err != nil {
		return "", err
	}
	if n > 2048 {
		return "", errors.New("hy2: string too long")
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return "", err
	}
	return string(buf), nil
}

// ---- TCP request/response ----

func hy2TCPRequestBytes(addr string, payload []byte) []byte {
	pad := hy2Padding(64, 512)
	var b bytes.Buffer
	b.Write(hy2AppendVarint(nil, hy2FrameTypeTCPRequest))
	hy2WriteVString(&b, addr)
	b.Write(hy2AppendVarint(nil, uint64(len(pad))))
	b.WriteString(pad)
	b.Write(payload)
	return b.Bytes()
}

func hy2ReadTCPRequest(r io.Reader) (string, error) {
	addr, err := hy2ReadVString(r)
	if err != nil {
		return "", err
	}
	padLen, err := hy2ReadVarint(r)
	if err != nil {
		return "", err
	}
	if padLen > 4096 {
		return "", errors.New("hy2: padding too long")
	}
	if padLen > 0 {
		if _, err := io.CopyN(io.Discard, r, int64(padLen)); err != nil {
			return "", err
		}
	}
	return addr, nil
}

func hy2TCPResponseBytes(ok bool, msg string, payload []byte) []byte {
	if len(msg) > 2048 {
		msg = msg[:2048]
	}
	pad := hy2Padding(128, 1024)
	var b bytes.Buffer
	if ok {
		b.WriteByte(0)
	} else {
		b.WriteByte(1)
	}
	hy2WriteVString(&b, msg)
	b.Write(hy2AppendVarint(nil, uint64(len(pad))))
	b.WriteString(pad)
	b.Write(payload)
	return b.Bytes()
}

func hy2ReadTCPResponse(r io.Reader) error {
	var status [1]byte
	if _, err := io.ReadFull(r, status[:]); err != nil {
		return err
	}
	msg, err := hy2ReadVString(r)
	if err != nil {
		return err
	}
	padLen, err := hy2ReadVarint(r)
	if err != nil {
		return err
	}
	if padLen > 4096 {
		return errors.New("hy2: padding too long")
	}
	if padLen > 0 {
		if _, err := io.CopyN(io.Discard, r, int64(padLen)); err != nil {
			return err
		}
	}
	if status[0] != 0 {
		return fmt.Errorf("hy2: remote error: %s", msg)
	}
	return nil
}

// ---- UDP messages ----

type hy2UDPMessage struct {
	sessionID uint32
	packetID  uint16
	fragID    uint8
	fragTotal uint8
	dest      string
	data      []byte
}

func (m *hy2UDPMessage) headerSize() int {
	return 4 + 2 + 1 + 1 + len(quicvarint.Append(nil, uint64(len(m.dest)))) + len(m.dest)
}

func (m *hy2UDPMessage) pack() []byte {
	var b bytes.Buffer
	_ = binary.Write(&b, binary.BigEndian, m.sessionID)
	_ = binary.Write(&b, binary.BigEndian, m.packetID)
	b.WriteByte(m.fragID)
	b.WriteByte(m.fragTotal)
	hy2WriteVString(&b, m.dest)
	b.Write(m.data)
	return b.Bytes()
}

func decodeHY2Message(b []byte) (*hy2UDPMessage, error) {
	r := bytes.NewReader(b)
	m := &hy2UDPMessage{}
	if err := binary.Read(r, binary.BigEndian, &m.sessionID); err != nil {
		return nil, err
	}
	if err := binary.Read(r, binary.BigEndian, &m.packetID); err != nil {
		return nil, err
	}
	var fb [2]byte
	if _, err := io.ReadFull(r, fb[:]); err != nil {
		return nil, err
	}
	m.fragID, m.fragTotal = fb[0], fb[1]
	dest, err := hy2ReadVString(r)
	if err != nil {
		return nil, err
	}
	m.dest = dest
	m.data = append([]byte(nil), b[len(b)-r.Len():]...)
	return m, nil
}

func fragHY2Message(m *hy2UDPMessage, maxSize int) []*hy2UDPMessage {
	chunk := maxSize - m.headerSize()
	if len(m.data) <= chunk || chunk <= 0 {
		return []*hy2UDPMessage{m}
	}
	var out []*hy2UDPMessage
	data := m.data
	for len(data) > 0 {
		n := chunk
		if n > len(data) {
			n = len(data)
		}
		f := *m
		f.data = data[:n]
		out = append(out, &f)
		data = data[n:]
	}
	for i, f := range out {
		f.fragTotal = uint8(len(out))
		f.fragID = uint8(i)
	}
	return out
}

// hy2Defragger reassembles fragmented messages by packetID.
type hy2Defragger struct {
	mu    sync.Mutex
	parts map[uint16]*hy2FragItem
}

type hy2FragItem struct {
	total   uint8
	got     int
	session uint32
	dest    string
	chunks  map[uint8][]byte
}

func newHY2Defragger() *hy2Defragger {
	return &hy2Defragger{parts: make(map[uint16]*hy2FragItem)}
}

func (d *hy2Defragger) feed(m *hy2UDPMessage) *hy2UDPMessage {
	if m.fragTotal <= 1 {
		return m
	}
	if m.fragID >= m.fragTotal {
		return nil
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	item, ok := d.parts[m.packetID]
	if !ok || item.total != m.fragTotal {
		item = &hy2FragItem{total: m.fragTotal, session: m.sessionID, dest: m.dest, chunks: make(map[uint8][]byte)}
		d.parts[m.packetID] = item
	}
	if _, dup := item.chunks[m.fragID]; dup {
		return nil
	}
	item.chunks[m.fragID] = m.data
	item.got++
	if item.got < int(item.total) {
		return nil
	}
	delete(d.parts, m.packetID)
	full := &hy2UDPMessage{sessionID: item.session, packetID: m.packetID, fragTotal: 1, dest: item.dest}
	for i := uint8(0); i < item.total; i++ {
		full.data = append(full.data, item.chunks[i]...)
	}
	return full
}

// ---- server ----

// HY2Server serves one Hysteria2 inbound on an engine-bound PacketConn.
type HY2Server struct {
	Password    string
	Meter       *TrafficMeter
	Tag         string
	UDPSocketFn udpSocketFunc
}

// Serve starts accepting QUIC connections.
func (s *HY2Server) Serve(pc net.PacketConn, tlsConf *tls.Config) (io.Closer, error) {
	transport := &quic.Transport{Conn: pc}
	listener, err := transport.Listen(tlsConf, hy2QUICConfig())
	if err != nil {
		return nil, err
	}
	go func() {
		for {
			conn, err := listener.Accept(context.Background())
			if err != nil {
				return
			}
			go s.handleConn(conn)
		}
	}()
	return &quicListenerCloser{listener: listener, transport: transport, pc: pc}, nil
}

func (s *HY2Server) handleConn(conn *quic.Conn) {
	if s.Meter != nil {
		s.Meter.Open(s.Tag)
		defer s.Meter.Close(s.Tag)
	}
	sess := &hy2ServerSession{
		srv:  s,
		conn: conn,
		udp:  make(map[uint32]*hy2UDPAssoc),
	}
	h3srv := &http3.Server{
		Handler:          sess,
		StreamDispatcher: sess.dispatchStream,
	}
	_ = h3srv.ServeQUICConn(conn)
	sess.closeAllUDP()
	_ = conn.CloseWithError(0, "")
}

type hy2ServerSession struct {
	srv  *HY2Server
	conn *quic.Conn

	authMu        sync.Mutex
	authenticated bool
	udpOnce       sync.Once

	udpMu sync.Mutex
	udp   map[uint32]*hy2UDPAssoc
}

// ServeHTTP implements the hysteria2 authentication endpoint (and the
// masquerade for everything else).
func (sess *hy2ServerSession) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost || r.Host != hy2URLHost || r.URL.Path != hy2URLPath {
		http.NotFound(w, r)
		return
	}
	sess.authMu.Lock()
	already := sess.authenticated
	sess.authMu.Unlock()
	if !already {
		if subtleCompare(r.Header.Get(hy2HeaderAuth), sess.srv.Password) != 1 {
			http.NotFound(w, r) // masquerade
			return
		}
		sess.authMu.Lock()
		sess.authenticated = true
		sess.authMu.Unlock()
		sess.udpOnce.Do(func() { go sess.loopDatagrams() })
	}
	h := w.Header()
	h.Set(hy2HeaderUDP, "true")
	h.Set(hy2HeaderCCRX, "0")
	h.Set(hy2HeaderPadding, hy2Padding(256, 2048))
	w.WriteHeader(hy2StatusAuthOK)
}

func (sess *hy2ServerSession) isAuthed() bool {
	sess.authMu.Lock()
	defer sess.authMu.Unlock()
	return sess.authenticated
}

// dispatchStream routes raw QUIC streams whose first frame type is
// the hysteria2 TCP request marker, mirroring the reference server.
func (sess *hy2ServerSession) dispatchStream(frameType http3.FrameType, stream *quic.Stream, err error) (bool, error) {
	if !sess.isAuthed() || err != nil {
		return false, nil
	}
	if uint64(frameType) != hy2FrameTypeTCPRequest {
		return false, nil
	}
	// The dispatcher peeked the frame type; consume it from the stream.
	if _, err := hy2ReadVarint(stream); err != nil {
		return true, nil
	}
	go sess.handleStream(stream)
	return true, nil
}

func (sess *hy2ServerSession) handleStream(stream *quic.Stream) {
	conn := &tuicStreamConn{Stream: stream, local: sess.conn.LocalAddr(), remote: sess.conn.RemoteAddr()}
	addrStr, err := hy2ReadTCPRequest(stream)
	if err != nil {
		conn.Close()
		return
	}
	target, err := ParseHostPort(addrStr)
	if err != nil {
		_, _ = stream.Write(hy2TCPResponseBytes(false, err.Error(), nil))
		conn.Close()
		return
	}
	upstream, err := DialDirect(target)
	if err != nil {
		_, _ = stream.Write(hy2TCPResponseBytes(false, err.Error(), nil))
		conn.Close()
		return
	}
	defer upstream.Close()
	if _, err := stream.Write(hy2TCPResponseBytes(true, "", nil)); err != nil {
		conn.Close()
		return
	}
	var relayConn net.Conn = conn
	if sess.srv.Meter != nil {
		relayConn = sess.srv.Meter.wrapConn(sess.srv.Tag, conn)
	}
	Relay(relayConn, upstream)
}

func (sess *hy2ServerSession) loopDatagrams() {
	for {
		data, err := sess.conn.ReceiveDatagram(context.Background())
		if err != nil {
			return
		}
		msg, err := decodeHY2Message(data)
		if err != nil {
			continue
		}
		sess.handleUDPMessage(msg)
	}
}

func (sess *hy2ServerSession) handleUDPMessage(msg *hy2UDPMessage) {
	sess.udpMu.Lock()
	assoc, ok := sess.udp[msg.sessionID]
	if !ok {
		var err error
		assoc, err = newHY2UDPAssoc(sess, msg.sessionID)
		if err != nil {
			sess.udpMu.Unlock()
			return
		}
		sess.udp[msg.sessionID] = assoc
	}
	sess.udpMu.Unlock()
	assoc.forward(msg)
}

func (sess *hy2ServerSession) closeAllUDP() {
	sess.udpMu.Lock()
	all := sess.udp
	sess.udp = make(map[uint32]*hy2UDPAssoc)
	sess.udpMu.Unlock()
	for _, a := range all {
		a.close()
	}
}

// hy2UDPAssoc mirrors the TUIC association design, datagrams only.
type hy2UDPAssoc struct {
	sess     *hy2ServerSession
	id       uint32
	sock     net.PacketConn
	defrag   *hy2Defragger
	packetID atomic.Uint32
	done     chan struct{}
	once     sync.Once
	lastUse  atomic.Int64
}

func newHY2UDPAssoc(sess *hy2ServerSession, id uint32) (*hy2UDPAssoc, error) {
	sockFn := sess.srv.UDPSocketFn
	if sockFn == nil {
		sockFn = defaultUDPSocket
	}
	sock, err := sockFn()
	if err != nil {
		return nil, err
	}
	a := &hy2UDPAssoc{
		sess:   sess,
		id:     id,
		sock:   sock,
		defrag: newHY2Defragger(),
		done:   make(chan struct{}),
	}
	a.lastUse.Store(time.Now().UnixNano())
	if sess.srv.Meter != nil {
		sess.srv.Meter.Open(sess.srv.Tag)
	}
	go a.replyPump()
	go a.janitor()
	return a, nil
}

func (a *hy2UDPAssoc) janitor() {
	tick := time.NewTicker(30 * time.Second)
	defer tick.Stop()
	for {
		select {
		case <-a.done:
			return
		case now := <-tick.C:
			if now.Sub(time.Unix(0, a.lastUse.Load())) > 300*time.Second {
				a.sess.udpMu.Lock()
				delete(a.sess.udp, a.id)
				a.sess.udpMu.Unlock()
				a.close()
				return
			}
		}
	}
}

func (a *hy2UDPAssoc) forward(msg *hy2UDPMessage) {
	full := a.defrag.feed(msg)
	if full == nil {
		return
	}
	target, err := ParseHostPort(full.dest)
	if err != nil {
		return
	}
	dst, err := resolveUDPAddr(target)
	if err != nil || dst == nil {
		return
	}
	if _, err := a.sock.WriteTo(full.data, dst); err == nil {
		a.lastUse.Store(time.Now().UnixNano())
		if a.sess.srv.Meter != nil {
			a.sess.srv.Meter.AddUp(a.sess.srv.Tag, len(full.data))
		}
	}
}

func (a *hy2UDPAssoc) replyPump() {
	buf := make([]byte, 65535)
	for {
		n, src, err := a.sock.ReadFrom(buf)
		if err != nil {
			return
		}
		a.lastUse.Store(time.Now().UnixNano())
		if a.sess.srv.Meter != nil {
			a.sess.srv.Meter.AddDown(a.sess.srv.Tag, n)
		}
		msg := &hy2UDPMessage{
			sessionID: a.id,
			packetID:  uint16(a.packetID.Add(1)),
			fragTotal: 1,
			dest:      src.String(),
			data:      append([]byte(nil), buf[:n]...),
		}
		for _, frag := range fragHY2Message(msg, hy2MaxDatagram) {
			if err := a.sess.conn.SendDatagram(frag.pack()); err != nil {
				return
			}
		}
	}
}

func (a *hy2UDPAssoc) close() {
	a.once.Do(func() {
		close(a.done)
		a.sock.Close()
		if a.sess.srv.Meter != nil {
			a.sess.srv.Meter.Close(a.sess.srv.Tag)
		}
	})
}

// ---- client ----

// HY2Client is a Hysteria2 client session.
type HY2Client struct {
	conn       *quic.Conn
	pc         net.PacketConn
	transport  *quic.Transport
	h3tr       *http3.Transport
	udpEnabled bool

	mu          sync.Mutex
	udp         map[uint32]*HY2UDPConn
	nextSession uint32
	done        chan struct{}
}

// DialHY2 opens a HY2 session over a fresh UDP socket.
func DialHY2(server string, sni string, password string) (*HY2Client, error) {
	pc, err := defaultUDPSocket()
	if err != nil {
		return nil, err
	}
	raddr, err := net.ResolveUDPAddr("udp", server)
	if err != nil {
		pc.Close()
		return nil, err
	}
	return DialHY2Packet(pc, raddr, sni, password)
}

// DialHY2Packet opens a HY2 session over an injected PacketConn.
func DialHY2Packet(pc net.PacketConn, serverAddr net.Addr, sni string, password string) (*HY2Client, error) {
	transport := &quic.Transport{Conn: pc}
	tlsConf := &tls.Config{
		ServerName:         sni,
		InsecureSkipVerify: true, // panel nodes use self-signed certs
		NextProtos:         []string{http3.NextProtoH3},
	}
	quicConf := hy2QUICConfig()
	c := &HY2Client{
		pc:        pc,
		transport: transport,
		udp:       make(map[uint32]*HY2UDPConn),
		done:      make(chan struct{}),
	}
	var quicConn *quic.Conn
	h3tr := &http3.Transport{
		TLSClientConfig: tlsConf,
		QUICConfig:      quicConf,
		Dial: func(ctx context.Context, _ string, tcfg *tls.Config, qcfg *quic.Config) (*quic.Conn, error) {
			conn, err := transport.Dial(ctx, serverAddr, tcfg, qcfg)
			if err != nil {
				return nil, err
			}
			quicConn = conn
			return conn, nil
		},
	}
	c.h3tr = h3tr
	req, err := http.NewRequest(http.MethodPost, "https://"+hy2URLHost+hy2URLPath, nil)
	if err != nil {
		pc.Close()
		return nil, err
	}
	req.Header.Set(hy2HeaderAuth, password)
	req.Header.Set(hy2HeaderCCRX, "0")
	req.Header.Set(hy2HeaderPadding, hy2Padding(256, 2048))
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	resp, err := h3tr.RoundTrip(req.WithContext(ctx))
	if err != nil {
		pc.Close()
		return nil, err
	}
	resp.Body.Close()
	if resp.StatusCode != hy2StatusAuthOK {
		pc.Close()
		return nil, fmt.Errorf("hy2: authentication failed, status %d", resp.StatusCode)
	}
	c.conn = quicConn
	c.udpEnabled = resp.Header.Get(hy2HeaderUDP) == "true"
	go c.loopDatagrams()
	return c, nil
}

func (c *HY2Client) loopDatagrams() {
	for {
		data, err := c.conn.ReceiveDatagram(context.Background())
		if err != nil {
			return
		}
		msg, err := decodeHY2Message(data)
		if err != nil {
			continue
		}
		c.mu.Lock()
		uc := c.udp[msg.sessionID]
		c.mu.Unlock()
		if uc != nil {
			uc.deliver(msg)
		}
	}
}

// DialTCP opens a HY2 TCP stream to target.
func (c *HY2Client) DialTCP(target Addr) (net.Conn, error) {
	stream, err := c.conn.OpenStream()
	if err != nil {
		return nil, err
	}
	if _, err := stream.Write(hy2TCPRequestBytes(target.String(), nil)); err != nil {
		stream.Close()
		return nil, err
	}
	return &hy2ClientConn{
		tuicStreamConn: &tuicStreamConn{Stream: stream, local: c.conn.LocalAddr(), remote: c.conn.RemoteAddr()},
	}, nil
}

// hy2ClientConn lazily consumes the TCP response header on first Read.
type hy2ClientConn struct {
	*tuicStreamConn
	respOnce sync.Once
	respErr  error
}

func (c *hy2ClientConn) Read(p []byte) (int, error) {
	c.respOnce.Do(func() {
		c.respErr = hy2ReadTCPResponse(c.Stream)
	})
	if c.respErr != nil {
		return 0, c.respErr
	}
	return c.Stream.Read(p)
}

// ListenUDP opens a HY2 UDP association.
func (c *HY2Client) ListenUDP() (net.PacketConn, error) {
	if !c.udpEnabled {
		return nil, errors.New("hy2: UDP disabled by server")
	}
	c.mu.Lock()
	id := c.nextSession
	c.nextSession++
	uc := &HY2UDPConn{
		client:  c,
		id:      id,
		defrag:  newHY2Defragger(),
		done:    make(chan struct{}),
		changed: make(chan struct{}),
	}
	c.udp[id] = uc
	c.mu.Unlock()
	return uc, nil
}

// Close terminates the client session.
func (c *HY2Client) Close() error {
	select {
	case <-c.done:
		return nil
	default:
		close(c.done)
	}
	c.mu.Lock()
	for _, uc := range c.udp {
		uc.closeLocal()
	}
	c.mu.Unlock()
	_ = c.h3tr.Close()
	_ = c.conn.CloseWithError(0, "")
	return c.pc.Close()
}

// HY2UDPConn is one client-side HY2 UDP association (net.PacketConn).
type HY2UDPConn struct {
	client *HY2Client
	id     uint32

	defrag   *hy2Defragger
	packetID atomic.Uint32

	mu       sync.Mutex
	pending  [][]byte
	pendingA []string
	changed  chan struct{}
	readDL   time.Time
	done     chan struct{}
	once     sync.Once
}

func (u *HY2UDPConn) deliver(msg *hy2UDPMessage) {
	full := u.defrag.feed(msg)
	if full == nil {
		return
	}
	u.mu.Lock()
	u.pending = append(u.pending, full.data)
	u.pendingA = append(u.pendingA, full.dest)
	close(u.changed)
	u.changed = make(chan struct{})
	u.mu.Unlock()
}

func (u *HY2UDPConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	if len(p) > hy2MaxUDPSize {
		return 0, errors.New("hy2: packet too large")
	}
	msg := &hy2UDPMessage{
		sessionID: u.id,
		packetID:  uint16(u.packetID.Add(1)),
		fragTotal: 1,
		dest:      addr.String(),
		data:      append([]byte(nil), p...),
	}
	for _, frag := range fragHY2Message(msg, hy2MaxDatagram) {
		if err := u.client.conn.SendDatagram(frag.pack()); err != nil {
			return 0, err
		}
	}
	return len(p), nil
}

func (u *HY2UDPConn) ReadFrom(p []byte) (int, net.Addr, error) {
	for {
		u.mu.Lock()
		if len(u.pending) > 0 {
			data := u.pending[0]
			src := u.pendingA[0]
			u.pending = u.pending[1:]
			u.pendingA = u.pendingA[1:]
			u.mu.Unlock()
			n := copy(p, data)
			ua, err := net.ResolveUDPAddr("udp", src)
			if err != nil {
				return n, &net.UDPAddr{Port: 0}, nil
			}
			return n, ua, nil
		}
		select {
		case <-u.done:
			u.mu.Unlock()
			return 0, nil, io.ErrClosedPipe
		default:
		}
		ch := u.changed
		dl := u.readDL
		u.mu.Unlock()
		var timer *time.Timer
		var timeout <-chan time.Time
		if !dl.IsZero() {
			d := time.Until(dl)
			if d <= 0 {
				return 0, nil, os.ErrDeadlineExceeded
			}
			timer = time.NewTimer(d)
			timeout = timer.C
		}
		select {
		case <-ch:
			if timer != nil {
				timer.Stop()
			}
		case <-timeout:
			return 0, nil, os.ErrDeadlineExceeded
		case <-u.done:
			if timer != nil {
				timer.Stop()
			}
			return 0, nil, io.ErrClosedPipe
		}
	}
}

func (u *HY2UDPConn) closeLocal() {
	u.once.Do(func() { close(u.done) })
}

func (u *HY2UDPConn) Close() error {
	u.closeLocal()
	u.client.mu.Lock()
	delete(u.client.udp, u.id)
	u.client.mu.Unlock()
	return nil
}

func (u *HY2UDPConn) LocalAddr() net.Addr { return u.client.conn.LocalAddr() }

func (u *HY2UDPConn) SetDeadline(t time.Time) error     { return u.SetReadDeadline(t) }
func (u *HY2UDPConn) SetWriteDeadline(time.Time) error  { return nil }
func (u *HY2UDPConn) SetReadDeadline(t time.Time) error {
	u.mu.Lock()
	u.readDL = t
	close(u.changed)
	u.changed = make(chan struct{})
	u.mu.Unlock()
	return nil
}

// subtleCompare is a constant-time string comparison (auth checks).
func subtleCompare(a, b string) int {
	if len(a) != len(b) {
		return 0
	}
	var v byte
	for i := 0; i < len(a); i++ {
		v |= a[i] ^ b[i]
	}
	if v == 0 {
		return 1
	}
	return 0
}
