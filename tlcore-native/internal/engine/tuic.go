package engine

// TUIC v5, implemented from the protocol specification as realized by
// the reference implementation (sing-quic/tuic):
//
//   - QUIC transport (ALPN "h3"), datagrams enabled.
//   - Authentication: the client opens a unidirectional stream and
//     writes [ver=5][cmd=0][UUID(16)][token(32)], where the token is
//     the TLS 1.3 exporter with label = UUID bytes and context =
//     password (ExportKeyingMaterial, 32 bytes).
//   - TCP: a bidirectional stream starting [5][1][address]; the rest
//     is payload. Address codec: 0x00 FQDN (len-prefixed), 0x01 IPv4,
//     0x02 IPv6, 0xff empty — each followed by a 2-byte port.
//   - UDP: "Packet" messages [5][2][sessionID(2)][packetID(2)]
//     [fragTotal(1)][fragID(1)][payloadLen(2)][address][payload],
//     carried in QUIC datagrams or (stream mode) unidirectional
//     streams; replies mirror the arrival transport. Sessions are
//     released with a Dissociate uni-stream message [5][3][id(2)].
//   - Heartbeats: datagram [5][4] every 10 seconds.
//
// Congestion control is a local transport concern and stays at the
// quic-go default on both sides, which is wire-compatible.

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/quic-go"
)

const (
	tuicVersion       = 5
	tuicCmdAuth       = 0
	tuicCmdConnect    = 1
	tuicCmdPacket     = 2
	tuicCmdDissociate = 3
	tuicCmdHeartbeat  = 4

	tuicAuthLen    = 2 + 16 + 32
	tuicMaxDatagram = 1197 // reference UDP MTU budget
)

// formatUUID renders 16 bytes as a canonical UUID string.
func formatUUID(b [16]byte) string {
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

func tuicQUICConfig() *quic.Config {
	return &quic.Config{
		EnableDatagrams:         true,
		MaxIncomingStreams:      1 << 60,
		MaxIncomingUniStreams:   1 << 60,
		MaxIdleTimeout:          30 * time.Second,
		KeepAlivePeriod:         10 * time.Second,
	}
}

// ---- address codec ----

func writeTUICAddr(w io.Writer, a Addr) error {
	var b []byte
	switch {
	case a.IPv4:
		b = append(b, 0x01)
		b = append(b, net.ParseIP(a.Host).To4()...)
	case a.IPv6:
		b = append(b, 0x02)
		b = append(b, net.ParseIP(a.Host).To16()...)
	case a.Host == "":
		b = append(b, 0xff) // empty (used by later fragments)
	default:
		b = append(b, 0x00, byte(len(a.Host)))
		b = append(b, a.Host...)
	}
	var p [2]byte
	binary.BigEndian.PutUint16(p[:], uint16(a.Port))
	b = append(b, p[:]...)
	_, err := w.Write(b)
	return err
}

func readTUICAddr(r io.Reader) (Addr, error) {
	var t [1]byte
	if _, err := io.ReadFull(r, t[:]); err != nil {
		return Addr{}, err
	}
	var a Addr
	switch t[0] {
	case 0x00:
		var l [1]byte
		if _, err := io.ReadFull(r, l[:]); err != nil {
			return Addr{}, err
		}
		host := make([]byte, int(l[0]))
		if _, err := io.ReadFull(r, host); err != nil {
			return Addr{}, err
		}
		a.Host = string(host)
	case 0x01:
		var ip [4]byte
		if _, err := io.ReadFull(r, ip[:]); err != nil {
			return Addr{}, err
		}
		a.Host = net.IP(ip[:]).String()
		a.IPv4 = true
	case 0x02:
		var ip [16]byte
		if _, err := io.ReadFull(r, ip[:]); err != nil {
			return Addr{}, err
		}
		a.Host = net.IP(ip[:]).String()
		a.IPv6 = true
	case 0xff:
		// empty address; port still follows
	default:
		return Addr{}, fmt.Errorf("tuic: unknown address type %d", t[0])
	}
	var p [2]byte
	if _, err := io.ReadFull(r, p[:]); err != nil {
		return Addr{}, err
	}
	a.Port = int(binary.BigEndian.Uint16(p[:]))
	return a, nil
}

func tuicAddrLen(a Addr) int {
	switch {
	case a.IPv4:
		return 1 + 4 + 2
	case a.IPv6:
		return 1 + 16 + 2
	case a.Host == "":
		return 1 + 2
	default:
		return 2 + len(a.Host) + 2
	}
}

// ---- UDP messages ----

type tuicUDPMessage struct {
	sessionID uint16
	packetID  uint16
	fragTotal uint8
	fragID    uint8
	dest      Addr
	data      []byte
}

func (m *tuicUDPMessage) headerSize() int {
	return 2 + 2 + 2 + 1 + 1 + 2 + tuicAddrLen(m.dest)
}

// pack returns the full datagram bytes (including [ver][cmd]).
func (m *tuicUDPMessage) pack() []byte {
	var b bytes.Buffer
	b.WriteByte(tuicVersion)
	b.WriteByte(tuicCmdPacket)
	_ = binary.Write(&b, binary.BigEndian, m.sessionID)
	_ = binary.Write(&b, binary.BigEndian, m.packetID)
	b.WriteByte(m.fragTotal)
	b.WriteByte(m.fragID)
	_ = binary.Write(&b, binary.BigEndian, uint16(len(m.data)))
	_ = writeTUICAddr(&b, m.dest)
	b.Write(m.data)
	return b.Bytes()
}

// decodeTUICMessage parses a datagram body after [ver][cmd].
func decodeTUICMessage(b []byte) (*tuicUDPMessage, error) {
	r := bytes.NewReader(b)
	return readTUICMessage(r, true)
}

// readTUICMessage parses one message from a stream (after [ver][cmd]);
// when exact is true the payload must consume the remaining input.
func readTUICMessage(r io.Reader, exact bool) (*tuicUDPMessage, error) {
	m := &tuicUDPMessage{}
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
	m.fragTotal, m.fragID = fb[0], fb[1]
	var dataLen uint16
	if err := binary.Read(r, binary.BigEndian, &dataLen); err != nil {
		return nil, err
	}
	dest, err := readTUICAddr(r)
	if err != nil {
		return nil, err
	}
	m.dest = dest
	m.data = make([]byte, int(dataLen))
	if _, err := io.ReadFull(r, m.data); err != nil {
		return nil, err
	}
	if exact {
		if br, ok := r.(*bytes.Reader); ok && br.Len() != 0 {
			return nil, io.ErrUnexpectedEOF
		}
	}
	return m, nil
}

// fragTUICMessage splits a message so each packed datagram fits maxSize.
func fragTUICMessage(m *tuicUDPMessage, maxSize int) []*tuicUDPMessage {
	chunk := maxSize - m.headerSize()
	if len(m.data) <= chunk || chunk <= 0 {
		return []*tuicUDPMessage{m}
	}
	var out []*tuicUDPMessage
	data := m.data
	for len(data) > 0 {
		n := chunk
		if n > len(data) {
			n = len(data)
		}
		f := *m
		f.data = data[:n]
		if len(out) > 0 {
			f.dest = Addr{}
		}
		out = append(out, &f)
		data = data[n:]
	}
	for i, f := range out {
		f.fragTotal = uint8(len(out))
		f.fragID = uint8(i)
	}
	return out
}

// tuicDefragger reassembles fragmented messages, keyed by packetID.
type tuicDefragger struct {
	mu    sync.Mutex
	parts map[uint16]*tuicFragItem
}

type tuicFragItem struct {
	total   uint8
	got     int
	session uint16
	dest    Addr
	chunks  map[uint8][]byte
}

func newTUICDefragger() *tuicDefragger {
	return &tuicDefragger{parts: make(map[uint16]*tuicFragItem)}
}

// feed returns the reassembled message once complete, else nil.
func (d *tuicDefragger) feed(m *tuicUDPMessage) *tuicUDPMessage {
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
		item = &tuicFragItem{total: m.fragTotal, session: m.sessionID, dest: m.dest, chunks: make(map[uint8][]byte)}
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
	full := &tuicUDPMessage{sessionID: item.session, packetID: m.packetID, fragTotal: 1, dest: item.dest}
	for i := uint8(0); i < item.total; i++ {
		full.data = append(full.data, item.chunks[i]...)
	}
	return full
}

// ---- stream adapter (quic.Stream -> net.Conn with addresses) ----

type tuicStreamConn struct {
	*quic.Stream
	local  net.Addr
	remote net.Addr
}

func (c *tuicStreamConn) LocalAddr() net.Addr {
	if c.local != nil {
		return c.local
	}
	return &net.UDPAddr{}
}

func (c *tuicStreamConn) RemoteAddr() net.Addr {
	if c.remote != nil {
		return c.remote
	}
	return &net.UDPAddr{}
}

func (c *tuicStreamConn) Close() error {
	c.Stream.CancelRead(0)
	err := c.Stream.Close()
	c.Stream.SetWriteDeadline(time.Now())
	return err
}

// ---- server ----

// TUICServer serves one TUIC inbound on an engine-bound PacketConn.
type TUICServer struct {
	UUID        [16]byte
	Password    string
	Meter       *TrafficMeter
	Tag         string
	UDPSocketFn udpSocketFunc
}

// Serve starts accepting QUIC connections; the returned closer stops
// the listener and releases the PacketConn.
func (s *TUICServer) Serve(pc net.PacketConn, tlsConf *tls.Config) (io.Closer, error) {
	transport := &quic.Transport{Conn: pc}
	listener, err := transport.Listen(tlsConf, tuicQUICConfig())
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

type quicListenerCloser struct {
	listener  *quic.Listener
	transport *quic.Transport
	pc        net.PacketConn
}

func (c *quicListenerCloser) Close() error {
	// Close the PacketConn FIRST: quic.Transport.Close waits for its
	// packet-read loop to exit, and for an injected (non-UDP) conn its
	// SetReadDeadline nudge may never reach the blocked ReadFrom.
	// Closing the socket is the reliable unblock on every transport.
	err := c.pc.Close()
	_ = c.listener.Close()
	_ = c.transport.Close()
	return err
}

type tuicServerSession struct {
	srv      *TUICServer
	conn     *quic.Conn
	authDone chan struct{}
	authOnce sync.Once
	done     chan struct{}

	udpMu sync.Mutex
	udp   map[uint16]*tuicUDPAssoc
}

func (s *TUICServer) handleConn(conn *quic.Conn) {
	if s.Meter != nil {
		s.Meter.Open(s.Tag)
		defer s.Meter.Close(s.Tag)
	}
	sess := &tuicServerSession{
		srv:      s,
		conn:     conn,
		authDone: make(chan struct{}),
		done:     make(chan struct{}),
		udp:      make(map[uint16]*tuicUDPAssoc),
	}
	defer close(sess.done)
	defer conn.CloseWithError(0, "")
	go sess.loopUniStreams()
	go sess.loopStreams()
	go sess.loopDatagrams()
	go sess.loopHeartbeat()
	go sess.authTimeout()
	<-conn.Context().Done()
	sess.closeAllUDP()
}

func (sess *tuicServerSession) authed() bool {
	select {
	case <-sess.authDone:
		return true
	default:
		return false
	}
}

func (sess *tuicServerSession) authTimeout() {
	select {
	case <-sess.authDone:
	case <-sess.done:
	case <-time.After(5 * time.Second):
		sess.conn.CloseWithError(1, "authentication timeout")
	}
}

func (sess *tuicServerSession) loopHeartbeat() {
	tick := time.NewTicker(10 * time.Second)
	defer tick.Stop()
	for {
		select {
		case <-sess.done:
			return
		case <-tick.C:
			if err := sess.conn.SendDatagram([]byte{tuicVersion, tuicCmdHeartbeat}); err != nil {
				return
			}
		}
	}
}

func (sess *tuicServerSession) loopUniStreams() {
	for {
		stream, err := sess.conn.AcceptUniStream(context.Background())
		if err != nil {
			return
		}
		go sess.handleUniStream(stream)
	}
}

func (sess *tuicServerSession) handleUniStream(stream *quic.ReceiveStream) {
	defer stream.CancelRead(0)
	var hdr [2]byte
	if _, err := io.ReadFull(stream, hdr[:]); err != nil {
		return
	}
	if hdr[0] != tuicVersion {
		sess.conn.CloseWithError(2, "unknown version")
		return
	}
	switch hdr[1] {
	case tuicCmdAuth:
		body := make([]byte, tuicAuthLen-2)
		if _, err := io.ReadFull(stream, body); err != nil {
			return
		}
		var uuid [16]byte
		copy(uuid[:], body[:16])
		if uuid != sess.srv.UUID {
			sess.conn.CloseWithError(3, "unknown user")
			return
		}
		cs := sess.conn.ConnectionState().TLS
		token, err := cs.ExportKeyingMaterial(string(uuid[:]), []byte(sess.srv.Password), 32)
		if err != nil || !bytes.Equal(token, body[16:48]) {
			sess.conn.CloseWithError(3, "token mismatch")
			return
		}
		sess.authOnce.Do(func() { close(sess.authDone) })
	case tuicCmdPacket:
		if !sess.waitAuth() {
			return
		}
		msg, err := readTUICMessage(stream, false)
		if err != nil {
			return
		}
		sess.handleUDPMessage(msg, true)
	case tuicCmdDissociate:
		var idb [2]byte
		if _, err := io.ReadFull(stream, idb[:]); err != nil {
			return
		}
		sess.closeUDP(binary.BigEndian.Uint16(idb[:]))
	default:
		sess.conn.CloseWithError(2, "unknown command")
	}
}

// waitAuth blocks until authenticated or the connection dies.
func (sess *tuicServerSession) waitAuth() bool {
	select {
	case <-sess.authDone:
		return true
	case <-sess.done:
		return false
	}
}

func (sess *tuicServerSession) loopStreams() {
	for {
		stream, err := sess.conn.AcceptStream(context.Background())
		if err != nil {
			return
		}
		go sess.handleStream(stream)
	}
}

func (sess *tuicServerSession) handleStream(stream *quic.Stream) {
	conn := &tuicStreamConn{Stream: stream, local: sess.conn.LocalAddr(), remote: sess.conn.RemoteAddr()}
	var hdr [2]byte
	if _, err := io.ReadFull(stream, hdr[:]); err != nil {
		conn.Close()
		return
	}
	if hdr[0] != tuicVersion || hdr[1] != tuicCmdConnect {
		conn.Close()
		return
	}
	target, err := readTUICAddr(stream)
	if err != nil {
		conn.Close()
		return
	}
	if !sess.waitAuth() {
		conn.Close()
		return
	}
	upstream, err := DialDirect(target)
	if err != nil {
		conn.Close()
		return
	}
	defer upstream.Close()
	var relayConn net.Conn = conn
	if sess.srv.Meter != nil {
		relayConn = sess.srv.Meter.wrapConn(sess.srv.Tag, conn)
	}
	Relay(relayConn, upstream)
}

func (sess *tuicServerSession) loopDatagrams() {
	if !sess.waitAuth() {
		return
	}
	for {
		data, err := sess.conn.ReceiveDatagram(context.Background())
		if err != nil {
			return
		}
		if len(data) < 2 || data[0] != tuicVersion {
			continue
		}
		switch data[1] {
		case tuicCmdPacket:
			msg, err := decodeTUICMessage(data[2:])
			if err != nil {
				continue
			}
			sess.handleUDPMessage(msg, false)
		case tuicCmdHeartbeat:
			// liveness only
		}
	}
}

func (sess *tuicServerSession) handleUDPMessage(msg *tuicUDPMessage, viaStream bool) {
	sess.udpMu.Lock()
	assoc, ok := sess.udp[msg.sessionID]
	if !ok {
		var err error
		assoc, err = newTUICUDPAssoc(sess, msg.sessionID, viaStream)
		if err != nil {
			sess.udpMu.Unlock()
			return
		}
		sess.udp[msg.sessionID] = assoc
	}
	sess.udpMu.Unlock()
	assoc.forward(msg)
}

func (sess *tuicServerSession) closeUDP(id uint16) {
	sess.udpMu.Lock()
	assoc := sess.udp[id]
	delete(sess.udp, id)
	sess.udpMu.Unlock()
	if assoc != nil {
		assoc.close()
	}
}

func (sess *tuicServerSession) closeAllUDP() {
	sess.udpMu.Lock()
	all := sess.udp
	sess.udp = make(map[uint16]*tuicUDPAssoc)
	sess.udpMu.Unlock()
	for _, a := range all {
		a.close()
	}
}

// tuicUDPAssoc is one server-side UDP association: client packets are
// forwarded over a dedicated outbound socket; replies are packed back
// over the transport the session's packets arrived on.
type tuicUDPAssoc struct {
	sess      *tuicServerSession
	id        uint16
	viaStream bool
	sock      net.PacketConn
	defrag    *tuicDefragger
	packetID  atomic.Uint32
	done      chan struct{}
	once      sync.Once
	lastUse   atomic.Int64
}

func newTUICUDPAssoc(sess *tuicServerSession, id uint16, viaStream bool) (*tuicUDPAssoc, error) {
	sockFn := sess.srv.UDPSocketFn
	if sockFn == nil {
		sockFn = defaultUDPSocket
	}
	sock, err := sockFn()
	if err != nil {
		return nil, err
	}
	a := &tuicUDPAssoc{
		sess:      sess,
		id:        id,
		viaStream: viaStream,
		sock:      sock,
		defrag:    newTUICDefragger(),
		done:      make(chan struct{}),
	}
	a.lastUse.Store(time.Now().UnixNano())
	if sess.srv.Meter != nil {
		sess.srv.Meter.Open(sess.srv.Tag)
	}
	go a.replyPump()
	go a.janitor()
	return a, nil
}

func (a *tuicUDPAssoc) janitor() {
	tick := time.NewTicker(30 * time.Second)
	defer tick.Stop()
	for {
		select {
		case <-a.done:
			return
		case now := <-tick.C:
			if now.Sub(time.Unix(0, a.lastUse.Load())) > 300*time.Second {
				a.sess.closeUDP(a.id)
				return
			}
		}
	}
}

func (a *tuicUDPAssoc) forward(msg *tuicUDPMessage) {
	full := a.defrag.feed(msg)
	if full == nil {
		return
	}
	dst, err := resolveUDPAddr(full.dest)
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

func (a *tuicUDPAssoc) replyPump() {
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
		srcAddr, err := addrToAddr(src)
		if err != nil {
			continue
		}
		msg := &tuicUDPMessage{
			sessionID: a.id,
			packetID:  uint16(a.packetID.Add(1)),
			fragTotal: 1,
			dest:      srcAddr,
			data:      append([]byte(nil), buf[:n]...),
		}
		for _, frag := range fragTUICMessage(msg, tuicMaxDatagram) {
			packed := frag.pack()
			if a.viaStream {
				stream, err := a.sess.conn.OpenUniStream()
				if err != nil {
					return
				}
				_, _ = stream.Write(packed)
				stream.Close()
			} else {
				if err := a.sess.conn.SendDatagram(packed); err != nil {
					return
				}
			}
		}
	}
}

func (a *tuicUDPAssoc) close() {
	a.once.Do(func() {
		close(a.done)
		a.sock.Close()
		if a.sess.srv.Meter != nil {
			a.sess.srv.Meter.Close(a.sess.srv.Tag)
		}
	})
}

// ---- client ----

// TUICClient is a TUIC client session: one QUIC connection carrying
// any number of TCP streams and UDP associations.
type TUICClient struct {
	conn *quic.Conn
	pc   net.PacketConn
	uuid [16]byte

	mu          sync.Mutex
	udp         map[uint16]*TUICUDPConn
	nextSession uint16
	done        chan struct{}
}

// DialTUIC opens a TUIC client session over a fresh UDP socket.
func DialTUIC(server string, sni string, uuid [16]byte, password string) (*TUICClient, error) {
	pc, err := defaultUDPSocket()
	if err != nil {
		return nil, err
	}
	raddr, err := net.ResolveUDPAddr("udp", server)
	if err != nil {
		pc.Close()
		return nil, err
	}
	return DialTUICPacket(pc, raddr, sni, uuid, password)
}

// DialTUICPacket opens a TUIC client session over an injected
// PacketConn (used with in-memory transports in tests).
func DialTUICPacket(pc net.PacketConn, serverAddr net.Addr, sni string, uuid [16]byte, password string) (*TUICClient, error) {
	transport := &quic.Transport{Conn: pc}
	tlsConf := &tls.Config{
		ServerName:         sni,
		InsecureSkipVerify: true, // panel nodes use self-signed certs
		NextProtos:         []string{"h3"},
	}
	conn, err := transport.Dial(context.Background(), serverAddr, tlsConf, tuicQUICConfig())
	if err != nil {
		pc.Close()
		return nil, err
	}
	c := &TUICClient{
		conn: conn,
		pc:   pc,
		uuid: uuid,
		udp:  make(map[uint16]*TUICUDPConn),
		done: make(chan struct{}),
	}
	// Authenticate on a unidirectional stream.
	cs := conn.ConnectionState().TLS
	token, err := cs.ExportKeyingMaterial(string(uuid[:]), []byte(password), 32)
	if err != nil {
		c.Close()
		return nil, err
	}
	authStream, err := conn.OpenUniStream()
	if err != nil {
		c.Close()
		return nil, err
	}
	var auth bytes.Buffer
	auth.WriteByte(tuicVersion)
	auth.WriteByte(tuicCmdAuth)
	auth.Write(uuid[:])
	auth.Write(token)
	if _, err := authStream.Write(auth.Bytes()); err != nil {
		c.Close()
		return nil, err
	}
	authStream.Close()
	go c.loopDatagrams()
	go c.loopHeartbeat()
	return c, nil
}

func (c *TUICClient) loopHeartbeat() {
	tick := time.NewTicker(10 * time.Second)
	defer tick.Stop()
	for {
		select {
		case <-c.done:
			return
		case <-tick.C:
			if err := c.conn.SendDatagram([]byte{tuicVersion, tuicCmdHeartbeat}); err != nil {
				return
			}
		}
	}
}

func (c *TUICClient) loopDatagrams() {
	for {
		data, err := c.conn.ReceiveDatagram(context.Background())
		if err != nil {
			return
		}
		if len(data) < 2 || data[0] != tuicVersion {
			continue
		}
		if data[1] != tuicCmdPacket {
			continue // heartbeat
		}
		msg, err := decodeTUICMessage(data[2:])
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

// DialTCP opens a TUIC Connect stream to target.
func (c *TUICClient) DialTCP(target Addr) (net.Conn, error) {
	stream, err := c.conn.OpenStream()
	if err != nil {
		return nil, err
	}
	var hdr bytes.Buffer
	hdr.WriteByte(tuicVersion)
	hdr.WriteByte(tuicCmdConnect)
	if err := writeTUICAddr(&hdr, target); err != nil {
		stream.Close()
		return nil, err
	}
	if _, err := stream.Write(hdr.Bytes()); err != nil {
		stream.Close()
		return nil, err
	}
	return &tuicStreamConn{Stream: stream, local: c.conn.LocalAddr(), remote: c.conn.RemoteAddr()}, nil
}

// ListenUDP opens a TUIC UDP association (datagram mode).
func (c *TUICClient) ListenUDP() (net.PacketConn, error) {
	c.mu.Lock()
	id := c.nextSession
	c.nextSession++
	uc := &TUICUDPConn{
		client:  c,
		id:      id,
		defrag:  newTUICDefragger(),
		done:    make(chan struct{}),
		changed: make(chan struct{}),
	}
	c.udp[id] = uc
	c.mu.Unlock()
	return uc, nil
}

// Close terminates the client session.
func (c *TUICClient) Close() error {
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
	_ = c.conn.CloseWithError(0, "")
	return c.pc.Close()
}

// TUICUDPConn is one client-side UDP association (net.PacketConn).
type TUICUDPConn struct {
	client *TUICClient
	id     uint16

	defrag   *tuicDefragger
	packetID atomic.Uint32

	mu       sync.Mutex
	pending  [][]byte
	pendingA []Addr
	changed  chan struct{}
	readDL   time.Time
	done     chan struct{}
	once     sync.Once
}

func (u *TUICUDPConn) deliver(msg *tuicUDPMessage) {
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

func (u *TUICUDPConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	dest, err := addrToAddr(addr)
	if err != nil {
		return 0, err
	}
	msg := &tuicUDPMessage{
		sessionID: u.id,
		packetID:  uint16(u.packetID.Add(1)),
		fragTotal: 1,
		dest:      dest,
		data:      append([]byte(nil), p...),
	}
	for _, frag := range fragTUICMessage(msg, tuicMaxDatagram) {
		if err := u.client.conn.SendDatagram(frag.pack()); err != nil {
			return 0, err
		}
	}
	return len(p), nil
}

func (u *TUICUDPConn) ReadFrom(p []byte) (int, net.Addr, error) {
	for {
		u.mu.Lock()
		if len(u.pending) > 0 {
			data := u.pending[0]
			src := u.pendingA[0]
			u.pending = u.pending[1:]
			u.pendingA = u.pendingA[1:]
			u.mu.Unlock()
			n := copy(p, data)
			ua, err := resolveUDPAddr(src)
			if err != nil {
				return n, &net.UDPAddr{Port: int(src.Port)}, nil
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

func (u *TUICUDPConn) closeLocal() {
	u.once.Do(func() { close(u.done) })
}

// Close releases the association (sends Dissociate).
func (u *TUICUDPConn) Close() error {
	u.closeLocal()
	u.client.mu.Lock()
	delete(u.client.udp, u.id)
	u.client.mu.Unlock()
	stream, err := u.client.conn.OpenUniStream()
	if err == nil {
		var b bytes.Buffer
		b.WriteByte(tuicVersion)
		b.WriteByte(tuicCmdDissociate)
		_ = binary.Write(&b, binary.BigEndian, u.id)
		_, _ = stream.Write(b.Bytes())
		stream.Close()
	}
	return nil
}

func (u *TUICUDPConn) LocalAddr() net.Addr { return u.client.conn.LocalAddr() }

func (u *TUICUDPConn) SetDeadline(t time.Time) error      { return u.SetReadDeadline(t) }
func (u *TUICUDPConn) SetWriteDeadline(time.Time) error   { return nil }
func (u *TUICUDPConn) SetReadDeadline(t time.Time) error {
	u.mu.Lock()
	u.readDL = t
	close(u.changed)
	u.changed = make(chan struct{})
	u.mu.Unlock()
	return nil
}

// addrToAddr converts a net.Addr to an engine Addr.
func addrToAddr(a net.Addr) (Addr, error) {
	switch v := a.(type) {
	case *net.UDPAddr:
		return addrFromUDP(v), nil
	default:
		return ParseHostPort(a.String())
	}
}
