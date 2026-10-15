package engine

// AnyTLS (v2), implemented from the protocol's public design and
// cross-checked against the reference implementation's wire behavior:
//
//	over TLS, the client first sends SHA-256(password) (32 bytes), a
//	2-byte big-endian padding length and that many zero bytes (record
//	shaping). Then a multiplexed session of frames
//	[cmd(1) | streamID(4) | length(2) | data]:
//	  0 Waste · 1 SYN · 2 PSH · 3 FIN · 4 Settings · 5 Alert
//	  6 UpdatePaddingScheme · 7 SYNACK · 8/9 heartbeat · 10 ServerSettings
//	The client opens with a Settings frame (v=2, padding scheme MD5);
//	the server answers ServerSettings and per-stream SYNACK once the
//	upstream is dialed. Each stream's first bytes are the target's
//	SOCKS address; the rest is payload. Client writes for the first
//	<stop> packets are shaped to the padding scheme's record sizes.
//
// TCP streams only (no UDP-over-stream), matching the protocol's
// primary deployment mode.

import (
	"bufio"
	"bytes"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	atCmdWaste               = 0
	atCmdSYN                 = 1
	atCmdPSH                 = 2
	atCmdFIN                 = 3
	atCmdSettings            = 4
	atCmdAlert               = 5
	atCmdUpdatePaddingScheme = 6
	atCmdSYNACK              = 7
	atCmdHeartRequest        = 8
	atCmdHeartResponse       = 9
	atCmdServerSettings      = 10

	atHeaderSize = 7 // cmd(1) + sid(4) + len(2)
	atCheckMark  = -1
)

// ---- padding scheme ----

const atDefaultPaddingScheme = `stop=8
0=30-30
1=100-400
2=400-500,c,500-1000,c,500-1000,c,500-1000,c,500-1000
3=9-9,500-1000
4=500-1000
5=500-1000
6=500-1000
7=500-1000`

type atPaddingFactory struct {
	raw    []byte
	md5hex string
	stop   uint32
	ranges map[uint32]string
}

func newAtPaddingFactory(raw []byte) *atPaddingFactory {
	f := &atPaddingFactory{raw: raw, md5hex: fmt.Sprintf("%x", md5.Sum(raw)), ranges: map[uint32]string{}}
	for _, line := range strings.Split(string(raw), "\n") {
		kv := strings.SplitN(line, "=", 2)
		if len(kv) != 2 {
			continue
		}
		if kv[0] == "stop" {
			n, err := strconv.Atoi(kv[1])
			if err != nil {
				return nil
			}
			f.stop = uint32(n)
			continue
		}
		if idx, err := strconv.Atoi(kv[0]); err == nil {
			f.ranges[uint32(idx)] = kv[1]
		}
	}
	return f
}

// recordSizes returns the target payload sizes for packet pkt.
func (f *atPaddingFactory) recordSizes(pkt uint32) []int {
	spec, ok := f.ranges[pkt]
	if !ok {
		return nil
	}
	var out []int
	for _, part := range strings.Split(spec, ",") {
		if part == "c" {
			out = append(out, atCheckMark)
			continue
		}
		mm := strings.Split(part, "-")
		if len(mm) != 2 {
			continue
		}
		lo, err1 := strconv.ParseInt(mm[0], 10, 64)
		hi, err2 := strconv.ParseInt(mm[1], 10, 64)
		if err1 != nil || err2 != nil {
			continue
		}
		if lo > hi {
			lo, hi = hi, lo
		}
		if lo <= 0 || hi <= 0 {
			continue
		}
		if lo == hi {
			out = append(out, int(lo))
		} else {
			n, _ := rand.Int(rand.Reader, big.NewInt(hi-lo))
			out = append(out, int(n.Int64()+lo))
		}
	}
	return out
}

// ---- string map (settings payload) ----

func atStringMapBytes(m map[string]string) []byte {
	lines := make([]string, 0, len(m))
	for k, v := range m {
		lines = append(lines, k+"="+v)
	}
	return []byte(strings.Join(lines, "\n"))
}

func atParseStringMap(b []byte) map[string]string {
	m := make(map[string]string)
	for _, line := range strings.Split(string(b), "\n") {
		if kv := strings.SplitN(line, "=", 2); len(kv) == 2 {
			m[kv[0]] = kv[1]
		}
	}
	return m
}

// ---- stream ----

// anyTLSStream is one multiplexed stream, implementing net.Conn.
type anyTLSStream struct {
	id   uint32
	sess *anyTLSSession

	mu       sync.Mutex
	changed  chan struct{}
	chunks   [][]byte
	off      int
	readEOF  bool
	readErr  error
	readDL   time.Time
	closed   bool // FIN sent / locally torn down
	reportOnce sync.Once
	dieOnce    sync.Once
}

func newAnyTLSStream(id uint32, sess *anyTLSSession) *anyTLSStream {
	return &anyTLSStream{id: id, sess: sess, changed: make(chan struct{})}
}

func (s *anyTLSStream) signalLocked() {
	close(s.changed)
	s.changed = make(chan struct{})
}

// feed appends received payload (called by the session receive loop).
func (s *anyTLSStream) feed(data []byte) {
	cp := make([]byte, len(data))
	copy(cp, data)
	s.mu.Lock()
	s.chunks = append(s.chunks, cp)
	s.signalLocked()
	s.mu.Unlock()
}

// closeLocally marks the read side EOF (FIN received or session dead).
func (s *anyTLSStream) closeLocally() {
	s.mu.Lock()
	s.readEOF = true
	s.signalLocked()
	s.mu.Unlock()
}

func (s *anyTLSStream) closeWithError(err error) {
	s.mu.Lock()
	s.readErr = err
	s.signalLocked()
	s.mu.Unlock()
}

func (s *anyTLSStream) Read(p []byte) (int, error) {
	for {
		s.mu.Lock()
		if len(s.chunks) > 0 {
			n := copy(p, s.chunks[0][s.off:])
			s.off += n
			if s.off >= len(s.chunks[0]) {
				s.chunks = s.chunks[1:]
				s.off = 0
			}
			s.mu.Unlock()
			return n, nil
		}
		if s.readErr != nil {
			err := s.readErr
			s.mu.Unlock()
			return 0, err
		}
		if s.readEOF {
			s.mu.Unlock()
			return 0, io.EOF
		}
		ch := s.changed
		dl := s.readDL
		s.mu.Unlock()
		var timer *time.Timer
		var timeout <-chan time.Time
		if !dl.IsZero() {
			d := time.Until(dl)
			if d <= 0 {
				return 0, os.ErrDeadlineExceeded
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
			return 0, os.ErrDeadlineExceeded
		}
	}
}

func (s *anyTLSStream) Write(p []byte) (int, error) {
	total := 0
	for len(p) > 0 {
		n := len(p)
		if n > 16384 {
			n = 16384
		}
		if err := s.sess.writeDataFrame(s.id, p[:n]); err != nil {
			return total, err
		}
		total += n
		p = p[n:]
	}
	return total, nil
}

// Close sends FIN to the peer and tears the stream down locally.
func (s *anyTLSStream) Close() error {
	var err error
	s.dieOnce.Do(func() {
		s.mu.Lock()
		s.closed = true
		s.mu.Unlock()
		err = s.sess.streamClosed(s.id)
		s.closeLocally()
	})
	return err
}

func (s *anyTLSStream) LocalAddr() net.Addr  { return s.sess.conn.LocalAddr() }
func (s *anyTLSStream) RemoteAddr() net.Addr { return s.sess.conn.RemoteAddr() }

func (s *anyTLSStream) SetReadDeadline(t time.Time) error {
	s.mu.Lock()
	s.readDL = t
	s.signalLocked()
	s.mu.Unlock()
	return nil
}

func (s *anyTLSStream) SetWriteDeadline(time.Time) error { return nil }
func (s *anyTLSStream) SetDeadline(t time.Time) error    { return s.SetReadDeadline(t) }

// handshakeSuccess reports a successful upstream dial (SYNACK, v2 peers).
func (s *anyTLSStream) handshakeSuccess() {
	s.reportOnce.Do(func() {
		if s.sess.peerVersion() >= 2 {
			_ = s.sess.writeControlFrame(atCmdSYNACK, s.id, nil)
		}
	})
}

// handshakeFailure reports a failed upstream dial (SYNACK with error).
func (s *anyTLSStream) handshakeFailure(err error) {
	s.reportOnce.Do(func() {
		if s.sess.peerVersion() >= 2 {
			_ = s.sess.writeControlFrame(atCmdSYNACK, s.id, []byte(err.Error()))
		}
	})
}

// ---- session ----

type anyTLSSession struct {
	conn     net.Conn
	isClient bool

	writeMu sync.Mutex

	mu          sync.Mutex
	streams     map[uint32]*anyTLSStream
	nextID      uint32
	closed      bool
	done        chan struct{}
	peerVer     byte
	paddingFact *atPaddingFactory

	// client-side write shaping
	buffering   bool
	buffer      []byte
	sendPadding bool
	pktCounter  atomic.Uint32

	// server-side
	settingsReceived bool
	onStream         func(*anyTLSStream)
}

func newAnyTLSSession(conn net.Conn, isClient bool) *anyTLSSession {
	return &anyTLSSession{
		conn:        conn,
		isClient:    isClient,
		streams:     make(map[uint32]*anyTLSStream),
		done:        make(chan struct{}),
		paddingFact: newAtPaddingFactory([]byte(atDefaultPaddingScheme)),
		sendPadding: isClient,
	}
}

func (s *anyTLSSession) peerVersion() byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.peerVer
}

func (s *anyTLSSession) setPeerVersion(v byte) {
	s.mu.Lock()
	s.peerVer = v
	s.mu.Unlock()
}

// runClient starts the client session: queue the Settings frame and
// start receiving. Frames stay buffered until the first stream write,
// like the reference client.
func (s *anyTLSSession) runClient() {
	s.buffering = true
	settings := map[string]string{
		"v":           "2",
		"client":      "tlcore-native",
		"padding-md5": s.paddingFact.md5hex,
	}
	_ = s.writeControlFrame(atCmdSettings, 0, atStringMapBytes(settings))
	go s.recvLoop()
}

// runServer starts the server receive loop.
func (s *anyTLSSession) runServer() {
	go s.recvLoop()
}

// openStream opens a new stream (client side).
func (s *anyTLSSession) openStream() (*anyTLSStream, error) {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil, io.ErrClosedPipe
	}
	s.nextID++
	sid := s.nextID
	stream := newAnyTLSStream(sid, s)
	s.streams[sid] = stream
	s.mu.Unlock()
	if err := s.writeControlFrame(atCmdSYN, sid, nil); err != nil {
		return nil, err
	}
	// Flush point: subsequent writes carry the buffered Settings+SYN.
	s.writeMu.Lock()
	s.buffering = false
	s.writeMu.Unlock()
	return stream, nil
}

// streamClosed sends FIN and unregisters a stream.
func (s *anyTLSSession) streamClosed(sid uint32) error {
	s.mu.Lock()
	delete(s.streams, sid)
	s.mu.Unlock()
	return s.writeControlFrame(atCmdFIN, sid, nil)
}

func (s *anyTLSSession) getStream(sid uint32) *anyTLSStream {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.streams[sid]
}

// Close terminates the session and all its streams.
func (s *anyTLSSession) Close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return io.ErrClosedPipe
	}
	s.closed = true
	close(s.done)
	streams := s.streams
	s.streams = make(map[uint32]*anyTLSStream)
	s.mu.Unlock()
	for _, st := range streams {
		st.closeLocally()
	}
	return s.conn.Close()
}

func (s *anyTLSSession) writeFrameHeader(cmd byte, sid uint32, length int) []byte {
	var h [atHeaderSize]byte
	h[0] = cmd
	binary.BigEndian.PutUint32(h[1:5], sid)
	binary.BigEndian.PutUint16(h[5:7], uint16(length))
	return h[:]
}

func (s *anyTLSSession) writeControlFrame(cmd byte, sid uint32, data []byte) error {
	frame := append(s.writeFrameHeader(cmd, sid, len(data)), data...)
	_, err := s.writeConn(frame)
	return err
}

func (s *anyTLSSession) writeDataFrame(sid uint32, data []byte) error {
	frame := append(s.writeFrameHeader(atCmdPSH, sid, len(data)), data...)
	_, err := s.writeConn(frame)
	return err
}

// writeConn serializes writes; on the client it also applies the
// padding scheme's record shaping for the first packets (a faithful
// port of the reference algorithm).
func (s *anyTLSSession) writeConn(b []byte) (int, error) {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()

	if s.buffering {
		s.buffer = append(s.buffer, b...)
		return len(b), nil
	}
	if len(s.buffer) > 0 {
		b = append(s.buffer, b...)
		s.buffer = nil
	}
	if !s.sendPadding {
		_, err := s.conn.Write(b)
		return len(b), err
	}
	pkt := s.pktCounter.Add(1)
	fact := s.paddingFact
	if pkt >= fact.stop {
		s.sendPadding = false
		_, err := s.conn.Write(b)
		return len(b), err
	}
	n := 0
	for _, l := range fact.recordSizes(pkt) {
		remain := len(b)
		if l == atCheckMark {
			if remain == 0 {
				break
			}
			continue
		}
		switch {
		case remain > l:
			if _, err := s.conn.Write(b[:l]); err != nil {
				return n, err
			}
			n += l
			b = b[l:]
		case remain > 0:
			paddingLen := l - remain - atHeaderSize
			if paddingLen > 0 {
				waste := make([]byte, atHeaderSize+paddingLen)
				copy(waste, s.writeFrameHeader(atCmdWaste, 0, paddingLen))
				b = append(b, waste...)
			}
			if _, err := s.conn.Write(b); err != nil {
				return n, err
			}
			n += remain
			b = nil
		default: // remain == 0: an all-padding record
			waste := make([]byte, atHeaderSize+l)
			copy(waste, s.writeFrameHeader(atCmdWaste, 0, l))
			if _, err := s.conn.Write(waste); err != nil {
				return n, err
			}
			b = nil
		}
	}
	if len(b) > 0 {
		n2, err := s.conn.Write(b)
		return n + n2, err
	}
	return n, nil
}

// recvLoop dispatches frames until the connection fails.
func (s *anyTLSSession) recvLoop() {
	defer s.Close()
	var hdr [atHeaderSize]byte
	for {
		if _, err := io.ReadFull(s.conn, hdr[:]); err != nil {
			return
		}
		cmd := hdr[0]
		sid := binary.BigEndian.Uint32(hdr[1:5])
		length := int(binary.BigEndian.Uint16(hdr[5:7]))
		var data []byte
		if length > 0 {
			data = make([]byte, length)
			if _, err := io.ReadFull(s.conn, data); err != nil {
				return
			}
		}
		switch cmd {
		case atCmdPSH:
			if stream := s.getStream(sid); stream != nil && length > 0 {
				stream.feed(data)
			}
		case atCmdSYN:
			if s.isClient {
				continue
			}
			s.mu.Lock()
			gotSettings := s.settingsReceived
			s.mu.Unlock()
			if !gotSettings {
				_ = s.writeControlFrame(atCmdAlert, 0, []byte("client did not send its settings"))
				return
			}
			stream := newAnyTLSStream(sid, s)
			s.mu.Lock()
			if _, ok := s.streams[sid]; !ok {
				s.streams[sid] = stream
			} else {
				s.mu.Unlock()
				continue
			}
			s.mu.Unlock()
			if s.onStream != nil {
				go s.onStream(stream)
			} else {
				stream.Close()
			}
		case atCmdSYNACK:
			if stream := s.getStream(sid); stream != nil && length > 0 {
				stream.closeWithError(fmt.Errorf("remote: %s", string(data)))
			}
		case atCmdFIN:
			s.mu.Lock()
			stream := s.streams[sid]
			delete(s.streams, sid)
			s.mu.Unlock()
			if stream != nil {
				stream.closeLocally()
			}
		case atCmdWaste:
			// padding; payload already consumed above
		case atCmdSettings:
			if s.isClient {
				continue
			}
			m := atParseStringMap(data)
			s.mu.Lock()
			s.settingsReceived = true
			s.mu.Unlock()
			if m["padding-md5"] != s.paddingFact.md5hex {
				_ = s.writeControlFrame(atCmdUpdatePaddingScheme, 0, s.paddingFact.raw)
			}
			if v, err := strconv.Atoi(m["v"]); err == nil && v >= 2 {
				s.setPeerVersion(byte(v))
				_ = s.writeControlFrame(atCmdServerSettings, 0, atStringMapBytes(map[string]string{"v": "2"}))
			}
		case atCmdServerSettings:
			if s.isClient {
				m := atParseStringMap(data)
				if v, err := strconv.Atoi(m["v"]); err == nil {
					s.setPeerVersion(byte(v))
				}
			}
		case atCmdUpdatePaddingScheme:
			if s.isClient && length > 0 {
				if f := newAtPaddingFactory(data); f != nil {
					s.mu.Lock()
					s.paddingFact = f
					s.mu.Unlock()
				}
			}
		case atCmdAlert:
			return
		case atCmdHeartRequest:
			_ = s.writeControlFrame(atCmdHeartResponse, sid, nil)
		case atCmdHeartResponse:
			// keepalive checking not implemented (same as reference)
		default:
			// unknown command; its data (if any) was consumed above
		}
	}
}

// ---- server ----

// AnyTLSServer serves one AnyTLS inbound (TLS terminated by the engine).
type AnyTLSServer struct {
	Password string
}

// Handle processes one accepted (already TLS-terminated) connection.
func (s *AnyTLSServer) Handle(conn net.Conn) {
	defer conn.Close()
	br := bufio.NewReader(conn)
	hash := make([]byte, 32)
	if _, err := io.ReadFull(br, hash); err != nil {
		return
	}
	want := sha256.Sum256([]byte(s.Password))
	if !bytes.Equal(hash, want[:]) {
		return // no fallback: drop unauthenticated connections
	}
	var lb [2]byte
	if _, err := io.ReadFull(br, lb[:]); err != nil {
		return
	}
	if padLen := int(binary.BigEndian.Uint16(lb[:])); padLen > 0 {
		if _, err := io.CopyN(io.Discard, br, int64(padLen)); err != nil {
			return
		}
	}
	sess := newAnyTLSSession(newBufferedConn(conn, br), false)
	sess.onStream = func(stream *anyTLSStream) {
		target, err := ReadSOCKSAddr(stream)
		if err != nil {
			stream.Close()
			return
		}
		upstream, err := DialDirect(target)
		if err != nil {
			stream.handshakeFailure(err)
			stream.Close()
			return
		}
		stream.handshakeSuccess()
		defer upstream.Close()
		Relay(stream, upstream)
		stream.Close()
	}
	sess.runServer()
	<-sess.done // block until the session dies
}

// ---- client ----

// DialAnyTLS opens an AnyTLS stream to target through server (TLS, SNI
// sni). One session per call (no idle pooling).
func DialAnyTLS(server, password, sni string, target Addr) (net.Conn, error) {
	tconn, err := tls.Dial("tcp", server, &tls.Config{
		ServerName:         sni,
		InsecureSkipVerify: true, // panel nodes use self-signed certs
		NextProtos:         []string{"h2", "http/1.1"},
	})
	if err != nil {
		return nil, err
	}
	fail := func(err error) (net.Conn, error) {
		tconn.Close()
		return nil, err
	}
	// Authentication header: hash | padding length | zero padding.
	fact := newAtPaddingFactory([]byte(atDefaultPaddingScheme))
	padLen := 0
	if sizes := fact.recordSizes(0); len(sizes) > 0 {
		padLen = sizes[0]
	}
	sum := sha256.Sum256([]byte(password))
	var hdr bytes.Buffer
	hdr.Write(sum[:])
	var lb [2]byte
	binary.BigEndian.PutUint16(lb[:], uint16(padLen))
	hdr.Write(lb[:])
	hdr.Write(make([]byte, padLen))
	if _, err := tconn.Write(hdr.Bytes()); err != nil {
		return fail(err)
	}
	sess := newAnyTLSSession(tconn, true)
	sess.paddingFact = fact
	sess.runClient()
	stream, err := sess.openStream()
	if err != nil {
		return fail(err)
	}
	addrBytes, err := target.MarshalSOCKS()
	if err != nil {
		return fail(err)
	}
	if _, err := stream.Write(addrBytes); err != nil {
		return fail(err)
	}
	return &anyTLSClientConn{anyTLSStream: stream, sess: sess}, nil
}

// anyTLSClientConn ties the stream's lifetime to its session: closing
// the stream also closes the (single-stream) session.
type anyTLSClientConn struct {
	*anyTLSStream
	sess *anyTLSSession
}

func (c *anyTLSClientConn) Close() error {
	_ = c.anyTLSStream.Close()
	return c.sess.Close()
}
