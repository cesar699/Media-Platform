package engine

// Shadowsocks 2022 UDP (SIP022 packet mode), method 2022-blake3-aes-128-gcm.
// Wire format, transcribed from the public spec and cross-checked against
// the reference implementation's packet codec:
//
//	packet = ECB-PSK(first 16 bytes) | AEAD(rest)
//	header = sessionID(8) | packetID(8)          (the ECB-encrypted block)
//	plain  = type(1) | timestamp(8) | [clientSessionID(8) in responses]
//	       | paddingLen(2) | padding | SOCKS addr | payload
//
// The AEAD key is the BLAKE3 session subkey derived from PSK || sender's
// sessionID; the AEAD nonce is header bytes [4:16]. AES-ECB here is a
// single-block cipher keyed with the PSK itself. Client packet IDs count
// from 0; servers enforce a ±30 s timestamp window and a replay window.

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

const (
	ssUDPTimestampWindow = 30 // seconds, matches the reference packet codec
	ssUDPSessionIdle     = 300 * time.Second
)

// replayWindow is a sliding bitmap over packet IDs.
type replayWindow struct {
	highest uint64
	bits    []uint64
	started bool
}

func newReplayWindow(size int) *replayWindow {
	return &replayWindow{bits: make([]uint64, (size+63)/64)}
}

// checkAndAdd reports whether id is fresh (not a replay, not too old)
// and records it when so.
func (w *replayWindow) checkAndAdd(id uint64) bool {
	size := uint64(len(w.bits) * 64)
	if !w.started {
		w.started = true
		w.highest = id
		w.bits[0] = 1 // bit for id itself (offset 0)
		return true
	}
	if id > w.highest {
		shift := id - w.highest
		if shift >= size {
			for i := range w.bits {
				w.bits[i] = 0
			}
		} else {
			// shift bitmap right by `shift` positions (toward older)
			wordShift := int(shift / 64)
			bitShift := uint(shift % 64)
			for i := len(w.bits) - 1; i >= 0; i-- {
				var v uint64
				src := i - wordShift
				if src >= 0 {
					v = w.bits[src] << bitShift
					if bitShift > 0 && src > 0 {
						v |= w.bits[src-1] >> (64 - bitShift)
					}
				}
				w.bits[i] = v
			}
		}
		w.highest = id
		w.bits[0] |= 1
		return true
	}
	offset := w.highest - id
	if offset >= size {
		return false
	}
	word := w.bits[offset/64]
	bit := uint64(1) << (offset % 64)
	if word&bit != 0 {
		return false
	}
	w.bits[offset/64] |= bit
	return true
}

// ssPacketCipher bundles the per-direction crypto of one UDP session end.
type ssPacketEnd struct {
	block cipher.Block // AES(PSK), ECB on the 16-byte header block
	aead  cipher.AEAD  // session subkey AEAD for one direction
}

// newSSPacketEnd builds the crypto for packets SENDER-side sessionID.
func newSSPacketEnd(psk []byte, sessionID uint64) (*ssPacketEnd, error) {
	block, err := aes.NewCipher(psk)
	if err != nil {
		return nil, err
	}
	var sid [8]byte
	binary.BigEndian.PutUint64(sid[:], sessionID)
	aead, err := ssAEAD(ssSessionKey(psk, sid[:]))
	if err != nil {
		return nil, err
	}
	return &ssPacketEnd{block: block, aead: aead}, nil
}

// sealPacket encrypts plain-after-header with header (16 bytes, mutated:
// returned packet has the header block ECB-encrypted in front).
func (e *ssPacketEnd) sealPacket(header [16]byte, plain []byte) []byte {
	out := make([]byte, 0, 16+len(plain)+e.aead.Overhead())
	out = append(out, header[:]...)
	out = e.aead.Seal(out, header[4:16], plain, nil)
	e.block.Encrypt(out[:16], out[:16])
	return out
}

// openPacket decrypts a full packet, returning the header and plaintext.
func (e *ssPacketEnd) openPacket(packet []byte) (sessionID, packetID uint64, plain []byte, err error) {
	if len(packet) < 16+e.aead.Overhead() {
		return 0, 0, nil, errors.New("ss udp: packet too short")
	}
	var header [16]byte
	copy(header[:], packet[:16])
	e.block.Decrypt(header[:], header[:])
	sessionID = binary.BigEndian.Uint64(header[0:8])
	packetID = binary.BigEndian.Uint64(header[8:16])
	plain, err = e.aead.Open(nil, header[4:16], packet[16:], nil)
	if err != nil {
		return 0, 0, nil, fmt.Errorf("ss udp: open: %w", err)
	}
	return sessionID, packetID, plain, nil
}

// ---- server ----

// ssUDPSession is one client session on the SS2022 UDP service.
type ssUDPSession struct {
	mu         sync.Mutex
	clientID   uint64
	serverID   uint64
	recv       *ssPacketEnd // decrypts client packets (keyed by clientID)
	send       *ssPacketEnd // encrypts server packets (keyed by serverID)
	window     *replayWindow
	out        net.PacketConn
	nextPktID  atomic.Uint64
	lastSeen   atomic.Int64
	clientAddr net.Addr
	closed     bool
}

// ServeUDP serves Shadowsocks-2022 UDP packets on pc until it errors.
// Outbound sockets come from s.UDPSocketFn (default: real UDP).
func (s *SS2022Server) ServeUDP(pc net.PacketConn) {
	newSocket := s.UDPSocketFn
	if newSocket == nil {
		newSocket = defaultUDPSocket
	}
	sessions := make(map[string]*ssUDPSession)
	var sessionsMu sync.Mutex
	done := make(chan struct{})
	defer close(done)
	// Janitor: drop idle sessions.
	go func() {
		tick := time.NewTicker(time.Minute)
		defer tick.Stop()
		for {
			select {
			case <-done:
				return
			case now := <-tick.C:
				sessionsMu.Lock()
				for key, sess := range sessions {
					if now.Sub(time.Unix(sess.lastSeen.Load(), 0)) > ssUDPSessionIdle {
						sess.mu.Lock()
						sess.closed = true
						sess.out.Close()
						sess.mu.Unlock()
						delete(sessions, key)
						s.Meter.Close(s.Tag)
					}
				}
				sessionsMu.Unlock()
			}
		}
	}()

	buf := make([]byte, 65535)
	for {
		n, clientAddr, err := pc.ReadFrom(buf)
		if err != nil {
			return
		}
		s.Meter.AddUp(s.Tag, n)
		packet := make([]byte, n)
		copy(packet, buf[:n])
		go s.handleSSUDPPacket(pc, packet, clientAddr, sessions, &sessionsMu, newSocket)
	}
}

func (s *SS2022Server) handleSSUDPPacket(pc net.PacketConn, packet []byte, clientAddr net.Addr, sessions map[string]*ssUDPSession, sessionsMu *sync.Mutex, newSocket udpSocketFunc) {
	if len(packet) < 16 {
		return
	}
	// Peek the client session ID: ECB-decrypt the header block with the PSK.
	block, err := aes.NewCipher(s.PSK)
	if err != nil {
		return
	}
	var header [16]byte
	copy(header[:], packet[:16])
	block.Decrypt(header[:], header[:])
	clientID := binary.BigEndian.Uint64(header[0:8])

	key := clientAddr.String() + "/" + fmt.Sprint(clientID)
	sessionsMu.Lock()
	sess := sessions[key]
	if sess == nil {
		recv, err := newSSPacketEnd(s.PSK, clientID)
		if err != nil {
			sessionsMu.Unlock()
			return
		}
		var serverID uint64
		var sb [8]byte
		if _, err := rand.Read(sb[:]); err != nil {
			sessionsMu.Unlock()
			return
		}
		serverID = binary.BigEndian.Uint64(sb[:])
		send, err := newSSPacketEnd(s.PSK, serverID)
		if err != nil {
			sessionsMu.Unlock()
			return
		}
		out, err := newSocket()
		if err != nil {
			sessionsMu.Unlock()
			return
		}
		sess = &ssUDPSession{
			clientID:   clientID,
			serverID:   serverID,
			recv:       recv,
			send:       send,
			window:     newReplayWindow(2048),
			out:        out,
			clientAddr: clientAddr,
		}
		sess.lastSeen.Store(time.Now().Unix())
		sessions[key] = sess
		s.Meter.Open(s.Tag)
		// Reply pump for this session.
		go func(sess *ssUDPSession) {
			udpReplyPump(sess.out, func(src Addr, payload []byte) {
				sess.mu.Lock()
				if sess.closed {
					sess.mu.Unlock()
					return
				}
				pktID := sess.nextPktID.Add(1) - 1
				var hdr [16]byte
				binary.BigEndian.PutUint64(hdr[0:8], sess.serverID)
				binary.BigEndian.PutUint64(hdr[8:16], pktID)
				var body bytes.Buffer
				body.WriteByte(0x01)
				var ts [8]byte
				binary.BigEndian.PutUint64(ts[:], uint64(time.Now().Unix()))
				body.Write(ts[:])
				var cid [8]byte
				binary.BigEndian.PutUint64(cid[:], sess.clientID)
				body.Write(cid[:])
				body.Write([]byte{0, 0}) // padding length
				addrBytes, err := src.MarshalSOCKS()
				if err != nil {
					sess.mu.Unlock()
					return
				}
				body.Write(addrBytes)
				body.Write(payload)
				out := sess.send.sealPacket(hdr, body.Bytes())
				sess.mu.Unlock()
				if _, err := pc.WriteTo(out, sess.clientAddr); err == nil {
					s.Meter.AddDown(s.Tag, len(out))
				}
			})
		}(sess)
	}
	sessionsMu.Unlock()

	sess.mu.Lock()
	if sess.closed {
		sess.mu.Unlock()
		return
	}
	_, packetID, plain, err := sess.recv.openPacket(packet)
	if err != nil {
		sess.mu.Unlock()
		return
	}
	if !sess.window.checkAndAdd(packetID) {
		sess.mu.Unlock()
		return
	}
	sess.lastSeen.Store(time.Now().Unix())
	out := sess.out
	sess.mu.Unlock()

	// Parse: type(1) | timestamp(8) | paddingLen(2) | padding | addr | payload.
	if len(plain) < 11 || plain[0] != 0x00 {
		return
	}
	ts := int64(binary.BigEndian.Uint64(plain[1:9]))
	if delta := time.Now().Unix() - ts; delta > ssUDPTimestampWindow || delta < -ssUDPTimestampWindow {
		return
	}
	padLen := int(binary.BigEndian.Uint16(plain[9:11]))
	rest := plain[11:]
	if padLen > len(rest) {
		return
	}
	rest = rest[padLen:]
	br := bytes.NewReader(rest)
	target, err := ReadSOCKSAddr(br)
	if err != nil {
		return
	}
	payload := make([]byte, br.Len())
	_, _ = br.Read(payload)
	ua, err := resolveUDPAddr(target)
	if err != nil {
		return
	}
	_, _ = out.WriteTo(payload, ua)
}

// ---- client ----

// SS2022UDPClient sends and receives 2022 packet-mode datagrams to one
// server. Used by tests and the local gateway; panel inbounds only serve.
type SS2022UDPClient struct {
	pc         net.PacketConn
	serverAddr net.Addr
	psk        []byte
	clientID   uint64
	send       *ssPacketEnd
	mu         sync.Mutex
	nextPktID  atomic.Uint64
	serverID   uint64
	recv       *ssPacketEnd
	window     *replayWindow
	seenServer bool
}

// NewSS2022UDPClient creates a client over pc (a real UDP socket when
// nil) talking to server ("host:port").
func NewSS2022UDPClient(server string, psk []byte, pc net.PacketConn) (*SS2022UDPClient, error) {
	if pc == nil {
		var err error
		pc, err = defaultUDPSocket()
		if err != nil {
			return nil, err
		}
	}
	ua, err := net.ResolveUDPAddr("udp", server)
	if err != nil {
		return nil, err
	}
	var idb [8]byte
	if _, err := rand.Read(idb[:]); err != nil {
		return nil, err
	}
	clientID := binary.BigEndian.Uint64(idb[:])
	send, err := newSSPacketEnd(psk, clientID)
	if err != nil {
		return nil, err
	}
	return &SS2022UDPClient{
		pc: pc, serverAddr: ua, psk: psk, clientID: clientID,
		send: send, window: newReplayWindow(2048),
	}, nil
}

// WritePacket sends one datagram to dest through the server.
func (c *SS2022UDPClient) WritePacket(dest Addr, payload []byte) error {
	padLen := 0
	// The reference client pads DNS-sized packets (anti-fingerprinting).
	if dest.Port == 53 && len(payload) < 900 {
		var rb [1]byte
		_, _ = rand.Read(rb[:])
		padLen = 1 + int(rb[0])%(900-len(payload))
	}
	var hdr [16]byte
	binary.BigEndian.PutUint64(hdr[0:8], c.clientID)
	binary.BigEndian.PutUint64(hdr[8:16], c.nextPktID.Add(1)-1)
	var body bytes.Buffer
	body.WriteByte(0x00)
	var ts [8]byte
	binary.BigEndian.PutUint64(ts[:], uint64(time.Now().Unix()))
	body.Write(ts[:])
	var pl [2]byte
	binary.BigEndian.PutUint16(pl[:], uint16(padLen))
	body.Write(pl[:])
	padding := make([]byte, padLen)
	_, _ = rand.Read(padding)
	body.Write(padding)
	addrBytes, err := dest.MarshalSOCKS()
	if err != nil {
		return err
	}
	body.Write(addrBytes)
	body.Write(payload)
	_, err = c.pc.WriteTo(c.send.sealPacket(hdr, body.Bytes()), c.serverAddr)
	return err
}

// ReadPacket receives the next datagram, returning its source address.
func (c *SS2022UDPClient) ReadPacket() (Addr, []byte, error) {
	buf := make([]byte, 65535)
	for {
		n, _, err := c.pc.ReadFrom(buf)
		if err != nil {
			return Addr{}, nil, err
		}
		src, payload, ok := c.openServerPacket(buf[:n])
		if ok {
			return src, payload, nil
		}
	}
}

func (c *SS2022UDPClient) openServerPacket(packet []byte) (Addr, []byte, bool) {
	if len(packet) < 16 {
		return Addr{}, nil, false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	// The receive end is keyed by the server's session ID, learned from
	// the first packet's ECB-decrypted header.
	if !c.seenServer {
		block, err := aes.NewCipher(c.psk)
		if err != nil {
			return Addr{}, nil, false
		}
		var header [16]byte
		copy(header[:], packet[:16])
		block.Decrypt(header[:], header[:])
		serverID := binary.BigEndian.Uint64(header[0:8])
		recv, err := newSSPacketEnd(c.psk, serverID)
		if err != nil {
			return Addr{}, nil, false
		}
		c.serverID, c.recv, c.seenServer = serverID, recv, true
	}
	sessID, packetID, plain, err := c.recv.openPacket(packet)
	if err != nil || sessID != c.serverID {
		return Addr{}, nil, false
	}
	if !c.window.checkAndAdd(packetID) {
		return Addr{}, nil, false
	}
	// type(1)=1 | ts(8) | clientID(8) | padLen(2) | padding | addr | payload
	if len(plain) < 19 || plain[0] != 0x01 {
		return Addr{}, nil, false
	}
	ts := int64(binary.BigEndian.Uint64(plain[1:9]))
	if delta := time.Now().Unix() - ts; delta > ssUDPTimestampWindow || delta < -ssUDPTimestampWindow {
		return Addr{}, nil, false
	}
	if binary.BigEndian.Uint64(plain[9:17]) != c.clientID {
		return Addr{}, nil, false
	}
	padLen := int(binary.BigEndian.Uint16(plain[17:19]))
	rest := plain[19:]
	if padLen > len(rest) {
		return Addr{}, nil, false
	}
	rest = rest[padLen:]
	br := bytes.NewReader(rest)
	src, err := ReadSOCKSAddr(br)
	if err != nil {
		return Addr{}, nil, false
	}
	payload := make([]byte, br.Len())
	_, _ = br.Read(payload)
	return src, payload, true
}

// Close closes the underlying socket.
func (c *SS2022UDPClient) Close() error { return c.pc.Close() }
