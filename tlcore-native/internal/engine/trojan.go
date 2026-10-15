package engine

// Trojan, from the public protocol description:
//   over TLS: hex(SHA-224(password)) | CRLF | cmd(0x01) | SOCKS addr | CRLF | payload

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"sync"
)

// TrojanHash returns the wire-form password hash for Trojan.
func TrojanHash(password string) string {
	sum := sha256.Sum224([]byte(password))
	return hex.EncodeToString(sum[:])
}

// TrojanServer serves one Trojan inbound (TLS is terminated by the engine).
type TrojanServer struct {
	Password string
	// UDPSocketFn creates outbound UDP sockets for UDP sessions;
	// nil uses real UDP sockets.
	UDPSocketFn udpSocketFunc
}

func (s *TrojanServer) udpSocket() (net.PacketConn, error) {
	if s.UDPSocketFn != nil {
		return s.UDPSocketFn()
	}
	return defaultUDPSocket()
}

// Handle processes one accepted (already TLS-terminated) connection.
func (s *TrojanServer) Handle(conn net.Conn) {
	defer conn.Close()
	br := bufio.NewReader(conn)
	hash := make([]byte, 56)
	if _, err := io.ReadFull(br, hash); err != nil {
		return
	}
	if !bytes.Equal(hash, []byte(TrojanHash(s.Password))) {
		return // no fallback in v1: just drop unauthenticated connections
	}
	var crlf [2]byte
	if _, err := io.ReadFull(br, crlf[:]); err != nil || crlf != [2]byte{'\r', '\n'} {
		return
	}
	var cmd [1]byte
	if _, err := io.ReadFull(br, cmd[:]); err != nil || (cmd[0] != 0x01 && cmd[0] != 0x03) {
		return
	}
	target, err := ReadSOCKSAddr(br)
	if err != nil {
		return
	}
	if _, err := io.ReadFull(br, crlf[:]); err != nil || crlf != [2]byte{'\r', '\n'} {
		return
	}
	if cmd[0] == 0x03 {
		s.serveUDP(conn, br)
		return
	}
	upstream, err := DialDirect(target)
	if err != nil {
		return
	}
	defer upstream.Close()
	// Relay with the buffered reader so no early payload bytes are lost.
	done := make(chan struct{}, 2)
	go func() {
		_, _ = io.Copy(upstream, br)
		closeWrite(upstream)
		done <- struct{}{}
	}()
	go func() {
		_, _ = io.Copy(conn, upstream)
		done <- struct{}{}
	}()
	<-done
}

// serveUDP runs a Trojan UDP session (command 0x03): the stream carries
// framed packets [SOCKS addr | length(2) | CRLF | payload] in both
// directions; each packet names its own target.
func (s *TrojanServer) serveUDP(conn net.Conn, br *bufio.Reader) {
	out, err := s.udpSocket()
	if err != nil {
		return
	}
	defer out.Close()
	var writeMu sync.Mutex
	go udpReplyPump(out, func(src Addr, payload []byte) {
		frame, err := trojanUDPFrame(src, payload)
		if err != nil {
			return
		}
		writeMu.Lock()
		_, _ = conn.Write(frame)
		writeMu.Unlock()
	})
	for {
		dest, payload, err := readTrojanUDPFrame(br)
		if err != nil {
			return
		}
		ua, err := resolveUDPAddr(dest)
		if err != nil {
			continue
		}
		_, _ = out.WriteTo(payload, ua)
	}
}

// trojanUDPFrame builds one framed UDP packet.
func trojanUDPFrame(dest Addr, payload []byte) ([]byte, error) {
	addrBytes, err := dest.MarshalSOCKS()
	if err != nil {
		return nil, err
	}
	if len(payload) > 65535 {
		return nil, errPayloadTooLarge
	}
	var buf bytes.Buffer
	buf.Write(addrBytes)
	var lb [2]byte
	binary.BigEndian.PutUint16(lb[:], uint16(len(payload)))
	buf.Write(lb[:])
	buf.WriteString("\r\n")
	buf.Write(payload)
	return buf.Bytes(), nil
}

// readTrojanUDPFrame parses one framed UDP packet from r.
func readTrojanUDPFrame(r io.Reader) (Addr, []byte, error) {
	dest, err := ReadSOCKSAddr(r)
	if err != nil {
		return Addr{}, nil, err
	}
	var lb [2]byte
	if _, err := io.ReadFull(r, lb[:]); err != nil {
		return Addr{}, nil, err
	}
	var crlf [2]byte
	if _, err := io.ReadFull(r, crlf[:]); err != nil || crlf != [2]byte{'\r', '\n'} {
		return Addr{}, nil, errors.New("trojan udp: bad frame delimiter")
	}
	payload := make([]byte, int(binary.BigEndian.Uint16(lb[:])))
	if _, err := io.ReadFull(r, payload); err != nil {
		return Addr{}, nil, err
	}
	return dest, payload, nil
}

var errPayloadTooLarge = errors.New("udp payload exceeds 65535 bytes")

// TrojanUDPConn is the client side of a Trojan UDP session.
type TrojanUDPConn struct {
	net.Conn
	br *bufio.Reader
	mu sync.Mutex
}

// DialTrojanUDP opens a Trojan UDP session through server (TLS, SNI sni);
// firstTarget fills the request header's address field.
func DialTrojanUDP(server, password, sni string, firstTarget Addr) (*TrojanUDPConn, error) {
	tconn, err := tls.Dial("tcp", server, &tls.Config{
		ServerName:         sni,
		InsecureSkipVerify: true,
		NextProtos:         []string{"h2", "http/1.1"},
	})
	if err != nil {
		return nil, err
	}
	addrBytes, err := firstTarget.MarshalSOCKS()
	if err != nil {
		tconn.Close()
		return nil, err
	}
	var buf bytes.Buffer
	buf.WriteString(TrojanHash(password))
	buf.WriteString("\r\n")
	buf.WriteByte(0x03)
	buf.Write(addrBytes)
	buf.WriteString("\r\n")
	if _, err := tconn.Write(buf.Bytes()); err != nil {
		tconn.Close()
		return nil, err
	}
	return &TrojanUDPConn{Conn: tconn, br: bufio.NewReader(tconn)}, nil
}

// WritePacket sends one datagram to dest.
func (c *TrojanUDPConn) WritePacket(dest Addr, payload []byte) error {
	frame, err := trojanUDPFrame(dest, payload)
	if err != nil {
		return err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	_, err = c.Conn.Write(frame)
	return err
}

// ReadPacket receives the next datagram and its source address.
func (c *TrojanUDPConn) ReadPacket() (Addr, []byte, error) {
	return readTrojanUDPFrame(c.br)
}
func DialTrojan(server, password, sni string, target Addr) (net.Conn, error) {
	tconn, err := tls.Dial("tcp", server, &tls.Config{
		ServerName:         sni,
		InsecureSkipVerify: true, // panel nodes use self-signed certs
		NextProtos:         []string{"h2", "http/1.1"},
	})
	if err != nil {
		return nil, err
	}
	addrBytes, err := target.MarshalSOCKS()
	if err != nil {
		tconn.Close()
		return nil, err
	}
	var buf bytes.Buffer
	buf.WriteString(TrojanHash(password))
	buf.WriteString("\r\n")
	buf.WriteByte(0x01)
	buf.Write(addrBytes)
	buf.WriteString("\r\n")
	if _, err := tconn.Write(buf.Bytes()); err != nil {
		tconn.Close()
		return nil, err
	}
	return tconn, nil
}
