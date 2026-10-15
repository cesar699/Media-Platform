package engine

// VLESS, from the public protocol description:
//   request:  version(0x00) | UUID(16) | addons len(1)+addons | cmd(0x01=TCP)
//             | port(2, BE) | addr type(1=IPv4, 2=domain, 3=IPv6) | addr | payload
//   response: version(0x00) | addons len(1)+addons | payload

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strings"
)

// ParseUUID converts the textual UUID form to 16 bytes.
func ParseUUID(s string) ([16]byte, error) {
	var out [16]byte
	h := strings.ReplaceAll(s, "-", "")
	if len(h) != 32 {
		return out, fmt.Errorf("invalid uuid %q", s)
	}
	for i := 0; i < 16; i++ {
		var v int
		_, err := fmt.Sscanf(h[i*2:i*2+2], "%02x", &v)
		if err != nil {
			return out, fmt.Errorf("invalid uuid %q", s)
		}
		out[i] = byte(v)
	}
	return out, nil
}

// VLESSServer serves one VLESS inbound (plain TCP, or TLS terminated by the engine).
type VLESSServer struct {
	UUID string
	// UDPSocketFn creates outbound UDP sockets for UDP sessions;
	// nil uses real UDP sockets.
	UDPSocketFn udpSocketFunc
}

func (s *VLESSServer) udpSocket() (net.PacketConn, error) {
	if s.UDPSocketFn != nil {
		return s.UDPSocketFn()
	}
	return defaultUDPSocket()
}

// Handle processes one accepted connection.
func (s *VLESSServer) Handle(conn net.Conn) {
	defer conn.Close()
	want, err := ParseUUID(s.UUID)
	if err != nil {
		return
	}
	br := bufio.NewReader(conn)
	head := make([]byte, 18)
	if _, err := io.ReadFull(br, head); err != nil {
		return
	}
	if head[0] != 0x00 {
		return
	}
	if !bytes.Equal(head[1:17], want[:]) {
		return
	}
	addonLen := int(head[17])
	if addonLen > 0 {
		if _, err := io.CopyN(io.Discard, br, int64(addonLen)); err != nil {
			return
		}
	}
	var cmd [1]byte
	if _, err := io.ReadFull(br, cmd[:]); err != nil || (cmd[0] != 0x01 && cmd[0] != 0x02) {
		return
	}
	target, err := readVLESSAddr(br)
	if err != nil {
		return
	}
	if cmd[0] == 0x02 {
		s.serveUDP(conn, br, target)
		return
	}
	upstream, err := DialDirect(target)
	if err != nil {
		return
	}
	defer upstream.Close()
	if _, err := conn.Write([]byte{0x00, 0x00}); err != nil {
		return
	}
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

// readVLESSAddr reads port-first VLESS address form.
func readVLESSAddr(br io.Reader) (Addr, error) {
	var pb [2]byte
	if _, err := io.ReadFull(br, pb[:]); err != nil {
		return Addr{}, err
	}
	port := int(binary.BigEndian.Uint16(pb[:]))
	var at [1]byte
	if _, err := io.ReadFull(br, at[:]); err != nil {
		return Addr{}, err
	}
	a := Addr{Port: port}
	switch at[0] {
	case 0x01:
		var b [4]byte
		if _, err := io.ReadFull(br, b[:]); err != nil {
			return Addr{}, err
		}
		a.Host = net.IP(b[:]).String()
		a.IPv4 = true
	case 0x02:
		var l [1]byte
		if _, err := io.ReadFull(br, l[:]); err != nil {
			return Addr{}, err
		}
		b := make([]byte, int(l[0]))
		if _, err := io.ReadFull(br, b); err != nil {
			return Addr{}, err
		}
		a.Host = string(b)
	case 0x03:
		var b [16]byte
		if _, err := io.ReadFull(br, b[:]); err != nil {
			return Addr{}, err
		}
		a.Host = net.IP(b[:]).String()
		a.IPv6 = true
	default:
		return Addr{}, fmt.Errorf("vless: unknown address type %d", at[0])
	}
	return a, nil
}

// serveUDP runs a VLESS UDP session (command 0x02): the target is fixed
// by the request header; the stream carries [length(2) | payload]
// packets in both directions after the 2-byte response header.
func (s *VLESSServer) serveUDP(conn net.Conn, br *bufio.Reader, target Addr) {
	ua, err := resolveUDPAddr(target)
	if err != nil {
		return
	}
	out, err := s.udpSocket()
	if err != nil {
		return
	}
	defer out.Close()
	if _, err := conn.Write([]byte{0x00, 0x00}); err != nil {
		return
	}
	go udpReplyPump(out, func(src Addr, payload []byte) {
		var lb [2]byte
		binary.BigEndian.PutUint16(lb[:], uint16(len(payload)))
		frame := append(lb[:], payload...)
		_, _ = conn.Write(frame)
	})
	for {
		var lb [2]byte
		if _, err := io.ReadFull(br, lb[:]); err != nil {
			return
		}
		payload := make([]byte, int(binary.BigEndian.Uint16(lb[:])))
		if _, err := io.ReadFull(br, payload); err != nil {
			return
		}
		_, _ = out.WriteTo(payload, ua)
	}
}

// VLESSUDPConn is the client side of a VLESS UDP session (fixed target).
type VLESSUDPConn struct {
	net.Conn
	br     *bufio.Reader
	header bool
}

// DialVLESSUDP opens a VLESS UDP session to target through server.
func DialVLESSUDP(server, uuid string, target Addr) (*VLESSUDPConn, error) {
	raw, err := net.Dial("tcp", server)
	if err != nil {
		return nil, err
	}
	id, err := ParseUUID(uuid)
	if err != nil {
		raw.Close()
		return nil, err
	}
	addrBytes, err := marshalVLESSAddr(target)
	if err != nil {
		raw.Close()
		return nil, err
	}
	var buf bytes.Buffer
	buf.WriteByte(0x00)
	buf.Write(id[:])
	buf.WriteByte(0x00) // no addons
	buf.WriteByte(0x02) // UDP
	buf.Write(addrBytes)
	if _, err := raw.Write(buf.Bytes()); err != nil {
		raw.Close()
		return nil, err
	}
	return &VLESSUDPConn{Conn: raw, br: bufio.NewReader(raw)}, nil
}

// WritePacket sends one datagram to the session target.
func (c *VLESSUDPConn) WritePacket(payload []byte) error {
	if len(payload) > 65535 {
		return errPayloadTooLarge
	}
	var lb [2]byte
	binary.BigEndian.PutUint16(lb[:], uint16(len(payload)))
	frame := append(lb[:], payload...)
	_, err := c.Conn.Write(frame)
	return err
}

// ReadPacket receives the next datagram from the session target.
func (c *VLESSUDPConn) ReadPacket() ([]byte, error) {
	if !c.header {
		var h [2]byte
		if _, err := io.ReadFull(c.br, h[:]); err != nil {
			return nil, err
		}
		if h[0] != 0x00 {
			return nil, fmt.Errorf("vless: bad response version %d", h[0])
		}
		if h[1] > 0 {
			if _, err := io.CopyN(io.Discard, c.br, int64(h[1])); err != nil {
				return nil, err
			}
		}
		c.header = true
	}
	var lb [2]byte
	if _, err := io.ReadFull(c.br, lb[:]); err != nil {
		return nil, err
	}
	payload := make([]byte, int(binary.BigEndian.Uint16(lb[:])))
	if _, err := io.ReadFull(c.br, payload); err != nil {
		return nil, err
	}
	return payload, nil
}

func marshalVLESSAddr(a Addr) ([]byte, error) {
	var buf bytes.Buffer
	var pb [2]byte
	binary.BigEndian.PutUint16(pb[:], uint16(a.Port))
	buf.Write(pb[:])
	switch {
	case a.IPv4:
		buf.WriteByte(0x01)
		buf.Write(net.ParseIP(a.Host).To4())
	case a.IPv6:
		buf.WriteByte(0x03)
		buf.Write(net.ParseIP(a.Host).To16())
	default:
		if len(a.Host) > 255 {
			return nil, fmt.Errorf("domain too long")
		}
		buf.WriteByte(0x02)
		buf.WriteByte(byte(len(a.Host)))
		buf.WriteString(a.Host)
	}
	return buf.Bytes(), nil
}

// DialVLESS opens a VLESS tunnel (plain TCP) to target. It returns a conn
// whose first reads transparently consume the 2-byte response header.
func DialVLESS(server, uuid string, target Addr) (net.Conn, error) {
	raw, err := net.Dial("tcp", server)
	if err != nil {
		return nil, err
	}
	id, err := ParseUUID(uuid)
	if err != nil {
		raw.Close()
		return nil, err
	}
	addrBytes, err := marshalVLESSAddr(target)
	if err != nil {
		raw.Close()
		return nil, err
	}
	var buf bytes.Buffer
	buf.WriteByte(0x00)
	buf.Write(id[:])
	buf.WriteByte(0x00) // no addons
	buf.WriteByte(0x01) // TCP
	buf.Write(addrBytes)
	if _, err := raw.Write(buf.Bytes()); err != nil {
		raw.Close()
		return nil, err
	}
	return &vlessClientConn{Conn: raw, br: bufio.NewReader(raw)}, nil
}

type vlessClientConn struct {
	net.Conn
	br     *bufio.Reader
	header bool
}

func (c *vlessClientConn) Read(p []byte) (int, error) {
	if !c.header {
		var h [2]byte
		if _, err := io.ReadFull(c.br, h[:]); err != nil {
			return 0, err
		}
		if h[0] != 0x00 {
			return 0, fmt.Errorf("vless: bad response version %d", h[0])
		}
		if h[1] > 0 { // skip addons
			if _, err := io.CopyN(io.Discard, c.br, int64(h[1])); err != nil {
				return 0, err
			}
		}
		c.header = true
	}
	return c.br.Read(p)
}
