// Package engine is TLCore-Native's original proxy core: protocol
// implementations written from their public specifications, with no
// dependency on sing-box or Xray code.
package engine

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strconv"
)

// Addr is a SOCKS-style target address (host may be a domain name).
type Addr struct {
	Host string
	Port int
	IPv4 bool // host is an IPv4 literal
	IPv6 bool // host is an IPv6 literal
}

// ParseHostPort splits "host:port" and classifies the host.
func ParseHostPort(s string) (Addr, error) {
	host, portStr, err := net.SplitHostPort(s)
	if err != nil {
		return Addr{}, err
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 {
		return Addr{}, fmt.Errorf("invalid port in %q", s)
	}
	a := Addr{Host: host, Port: port}
	if ip := net.ParseIP(host); ip != nil {
		if ip.To4() != nil {
			a.IPv4 = true
		} else {
			a.IPv6 = true
		}
	}
	return a, nil
}

// String returns host:port form.
func (a Addr) String() string {
	return net.JoinHostPort(a.Host, strconv.Itoa(a.Port))
}

// MarshalSOCKS encodes the address in SOCKS5 wire form:
// ATYP(1) + addr + port(2, big-endian). ATYP: 1=IPv4, 3=domain, 4=IPv6.
func (a Addr) MarshalSOCKS() ([]byte, error) {
	var out []byte
	switch {
	case a.IPv4:
		ip := net.ParseIP(a.Host).To4()
		out = append(out, 0x01)
		out = append(out, ip...)
	case a.IPv6:
		ip := net.ParseIP(a.Host).To16()
		out = append(out, 0x04)
		out = append(out, ip...)
	default:
		if len(a.Host) > 255 {
			return nil, fmt.Errorf("domain too long")
		}
		out = append(out, 0x03, byte(len(a.Host)))
		out = append(out, a.Host...)
	}
	var p [2]byte
	binary.BigEndian.PutUint16(p[:], uint16(a.Port))
	return append(out, p[:]...), nil
}

// ReadSOCKSAddr reads a SOCKS5 wire-form address from r.
func ReadSOCKSAddr(r io.Reader) (Addr, error) {
	var atyp [1]byte
	if _, err := io.ReadFull(r, atyp[:]); err != nil {
		return Addr{}, err
	}
	a := Addr{}
	switch atyp[0] {
	case 0x01:
		var b [4]byte
		if _, err := io.ReadFull(r, b[:]); err != nil {
			return Addr{}, err
		}
		a.Host = net.IP(b[:]).String()
		a.IPv4 = true
	case 0x03:
		var l [1]byte
		if _, err := io.ReadFull(r, l[:]); err != nil {
			return Addr{}, err
		}
		b := make([]byte, int(l[0]))
		if _, err := io.ReadFull(r, b); err != nil {
			return Addr{}, err
		}
		a.Host = string(b)
	case 0x04:
		var b [16]byte
		if _, err := io.ReadFull(r, b[:]); err != nil {
			return Addr{}, err
		}
		a.Host = net.IP(b[:]).String()
		a.IPv6 = true
	default:
		return Addr{}, fmt.Errorf("unknown address type %d", atyp[0])
	}
	var p [2]byte
	if _, err := io.ReadFull(r, p[:]); err != nil {
		return Addr{}, err
	}
	a.Port = int(binary.BigEndian.Uint16(p[:]))
	return a, nil
}

// DialDirect opens a TCP connection to the target (resolving domains).
func DialDirect(a Addr) (net.Conn, error) {
	d := net.Dialer{}
	return d.Dial("tcp", a.String())
}

// Relay copies traffic in both directions and returns when either side
// is done, closing both conns.
func Relay(a, b net.Conn) {
	done := make(chan struct{}, 2)
	go func() {
		_, _ = io.Copy(b, a)
		closeWrite(b)
		done <- struct{}{}
	}()
	go func() {
		_, _ = io.Copy(a, b)
		closeWrite(a)
		done <- struct{}{}
	}()
	<-done
	a.Close()
	b.Close()
}

func closeWrite(c net.Conn) {
	if tc, ok := c.(interface{ CloseWrite() error }); ok {
		_ = tc.CloseWrite()
	}
}
