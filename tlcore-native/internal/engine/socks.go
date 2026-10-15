package engine

// Mixed inbound: SOCKS5 (CONNECT, no auth) and HTTP proxy (CONNECT and
// absolute-form requests) on one port, dialing out through a DialFunc.
// Used by the probe tool and available as a local gateway inbound.

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
)

// DialFunc opens a stream to target, possibly through a proxy protocol.
type DialFunc func(target Addr) (net.Conn, error)

// DirectDial is the DialFunc that connects directly.
func DirectDial(target Addr) (net.Conn, error) { return DialDirect(target) }

// ServeMixed accepts SOCKS5 or HTTP proxy connections on ln.
func ServeMixed(ln net.Listener, dial DialFunc) {
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		go handleMixed(c, dial)
	}
}

func handleMixed(conn net.Conn, dial DialFunc) {
	defer conn.Close()
	br := bufio.NewReader(conn)
	first, err := br.Peek(1)
	if err != nil {
		return
	}
	if first[0] == 0x05 {
		handleSOCKS5(conn, br, dial)
	} else {
		handleHTTPProxy(conn, br, dial)
	}
}

func handleSOCKS5(conn net.Conn, br *bufio.Reader, dial DialFunc) {
	head := make([]byte, 2)
	if _, err := io.ReadFull(br, head); err != nil || head[0] != 0x05 {
		return
	}
	methods := make([]byte, int(head[1]))
	if _, err := io.ReadFull(br, methods); err != nil {
		return
	}
	if _, err := conn.Write([]byte{0x05, 0x00}); err != nil { // no auth
		return
	}
	req := make([]byte, 3)
	if _, err := io.ReadFull(br, req); err != nil || req[0] != 0x05 {
		return
	}
	if req[1] != 0x01 { // CONNECT only
		_, _ = conn.Write([]byte{0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	target, err := ReadSOCKSAddr(br)
	if err != nil {
		return
	}
	upstream, err := dial(target)
	if err != nil {
		_, _ = conn.Write([]byte{0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	defer upstream.Close()
	if _, err := conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}); err != nil {
		return
	}
	Relay(newBufferedConn(conn, br), upstream)
}

func handleHTTPProxy(conn net.Conn, br *bufio.Reader, dial DialFunc) {
	for {
		line, err := readLine(br)
		if err != nil {
			return
		}
		parts := strings.SplitN(line, " ", 3)
		if len(parts) < 3 {
			return
		}
		method, targetStr := parts[0], parts[1]
		// Drain headers, remember Host for non-CONNECT.
		host := ""
		for {
			h, err := readLine(br)
			if err != nil {
				return
			}
			if h == "" {
				break
			}
			if strings.HasPrefix(strings.ToLower(h), "host:") {
				host = strings.TrimSpace(h[5:])
			}
		}
		if method == "CONNECT" {
			target, err := ParseHostPort(targetStr)
			if err != nil {
				return
			}
			upstream, err := dial(target)
			if err != nil {
				_, _ = conn.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
				return
			}
			defer upstream.Close()
			if _, err := conn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")); err != nil {
				return
			}
			Relay(newBufferedConn(conn, br), upstream)
			return
		}
		// Absolute-form request: strip scheme, forward origin-form.
		rest := targetStr
		if i := strings.Index(rest, "://"); i >= 0 {
			rest = rest[i+3:]
		}
		hostPort := rest
		path := "/"
		if i := strings.Index(rest, "/"); i >= 0 {
			hostPort, path = rest[:i], rest[i:]
		}
		if !strings.Contains(hostPort, ":") {
			hostPort += ":80"
		}
		target, err := ParseHostPort(hostPort)
		if err != nil {
			return
		}
		upstream, err := dial(target)
		if err != nil {
			_, _ = conn.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
			return
		}
		defer upstream.Close()
		reqLine := fmt.Sprintf("%s %s %s\r\n", method, path, parts[2])
		if host != "" {
			reqLine += "Host: " + host + "\r\n"
		}
		reqLine += "Connection: close\r\n\r\n"
		if _, err := upstream.Write([]byte(reqLine)); err != nil {
			return
		}
		_, _ = io.Copy(conn, upstream)
		return
	}
}

func readLine(br *bufio.Reader) (string, error) {
	line, err := br.ReadString('\n')
	if err != nil {
		return "", err
	}
	return strings.TrimRight(line, "\r\n"), nil
}

type bufferedConn struct {
	net.Conn
	r *bufio.Reader
}

func newBufferedConn(c net.Conn, r *bufio.Reader) net.Conn {
	return &bufferedConn{Conn: c, r: r}
}

func (c *bufferedConn) Read(p []byte) (int, error) { return c.r.Read(p) }

var errNoUDP = errors.New("udp not supported in mixed inbound")
