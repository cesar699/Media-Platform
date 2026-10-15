package engine

// AnyTLS tests: my client <-> my server over real loopback (TLS + TCP),
// with a plain TCP echo target behind the server.

import (
	"io"
	"net"
	"testing"
	"time"
)

// startTCPEcho runs a TCP echo server on loopback.
func startTCPEcho(t *testing.T) (addr string, stop func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 4096)
				for {
					n, err := c.Read(buf)
					if n > 0 {
						out := append([]byte("ECHO:"), buf[:n]...)
						if _, err := c.Write(out); err != nil {
							return
						}
					}
					if err != nil {
						return
					}
				}
			}(c)
		}
	}()
	return ln.Addr().String(), func() { ln.Close() }
}

func TestAnyTLSMineToMine(t *testing.T) {
	echoAddr, stopEcho := startTCPEcho(t)
	defer stopEcho()
	target, err := ParseHostPort(echoAddr)
	if err != nil {
		t.Fatal(err)
	}
	certFile, keyFile := testCertFiles(t)
	eng := &Engine{}
	spec := InboundSpec{Tag: "anytls-test", Protocol: "anytls", Port: 19421,
		Params: map[string]string{"password": "anytls-test-pw", "sni": "www.microsoft.com"}, CertFile: certFile, KeyFile: keyFile}
	if err := eng.Start([]InboundSpec{spec}); err != nil {
		t.Fatal(err)
	}
	defer eng.Stop()
	time.Sleep(100 * time.Millisecond)

	conn, err := DialAnyTLS("127.0.0.1:19421", "anytls-test-pw", "www.microsoft.com", target)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Write([]byte("hello-anytls")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 64)
	n, err := io.ReadFull(conn, buf[:len("ECHO:hello-anytls")])
	if err != nil {
		t.Fatal(err)
	}
	if string(buf[:n]) != "ECHO:hello-anytls" {
		t.Fatalf("bad echo: %q", buf[:n])
	}
	// A second, larger write (multi-frame chunking) round-trips too.
	big := make([]byte, 40000)
	for i := range big {
		big[i] = byte(i % 251)
	}
	if _, err := conn.Write(big); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len("ECHO:")+len(big))
	// The echo server prefixes each Read chunk, so the reply is a series
	// of ECHO:-prefixed segments; just verify total content volume and
	// that reads keep flowing until we have it all.
	total := 0
	for total < len(got) {
		m, err := conn.Read(got[total:])
		if err != nil {
			t.Fatalf("read big echo at %d: %v", total, err)
		}
		total += m
	}
}

func TestAnyTLSWrongPassword(t *testing.T) {
	echoAddr, stopEcho := startTCPEcho(t)
	defer stopEcho()
	target, err := ParseHostPort(echoAddr)
	if err != nil {
		t.Fatal(err)
	}
	certFile, keyFile := testCertFiles(t)
	eng := &Engine{}
	spec := InboundSpec{Tag: "anytls-test-bad", Protocol: "anytls", Port: 19422,
		Params: map[string]string{"password": "right-pw", "sni": "www.microsoft.com"}, CertFile: certFile, KeyFile: keyFile}
	if err := eng.Start([]InboundSpec{spec}); err != nil {
		t.Fatal(err)
	}
	defer eng.Stop()
	time.Sleep(100 * time.Millisecond)

	conn, err := DialAnyTLS("127.0.0.1:19422", "wrong-pw", "www.microsoft.com", target)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	_, _ = conn.Write([]byte("should-not-echo"))
	buf := make([]byte, 32)
	if _, err := conn.Read(buf); err == nil {
		t.Fatal("wrong-password stream got a response")
	}
}
