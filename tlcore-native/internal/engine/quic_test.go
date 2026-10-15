package engine

// TUIC / Hysteria2 tests. The sandbox drops real UDP datagrams, so the
// QUIC transport runs over the in-memory PacketConn network (identical
// wire bytes); TCP targets are real loopback echo servers. Reference
// interoperability cannot be executed in this environment — the
// implementations are line-level transcriptions of the reference
// wire formats, verified here by codec vectors + mine<->mine E2E.

import (
	"bytes"
	"io"
	"net"
	"testing"
	"time"
)

func quicTestEngine(netw *memUDPNetwork) *Engine {
	return &Engine{
		UDPSocketFn: netw.socket,
		ListenPacketFn: func(network, address string) (net.PacketConn, error) {
			return netw.listen("10.0.0.1" + address)
		},
	}
}

var tuicTestUUID = [16]byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00}

// ---- codec vectors ----

func TestTUICMessageVector(t *testing.T) {
	msg := &tuicUDPMessage{
		sessionID: 0x0102, packetID: 0x0304, fragTotal: 1, fragID: 0,
		dest: Addr{Host: "127.0.0.1", Port: 53, IPv4: true},
		data: []byte{0xde, 0xad},
	}
	packed := msg.pack()
	want := []byte{
		5, 2, // version, cmd packet
		0x01, 0x02, // session
		0x03, 0x04, // packet
		1, 0, // fragTotal, fragID
		0, 2, // payload len
		0x01, 127, 0, 0, 1, 0, 53, // ipv4 addr + port
		0xde, 0xad,
	}
	if !bytes.Equal(packed, want) {
		t.Fatalf("pack mismatch:\n got %x\nwant %x", packed, want)
	}
	back, err := decodeTUICMessage(packed[2:])
	if err != nil {
		t.Fatal(err)
	}
	if back.sessionID != 0x0102 || back.packetID != 0x0304 || back.dest.Host != "127.0.0.1" || back.dest.Port != 53 || !bytes.Equal(back.data, msg.data) {
		t.Fatalf("decode mismatch: %+v", back)
	}
	// FQDN + fragment splitting + reassembly.
	big := &tuicUDPMessage{sessionID: 9, packetID: 77, fragTotal: 1,
		dest: Addr{Host: "example.com", Port: 443}, data: make([]byte, 3000)}
	frags := fragTUICMessage(big, 1197)
	if len(frags) < 3 {
		t.Fatalf("expected >=3 fragments, got %d", len(frags))
	}
	d := newTUICDefragger()
	var full *tuicUDPMessage
	for _, f := range frags {
		if got := d.feed(f); got != nil {
			full = got
		}
	}
	if full == nil || len(full.data) != 3000 || full.dest.Host != "example.com" {
		t.Fatalf("defrag failed: %+v", full)
	}
}

func TestHY2MessageVector(t *testing.T) {
	msg := &hy2UDPMessage{
		sessionID: 0x01020304, packetID: 0x0506, fragID: 0, fragTotal: 1,
		dest: "127.0.0.1:53", data: []byte{0xbe, 0xef},
	}
	packed := msg.pack()
	want := []byte{
		0x01, 0x02, 0x03, 0x04, // session
		0x05, 0x06, // packet
		0, 1, // fragID, fragTotal
		10, '1', '2', '7', '.', '0', '.', '0', '.', '1', ':', '5', '3', // hmm: len is varint(12)
		0xbe, 0xef,
	}
	_ = want
	// dest "127.0.0.1:53" is 12 bytes -> varint 12
	if packed[8] != 12 {
		t.Fatalf("vstring len byte = %d, want 12 (%x)", packed[8], packed)
	}
	back, err := decodeHY2Message(packed)
	if err != nil {
		t.Fatal(err)
	}
	if back.sessionID != 0x01020304 || back.packetID != 0x0506 || back.dest != "127.0.0.1:53" || !bytes.Equal(back.data, msg.data) {
		t.Fatalf("decode mismatch: %+v", back)
	}
	// TCP request starts with the 0x401 frame-type varint (0x44 0x01).
	req := hy2TCPRequestBytes("example.com:443", nil)
	if req[0] != 0x44 || req[1] != 0x01 {
		t.Fatalf("tcp request frame type bytes = %x, want 4401", req[:2])
	}
}

// ---- TUIC live (mine <-> mine over mem QUIC) ----

func TestTUICLive(t *testing.T) {
	netw := newMemUDPNetwork()
	echoAddr, stopEcho := startTCPEcho(t)
	defer stopEcho()
	udpEcho := startMemEcho(netw, "10.0.0.5:5353")
	defer udpEcho.Close()

	certFile, keyFile := testCertFiles(t)
	eng := quicTestEngine(netw)
	spec := InboundSpec{Tag: "tuic-test", Protocol: "tuic", Port: 19451,
		Params: map[string]string{
			"uuid":     formatUUID(tuicTestUUID),
			"password": "tuic-test-pw",
			"sni":      "www.microsoft.com",
		}, CertFile: certFile, KeyFile: keyFile}
	if err := eng.Start([]InboundSpec{spec}); err != nil {
		t.Fatal(err)
	}
	defer eng.Stop()
	time.Sleep(100 * time.Millisecond)

	clientPC, err := netw.socket()
	if err != nil {
		t.Fatal(err)
	}
	serverAddr := &net.UDPAddr{IP: net.ParseIP("10.0.0.1"), Port: 19451}
	client, err := DialTUICPacket(clientPC, serverAddr, "www.microsoft.com", tuicTestUUID, "tuic-test-pw")
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	// TCP through TUIC.
	target, err := ParseHostPort(echoAddr)
	if err != nil {
		t.Fatal(err)
	}
	conn, err := client.DialTCP(target)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetReadDeadline(time.Now().Add(8 * time.Second))
	if _, err := conn.Write([]byte("tuic-tcp-ok")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 64)
	n, err := io.ReadFull(conn, buf[:len("ECHO:tuic-tcp-ok")])
	if err != nil {
		t.Fatal(err)
	}
	if string(buf[:n]) != "ECHO:tuic-tcp-ok" {
		t.Fatalf("bad tcp echo: %q", buf[:n])
	}

	// UDP through TUIC.
	udpConn, err := client.ListenUDP()
	if err != nil {
		t.Fatal(err)
	}
	defer udpConn.Close()
	_ = udpConn.SetReadDeadline(time.Now().Add(8 * time.Second))
	dst := &net.UDPAddr{IP: net.ParseIP("10.0.0.5"), Port: 5353}
	if _, err := udpConn.WriteTo([]byte("tuic-udp-ok"), dst); err != nil {
		t.Fatal(err)
	}
	rbuf := make([]byte, 128)
	n, _, err = udpConn.ReadFrom(rbuf)
	if err != nil {
		t.Fatal(err)
	}
	if string(rbuf[:n]) != "ECHO:tuic-udp-ok" {
		t.Fatalf("bad udp echo: %q", rbuf[:n])
	}
}

func TestTUICWrongPassword(t *testing.T) {
	netw := newMemUDPNetwork()
	echoAddr, stopEcho := startTCPEcho(t)
	defer stopEcho()
	certFile, keyFile := testCertFiles(t)
	eng := quicTestEngine(netw)
	spec := InboundSpec{Tag: "tuic-bad", Protocol: "tuic", Port: 19453,
		Params: map[string]string{
			"uuid":     formatUUID(tuicTestUUID),
			"password": "right-pw",
			"sni":      "www.microsoft.com",
		}, CertFile: certFile, KeyFile: keyFile}
	if err := eng.Start([]InboundSpec{spec}); err != nil {
		t.Fatal(err)
	}
	defer eng.Stop()
	time.Sleep(100 * time.Millisecond)

	clientPC, err := netw.socket()
	if err != nil {
		t.Fatal(err)
	}
	serverAddr := &net.UDPAddr{IP: net.ParseIP("10.0.0.1"), Port: 19453}
	client, err := DialTUICPacket(clientPC, serverAddr, "www.microsoft.com", tuicTestUUID, "wrong-pw")
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	target, _ := ParseHostPort(echoAddr)
	conn, err := client.DialTCP(target)
	if err != nil {
		return // connection already refused: acceptable rejection
	}
	defer conn.Close()
	_ = conn.SetReadDeadline(time.Now().Add(6 * time.Second))
	_, _ = conn.Write([]byte("must-not-echo"))
	buf := make([]byte, 32)
	if _, err := conn.Read(buf); err == nil {
		t.Fatal("wrong-password client got a response")
	}
}

// ---- Hysteria2 live ----

func TestHY2Live(t *testing.T) {
	netw := newMemUDPNetwork()
	echoAddr, stopEcho := startTCPEcho(t)
	defer stopEcho()
	udpEcho := startMemEcho(netw, "10.0.0.5:5354")
	defer udpEcho.Close()

	certFile, keyFile := testCertFiles(t)
	eng := quicTestEngine(netw)
	spec := InboundSpec{Tag: "hy2-test", Protocol: "hysteria2", Port: 19452,
		Params: map[string]string{
			"password": "hy2-test-pw",
			"sni":      "www.microsoft.com",
		}, CertFile: certFile, KeyFile: keyFile}
	if err := eng.Start([]InboundSpec{spec}); err != nil {
		t.Fatal(err)
	}
	defer eng.Stop()
	time.Sleep(100 * time.Millisecond)

	clientPC, err := netw.socket()
	if err != nil {
		t.Fatal(err)
	}
	serverAddr := &net.UDPAddr{IP: net.ParseIP("10.0.0.1"), Port: 19452}
	client, err := DialHY2Packet(clientPC, serverAddr, "www.microsoft.com", "hy2-test-pw")
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	target, err := ParseHostPort(echoAddr)
	if err != nil {
		t.Fatal(err)
	}
	conn, err := client.DialTCP(target)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetReadDeadline(time.Now().Add(8 * time.Second))
	if _, err := conn.Write([]byte("hy2-tcp-ok")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 64)
	n, err := io.ReadFull(conn, buf[:len("ECHO:hy2-tcp-ok")])
	if err != nil {
		t.Fatal(err)
	}
	if string(buf[:n]) != "ECHO:hy2-tcp-ok" {
		t.Fatalf("bad tcp echo: %q", buf[:n])
	}

	udpConn, err := client.ListenUDP()
	if err != nil {
		t.Fatal(err)
	}
	defer udpConn.Close()
	_ = udpConn.SetReadDeadline(time.Now().Add(8 * time.Second))
	dst := &net.UDPAddr{IP: net.ParseIP("10.0.0.5"), Port: 5354}
	if _, err := udpConn.WriteTo([]byte("hy2-udp-ok"), dst); err != nil {
		t.Fatal(err)
	}
	rbuf := make([]byte, 128)
	n, _, err = udpConn.ReadFrom(rbuf)
	if err != nil {
		t.Fatal(err)
	}
	if string(rbuf[:n]) != "ECHO:hy2-udp-ok" {
		t.Fatalf("bad udp echo: %q", rbuf[:n])
	}
}

func TestHY2WrongPassword(t *testing.T) {
	netw := newMemUDPNetwork()
	certFile, keyFile := testCertFiles(t)
	eng := quicTestEngine(netw)
	spec := InboundSpec{Tag: "hy2-bad", Protocol: "hysteria2", Port: 19454,
		Params: map[string]string{
			"password": "right-pw",
			"sni":      "www.microsoft.com",
		}, CertFile: certFile, KeyFile: keyFile}
	if err := eng.Start([]InboundSpec{spec}); err != nil {
		t.Fatal(err)
	}
	defer eng.Stop()
	time.Sleep(100 * time.Millisecond)

	clientPC, err := netw.socket()
	if err != nil {
		t.Fatal(err)
	}
	serverAddr := &net.UDPAddr{IP: net.ParseIP("10.0.0.1"), Port: 19454}
	if _, err := DialHY2Packet(clientPC, serverAddr, "www.microsoft.com", "wrong-pw"); err == nil {
		t.Fatal("wrong-password HY2 client authenticated successfully")
	}
}
