package engine

// Shared UDP plumbing for the native engine: outbound socket creation
// (injectable for tests, whose environment cannot pass real UDP), target
// resolution and reply pumps.

import (
	"fmt"
	"net"
)

// udpSocketFunc creates an unbound outbound UDP socket.
type udpSocketFunc func() (net.PacketConn, error)

// defaultUDPSocket binds an ephemeral UDP port.
func defaultUDPSocket() (net.PacketConn, error) {
	return net.ListenPacket("udp", ":0")
}

// defaultListenPacket binds a UDP listener.
func defaultListenPacket(network, address string) (net.PacketConn, error) {
	return net.ListenPacket(network, address)
}

// resolveUDPAddr resolves a target Addr to a UDP address.
func resolveUDPAddr(a Addr) (*net.UDPAddr, error) {
	ua, err := net.ResolveUDPAddr("udp", a.String())
	if err != nil {
		return nil, fmt.Errorf("resolve %s: %w", a.String(), err)
	}
	return ua, nil
}

// addrFromUDP converts a UDP source address to wire Addr form (IP literal).
func addrFromUDP(ua *net.UDPAddr) Addr {
	a := Addr{Host: ua.IP.String(), Port: ua.Port}
	if ua.IP.To4() != nil {
		a.IPv4 = true
	} else {
		a.IPv6 = true
	}
	return a
}

// udpReplyPump reads datagrams from sock until error and hands each to
// onPacket with its source address. It is the response half of every
// UDP relay session in this package.
func udpReplyPump(sock net.PacketConn, onPacket func(src Addr, payload []byte)) {
	buf := make([]byte, 65535)
	for {
		n, from, err := sock.ReadFrom(buf)
		if err != nil {
			return
		}
		ua, ok := from.(*net.UDPAddr)
		if !ok {
			continue
		}
		payload := make([]byte, n)
		copy(payload, buf[:n])
		onPacket(addrFromUDP(ua), payload)
	}
}
