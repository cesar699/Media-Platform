// Vmprobe: dial a VMess server with the native client, send an HTTP GET,
// and print the response or the exact error. Debug tool for interop work.
//
// Usage: vmprobe -server 127.0.0.1:12054 -uuid <uuid> -target 127.0.0.1:18081
package main

import (
	"flag"
	"fmt"
	"io"
	"net"
	"time"

	"tlcore-native/internal/engine"
)

func main() {
	server := flag.String("server", "", "vmess server host:port")
	uuid := flag.String("uuid", "", "uuid")
	target := flag.String("target", "127.0.0.1:18081", "target host:port")
	flag.Parse()

	addr, err := engine.ParseHostPort(*target)
	if err != nil {
		fmt.Println("bad target:", err)
		return
	}
	conn, err := engine.DialVMess(*server, *uuid, addr)
	if err != nil {
		fmt.Println("DIAL ERROR:", err)
		return
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	req := fmt.Sprintf("GET /marker.txt HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", *target)
	if _, err := conn.Write([]byte(req)); err != nil {
		fmt.Println("WRITE ERROR:", err)
		return
	}
	data, err := io.ReadAll(conn)
	fmt.Printf("READ: %d bytes, err=%v\n", len(data), err)
	if len(data) > 0 {
		fmt.Printf("BODY:\n%s\n", data)
	}
	_ = net.IPv4len // keep net import if unused in future edits
}
