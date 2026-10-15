// Probe: local mixed (SOCKS5/HTTP) gateway chained to a native-engine
// protocol client. Used by the end-to-end interop tests.
//
// Usage:
//
//	probe -listen 127.0.0.1:11080 -proto ss2022 -server 127.0.0.1:18388 -password <base64>
//	probe -listen 127.0.0.1:11080 -proto trojan -server 127.0.0.1:14443 -password <pw> -sni www.microsoft.com
//	probe -listen 127.0.0.1:11080 -proto vless  -server 127.0.0.1:10443 -uuid <uuid>
package main

import (
	"flag"
	"log"
	"net"

	"tlcore-native/internal/engine"
)

func main() {
	listen := flag.String("listen", "127.0.0.1:11080", "local mixed inbound address")
	protoName := flag.String("proto", "", "ss2022 | trojan | vless | vmess | anytls")
	server := flag.String("server", "", "proxy server host:port")
	password := flag.String("password", "", "password (ss2022: base64 PSK; trojan: plain)")
	uuid := flag.String("uuid", "", "uuid (vless/vmess)")
	sni := flag.String("sni", "www.microsoft.com", "TLS server name (trojan)")
	flag.Parse()

	var dial engine.DialFunc
	switch *protoName {
	case "ss2022":
		psk, err := engine.DecodePSK(*password)
		if err != nil {
			log.Fatal(err)
		}
		dial = func(t engine.Addr) (net.Conn, error) { return engine.DialSS2022(*server, psk, t) }
	case "trojan":
		dial = func(t engine.Addr) (net.Conn, error) { return engine.DialTrojan(*server, *password, *sni, t) }
	case "vless":
		dial = func(t engine.Addr) (net.Conn, error) { return engine.DialVLESS(*server, *uuid, t) }
	case "vmess":
		dial = func(t engine.Addr) (net.Conn, error) { return engine.DialVMess(*server, *uuid, t) }
	case "anytls":
		dial = func(t engine.Addr) (net.Conn, error) { return engine.DialAnyTLS(*server, *password, *sni, t) }
	case "tuic":
		uuid, err := engine.ParseUUID(*uuid)
		if err != nil {
			log.Fatal(err)
		}
		var client *engine.TUICClient
		dial = func(t engine.Addr) (net.Conn, error) {
			if client == nil {
				c, err := engine.DialTUIC(*server, *sni, uuid, *password)
				if err != nil {
					return nil, err
				}
				client = c
			}
			return client.DialTCP(t)
		}
	case "hysteria2":
		var client *engine.HY2Client
		dial = func(t engine.Addr) (net.Conn, error) {
			if client == nil {
				c, err := engine.DialHY2(*server, *sni, *password)
				if err != nil {
					return nil, err
				}
				client = c
			}
			return client.DialTCP(t)
		}
	default:
		log.Fatalf("unknown proto %q", *protoName)
	}
	ln, err := net.Listen("tcp", *listen)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("probe: %s via %s %s", *listen, *protoName, *server)
	engine.ServeMixed(ln, dial)
}
