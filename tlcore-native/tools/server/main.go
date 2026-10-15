// Server: run one native-engine inbound for interop testing.
//
// Usage:
//
//	server -proto ss2022 -port 18388 -password <base64>
//	server -proto trojan -port 14443 -password <pw> -cert cert.pem -key key.pem
//	server -proto vless  -port 10443 -uuid <uuid>
//	server -proto anytls -port 19443 -password <pw> -cert cert.pem -key key.pem
package main

import (
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"

	"tlcore-native/internal/engine"
)

func main() {
	protoName := flag.String("proto", "", "shadowsocks | trojan | vless | vmess | anytls")
	port := flag.Int("port", 0, "listen port")
	password := flag.String("password", "", "password param")
	uuid := flag.String("uuid", "", "uuid param")
	cert := flag.String("cert", "", "TLS cert file")
	key := flag.String("key", "", "TLS key file")
	flag.Parse()

	spec := engine.InboundSpec{
		Tag:      *protoName,
		Protocol: map[string]string{"ss2022": "shadowsocks"}[*protoName],
		Port:     *port,
		Params:   map[string]string{"password": *password, "uuid": *uuid},
		CertFile: *cert,
		KeyFile:  *key,
	}
	if spec.Protocol == "" {
		spec.Protocol = *protoName
	}
	e := &engine.Engine{}
	if err := e.Start([]engine.InboundSpec{spec}); err != nil {
		log.Fatal(err)
	}
	log.Printf("native %s listening on :%d", *protoName, *port)
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGINT, syscall.SIGTERM)
	<-ch
	e.Stop()
}
