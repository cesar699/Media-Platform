// Package proto describes the protocols the NATIVE engine implements,
// generates their secrets/certificates, builds engine inbound specs and
// renders client share links.
package proto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"tlcore-native/internal/engine"
	"tlcore-native/internal/store"
)

// Spec describes one selectable protocol in the panel.
type Spec struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	DefaultPort int    `json:"default_port"`
	NeedsCert   bool   `json:"needs_cert"`
}

// Specs returns the protocol catalog shown by the panel — only the
// protocols TLCore-Native implements itself.
func Specs() []Spec {
	return []Spec{
		{"shadowsocks", "Shadowsocks 2022", "自研实现：blake3 新版加密，轻量快速，已与官方互通对验", 8388, false},
		{"trojan", "Trojan", "自研实现：伪装成普通 HTTPS，已与官方互通对验", 4433, true},
		{"anytls", "AnyTLS", "自研实现：抗 TLS-in-TLS 指纹，多路复用 + 记录填充，已与官方互通对验", 9443, true},
		{"tuic", "TUIC v5", "自研实现：QUIC 传输，低延迟，TCP+UDP（沙箱无法实测 UDP 互通，见 README）", 10443, true},
		{"hysteria2", "Hysteria2", "自研实现：QUIC + HTTP/3 伪装，TCP+UDP（沙箱无法实测 UDP 互通，见 README）", 8443, true},
		{"vless", "VLESS", "自研实现：原生 VLESS（无 Reality），已与官方互通对验", 2053, false},
		{"vmess", "VMess", "自研实现：AEAD + AES-128-GCM，已与官方互通对验", 2083, false},
	}
}

// SpecByID finds a protocol spec.
func SpecByID(id string) (Spec, bool) {
	for _, s := range Specs() {
		if s.ID == id {
			return s, true
		}
	}
	return Spec{}, false
}

// NewParams generates fresh secrets for a protocol. For TLS protocols it
// also writes a self-signed cert/key pair under dataDir/certs/<cert_id>.*,
// using sni as the certificate name.
func NewParams(protocol, sni, dataDir string) (map[string]string, error) {
	p := map[string]string{}
	switch protocol {
	case "vless":
		p["uuid"] = newUUID()
	case "trojan":
		p["password"] = randToken(24)
		p["sni"] = sni
	case "anytls":
		p["password"] = randToken(24)
		p["sni"] = sni
	case "tuic":
		p["uuid"] = newUUID()
		p["password"] = randToken(24)
		p["sni"] = sni
	case "hysteria2":
		p["password"] = randToken(24)
		p["sni"] = sni
	case "shadowsocks":
		p["method"] = "2022-blake3-aes-128-gcm"
		p["password"] = base64.StdEncoding.EncodeToString(randBytes(16))
	case "vmess":
		p["uuid"] = newUUID()
	default:
		return nil, fmt.Errorf("unsupported protocol: %s", protocol)
	}
	if spec, _ := SpecByID(protocol); spec.NeedsCert {
		id := randHex(6)
		if err := writeSelfSigned(dataDir, id, sni); err != nil {
			return nil, err
		}
		p["cert_id"] = id
	}
	return p, nil
}

// BuildSpec renders one store.Inbound as a native-engine inbound spec.
func BuildSpec(in *store.Inbound, dataDir string) (engine.InboundSpec, error) {
	spec := engine.InboundSpec{
		Tag:      in.Tag,
		Protocol: in.Protocol,
		Port:     in.Port,
		Params:   in.Params,
	}
	if certID := in.Params["cert_id"]; certID != "" {
		spec.CertFile = filepath.Join(dataDir, "certs", certID+".pem")
		spec.KeyFile = filepath.Join(dataDir, "certs", certID+".key")
	}
	if _, err := engine.HandlerCheck(spec); err != nil {
		return spec, err
	}
	return spec, nil
}

// ShareLink renders the client import link for an inbound.
func ShareLink(in *store.Inbound, serverAddr string) string {
	p := in.Params
	name := url.PathEscape(in.Remark)
	switch in.Protocol {
	case "vless":
		q := url.Values{
			"security": {"none"},
			"type":     {"tcp"},
		}
		return fmt.Sprintf("vless://%s@%s:%d?%s#%s", p["uuid"], serverAddr, in.Port, q.Encode(), name)
	case "trojan":
		return fmt.Sprintf("trojan://%s@%s:%d?sni=%s&allowInsecure=1#%s",
			p["password"], serverAddr, in.Port, url.QueryEscape(p["sni"]), name)
	case "anytls":
		return fmt.Sprintf("anytls://%s@%s:%d?sni=%s&insecure=1#%s",
			p["password"], serverAddr, in.Port, url.QueryEscape(p["sni"]), name)
	case "tuic":
		return fmt.Sprintf("tuic://%s:%s@%s:%d?sni=%s&alpn=h3&congestion_control=bbr&insecure=1#%s",
			p["uuid"], p["password"], serverAddr, in.Port, url.QueryEscape(p["sni"]), name)
	case "hysteria2":
		return fmt.Sprintf("hysteria2://%s@%s:%d?sni=%s&insecure=1#%s",
			p["password"], serverAddr, in.Port, url.QueryEscape(p["sni"]), name)
	case "shadowsocks":
		userinfo := base64.RawURLEncoding.EncodeToString([]byte(p["method"] + ":" + p["password"]))
		return fmt.Sprintf("ss://%s@%s:%d#%s", userinfo, serverAddr, in.Port, name)
	case "vmess":
		doc := map[string]any{
			"v": "2", "ps": in.Remark, "add": serverAddr, "port": strconv.Itoa(in.Port),
			"id": p["uuid"], "aid": "0", "net": "tcp", "type": "none", "tls": "", "scy": "aes-128-gcm",
		}
		data, _ := json.Marshal(doc)
		return "vmess://" + base64.StdEncoding.EncodeToString(data)
	}
	return ""
}

// --- helpers ---

func randBytes(n int) []byte {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return b
}

func randHex(n int) string { return hex.EncodeToString(randBytes(n)) }

func randToken(n int) string {
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
	b := randBytes(n)
	for i := range b {
		b[i] = alphabet[int(b[i])%len(alphabet)]
	}
	return string(b)
}

func newUUID() string {
	b := randBytes(16)
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

// writeSelfSigned creates an ECDSA P-256 self-signed cert for sni and stores
// it as dataDir/certs/<id>.pem / .key.
func writeSelfSigned(dataDir, id, sni string) error {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().Unix()),
		Subject:      pkix.Name{CommonName: sni},
		DNSNames:     []string{sni},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().AddDate(10, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return err
	}
	dir := filepath.Join(dataDir, "certs")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	if err := os.WriteFile(filepath.Join(dir, id+".pem"), certPEM, 0o644); err != nil {
		return err
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	return os.WriteFile(filepath.Join(dir, id+".key"), keyPEM, 0o600)
}
