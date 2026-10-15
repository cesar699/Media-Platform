package engine

// Debug harness: feed a captured reference-client VMess request through
// the server-side parsing stages and report where it fails.
// Run: CAPTURE_FILE=... CAPTURE_UUID=... go test ./internal/engine/ -run TestCapturedRequest -v

import (
	"bytes"
	"encoding/binary"
	"os"
	"testing"
)

func TestCapturedRequest(t *testing.T) {
	path := os.Getenv("CAPTURE_FILE")
	uuid := os.Getenv("CAPTURE_UUID")
	if path == "" || uuid == "" {
		t.Skip("CAPTURE_FILE/CAPTURE_UUID not set")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("captured %d bytes", len(raw))
	userKey, err := vmessUserKey(uuid)
	if err != nil {
		t.Fatal(err)
	}
	r := bytes.NewReader(raw)
	authID := make([]byte, 16)
	if _, err := r.Read(authID); err != nil {
		t.Fatal(err)
	}
	if !checkAuthID(userKey, authID) {
		t.Fatalf("STAGE FAIL: authID check")
	}
	t.Log("authID OK")
	sealedLen := make([]byte, 18)
	if _, err := r.Read(sealedLen); err != nil {
		t.Fatal(err)
	}
	connNonce := make([]byte, 8)
	if _, err := r.Read(connNonce); err != nil {
		t.Fatal(err)
	}
	lenKey := vmessKDF(userKey[:], "VMess Header AEAD Key_Length", authID, connNonce)[:16]
	lenNonce := vmessKDF(userKey[:], "VMess Header AEAD Nonce_Length", authID, connNonce)[:12]
	lenAEAD, err := vmessGCM(lenKey)
	if err != nil {
		t.Fatal(err)
	}
	lenBytes, err := lenAEAD.Open(nil, lenNonce, sealedLen, authID)
	if err != nil {
		t.Fatalf("STAGE FAIL: header length open: %v", err)
	}
	headerLen := int(binary.BigEndian.Uint16(lenBytes))
	t.Logf("header length OK: %d", headerLen)
	sealedHeader := make([]byte, headerLen+16)
	if _, err := r.Read(sealedHeader); err != nil {
		t.Fatal(err)
	}
	hdrKey := vmessKDF(userKey[:], "VMess Header AEAD Key", authID, connNonce)[:16]
	hdrNonce := vmessKDF(userKey[:], "VMess Header AEAD Nonce", authID, connNonce)[:12]
	hdrAEAD, err := vmessGCM(hdrKey)
	if err != nil {
		t.Fatal(err)
	}
	plain, err := hdrAEAD.Open(nil, hdrNonce, sealedHeader, authID)
	if err != nil {
		t.Fatalf("STAGE FAIL: header open: %v", err)
	}
	t.Logf("header decrypt OK: %d bytes", len(plain))
	req, err := parseHeaderPlaintext(plain)
	if err != nil {
		t.Fatalf("STAGE FAIL: header parse: %v", err)
	}
	t.Logf("header parse OK: target=%s option=%d respAuth=%d", req.target.String(), req.option, req.respAuth)
	// Remaining bytes are the first body chunk(s): the GET request.
	rest := raw[len(raw)-r.Len():]
	t.Logf("remaining body bytes: %d", len(rest))
	bodyReader, err := makeBodyReader(bytes.NewReader(rest), req.option, req.reqKey[:], req.reqNonce[:], req.reqKey[:], req.reqNonce[:])
	if err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 4096)
	n, err := bodyReader.Read(buf)
	if err != nil {
		t.Fatalf("STAGE FAIL: body chunk read: %v", err)
	}
	t.Logf("body chunk OK: %q", buf[:n])
}
