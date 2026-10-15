package engine

// Shadowsocks 2022 (SIP022), method 2022-blake3-aes-128-gcm.
// Implemented from the public specification:
//   session key = BLAKE3-DeriveKey("shadowsocks 2022 session subkey", PSK || salt)
//   request  header (AEAD): type 0x00 | timestamp(8, BE) | length(2, BE)
//   response header (AEAD): type 0x01 | timestamp(8, BE) | request salt(16) | length(2, BE)
//   body: classic AEAD chunks — AEAD(uint16 length) | AEAD(payload), nonce++ per op.

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"time"

	"lukechampine.com/blake3"
)

const (
	ssSaltSize    = 16
	ssKeySize     = 16
	ssChunkMax    = 0x3FFF
	ssTimeWindow  = 300 // seconds of tolerated clock skew
	ssDeriveCtx   = "shadowsocks 2022 session subkey"
	ssMethod2022  = "2022-blake3-aes-128-gcm"
)

// DecodePSK parses the base64 server password of a 2022 method.
func DecodePSK(password string) ([]byte, error) {
	psk, err := base64.StdEncoding.DecodeString(password)
	if err != nil {
		return nil, fmt.Errorf("ss2022 password is not valid base64: %w", err)
	}
	if len(psk) != ssKeySize {
		return nil, fmt.Errorf("ss2022 password must decode to %d bytes, got %d", ssKeySize, len(psk))
	}
	return psk, nil
}

func ssSessionKey(psk, salt []byte) []byte {
	material := make([]byte, 0, len(psk)+len(salt))
	material = append(material, psk...)
	material = append(material, salt...)
	out := make([]byte, ssKeySize)
	blake3.DeriveKey(out, ssDeriveCtx, material)
	return out
}

func ssAEAD(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// nonce is a 12-byte little-endian counter.
type ssNonce [12]byte

func (n *ssNonce) inc() {
	for i := 0; i < len(n); i++ {
		n[i]++
		if n[i] != 0 {
			break
		}
	}
}

// chunkReader decrypts a classic AEAD chunk stream.
type chunkReader struct {
	r     io.Reader
	aead  cipher.AEAD
	nonce ssNonce
	buf   bytes.Buffer
}

func (cr *chunkReader) Read(p []byte) (int, error) {
	if cr.buf.Len() == 0 {
		if err := cr.readChunk(); err != nil {
			return 0, err
		}
	}
	return cr.buf.Read(p)
}

func (cr *chunkReader) decryptUnit(expectPlain int) ([]byte, error) {
	ct := make([]byte, expectPlain+cr.aead.Overhead())
	if _, err := io.ReadFull(cr.r, ct); err != nil {
		return nil, err
	}
	pt, err := cr.aead.Open(nil, cr.nonce[:], ct, nil)
	if err != nil {
		return nil, err
	}
	cr.nonce.inc()
	return pt, nil
}

func (cr *chunkReader) readChunk() error {
	lenBytes, err := cr.decryptUnit(2)
	if err != nil {
		return err
	}
	n := int(binary.BigEndian.Uint16(lenBytes))
	if n > ssChunkMax {
		return errors.New("ss: chunk too large")
	}
	payload, err := cr.decryptUnit(n)
	if err != nil {
		return err
	}
	cr.buf.Write(payload)
	return nil
}

// chunkWriter encrypts plaintext into classic AEAD chunks.
type chunkWriter struct {
	w     io.Writer
	aead  cipher.AEAD
	nonce ssNonce
	// prime, when set, is a 2022 response header template (27 bytes) whose
	// length field is patched with the first payload length and sealed as
	// the first unit, followed by that payload as the second unit.
	prime  []byte
	primed bool
}

func (cw *chunkWriter) sealUnit(plain []byte) error {
	ct := cw.aead.Seal(nil, cw.nonce[:], plain, nil)
	cw.nonce.inc()
	_, err := cw.w.Write(ct)
	return err
}

func (cw *chunkWriter) Write(p []byte) (int, error) {
	if cw.prime != nil && !cw.primed {
		cw.primed = true
		n := len(p)
		if n > ssChunkMax {
			n = ssChunkMax
		}
		binary.BigEndian.PutUint16(cw.prime[25:27], uint16(n))
		if err := cw.sealUnit(cw.prime); err != nil {
			return 0, err
		}
		if err := cw.sealUnit(p[:n]); err != nil {
			return 0, err
		}
		if n == len(p) {
			return n, nil
		}
		rest, err := cw.writeChunks(p[n:])
		return n + rest, err
	}
	return cw.writeChunks(p)
}

func (cw *chunkWriter) writeChunks(p []byte) (int, error) {
	total := 0
	for len(p) > 0 {
		n := len(p)
		if n > ssChunkMax {
			n = ssChunkMax
		}
		var lenBuf [2]byte
		binary.BigEndian.PutUint16(lenBuf[:], uint16(n))
		if err := cw.sealUnit(lenBuf[:]); err != nil {
			return total, err
		}
		if err := cw.sealUnit(p[:n]); err != nil {
			return total, err
		}
		total += n
		p = p[n:]
	}
	return total, nil
}

// ---- server ----

// SS2022Server serves one Shadowsocks-2022 inbound.
type SS2022Server struct {
	PSK []byte
	// Meter and Tag instrument the UDP service (TCP is metered by the
	// engine's accept loop). Both may be zero.
	Meter *TrafficMeter
	Tag   string
	// UDPSocketFn creates outbound UDP sockets for sessions; nil uses
	// real UDP sockets.
	UDPSocketFn udpSocketFunc
}

// Handle processes one accepted connection.
func (s *SS2022Server) Handle(conn net.Conn) {
	defer conn.Close()
	// Request salt.
	salt := make([]byte, ssSaltSize)
	if _, err := io.ReadFull(conn, salt); err != nil {
		return
	}
	aead, err := ssAEAD(ssSessionKey(s.PSK, salt))
	if err != nil {
		return
	}
	cr := &chunkReader{r: conn, aead: aead}
	// Request header (fixed 11-byte plaintext unit).
	header, err := cr.decryptUnit(11)
	if err != nil || header[0] != 0x00 {
		return
	}
	ts := int64(binary.BigEndian.Uint64(header[1:9]))
	if delta := time.Now().Unix() - ts; delta > ssTimeWindow || delta < -ssTimeWindow {
		return
	}
	initLen := int(binary.BigEndian.Uint16(header[9:11]))
	initPayload, err := cr.decryptUnit(initLen)
	if err != nil {
		return
	}
	// Initial payload = target address | padding length(2) | padding | early data.
	br := bytes.NewReader(initPayload)
	target, err := ReadSOCKSAddr(br)
	if err != nil {
		return
	}
	var padLenBuf [2]byte
	if _, err := io.ReadFull(br, padLenBuf[:]); err != nil {
		return
	}
	padLen := int(binary.BigEndian.Uint16(padLenBuf[:]))
	if padLen > br.Len() {
		return
	}
	if padLen == 0 && br.Len() == 0 {
		return // anti-probe rule (mirrors reference servers): payload or padding required
	}
	if _, err := io.CopyN(io.Discard, br, int64(padLen)); err != nil {
		return
	}
	early := make([]byte, br.Len())
	_, _ = br.Read(early)

	upstream, err := DialDirect(target)
	if err != nil {
		return
	}
	defer upstream.Close()
	if len(early) > 0 {
		if _, err := upstream.Write(early); err != nil {
			return
		}
	}
	// Response: fresh salt (emitted lazily with the first response data,
	// together with the response header whose variable chunk is that data).
	respSalt := make([]byte, ssSaltSize)
	if _, err := rand.Read(respSalt); err != nil {
		return
	}
	respAEAD, err := ssAEAD(ssSessionKey(s.PSK, respSalt))
	if err != nil {
		return
	}
	var hdr [27]byte
	hdr[0] = 0x01
	binary.BigEndian.PutUint64(hdr[1:9], uint64(time.Now().Unix()))
	copy(hdr[9:25], salt)
	cw := &ssResponseWriter{conn: conn, respSalt: respSalt, cw: &chunkWriter{w: conn, aead: respAEAD, prime: hdr[:]}}
	// Relay both directions immediately: the request stream may carry
	// payload in later chunks that the target needs before it can answer.
	done := make(chan struct{}, 2)
	go func() {
		_, _ = io.Copy(upstream, cr)
		closeWrite(upstream)
		done <- struct{}{}
	}()
	go func() {
		_, _ = io.Copy(cw, upstream)
		done <- struct{}{}
	}()
	<-done
}

// ssResponseWriter emits the response salt on the first write, then
// delegates to the priming chunk writer.
type ssResponseWriter struct {
	conn     net.Conn
	respSalt []byte
	cw       *chunkWriter
	sent     bool
}

func (w *ssResponseWriter) Write(p []byte) (int, error) {
	if !w.sent {
		w.sent = true
		if _, err := w.conn.Write(w.respSalt); err != nil {
			return 0, err
		}
	}
	return w.cw.Write(p)
}

// ---- client ----

type ssClientConn struct {
	net.Conn
	psk      []byte
	reqSalt  []byte
	writer   *chunkWriter
	reader   *chunkReader
	initErr  error
	initOnce bool
}

func (c *ssClientConn) Read(p []byte) (int, error) {
	if !c.initOnce {
		c.initOnce = true
		if err := c.readResponseHeader(); err != nil {
			c.initErr = err
		}
	}
	if c.initErr != nil {
		return 0, c.initErr
	}
	return c.reader.Read(p)
}

func (c *ssClientConn) Write(p []byte) (int, error) { return c.writer.Write(p) }

// readResponseHeader consumes the response salt + header + first chunk.
// It runs lazily on first Read: a proxy client must be able to send its
// payload before the server has anything to answer (the server emits its
// header together with the first response chunk).
func (c *ssClientConn) readResponseHeader() error {
	respSalt := make([]byte, ssSaltSize)
	if _, err := io.ReadFull(c.Conn, respSalt); err != nil {
		return err
	}
	respAEAD, err := ssAEAD(ssSessionKey(c.psk, respSalt))
	if err != nil {
		return err
	}
	cr := &chunkReader{r: c.Conn, aead: respAEAD}
	respHeader, err := cr.decryptUnit(27)
	if err != nil {
		return fmt.Errorf("ss2022 response header: %w", err)
	}
	if respHeader[0] != 0x01 {
		return errors.New("ss2022: bad response type")
	}
	if !bytes.Equal(respHeader[9:25], c.reqSalt) {
		return errors.New("ss2022: response salt mismatch")
	}
	firstLen := int(binary.BigEndian.Uint16(respHeader[25:27]))
	first, err := cr.decryptUnit(firstLen)
	if err != nil {
		return err
	}
	cr.buf.Write(first)
	c.reader = cr
	return nil
}

// DialSS2022 connects to a Shadowsocks-2022 server and opens a tunnel
// to target. The returned conn is a plain stream to the target.
func DialSS2022(server string, psk []byte, target Addr) (net.Conn, error) {
	raw, err := net.Dial("tcp", server)
	if err != nil {
		return nil, err
	}
	fail := func(err error) (net.Conn, error) {
		raw.Close()
		return nil, err
	}
	salt := make([]byte, ssSaltSize)
	if _, err := rand.Read(salt); err != nil {
		return fail(err)
	}
	aead, err := ssAEAD(ssSessionKey(psk, salt))
	if err != nil {
		return fail(err)
	}
	addrBytes, err := target.MarshalSOCKS()
	if err != nil {
		return fail(err)
	}
	// Initial variable chunk: addr | padding length(2) | padding | payload.
	// With no payload at dial time, reference clients still send random
	// padding (1..900 bytes); servers reject addr-only first packets.
	var rb [1]byte
	_, _ = rand.Read(rb[:])
	padLen := 1 + int(rb[0])%900
	initUnit := make([]byte, 0, len(addrBytes)+2+padLen)
	initUnit = append(initUnit, addrBytes...)
	var pl [2]byte
	binary.BigEndian.PutUint16(pl[:], uint16(padLen))
	initUnit = append(initUnit, pl[:]...)
	padding := make([]byte, padLen)
	_, _ = rand.Read(padding)
	initUnit = append(initUnit, padding...)
	cw := &chunkWriter{w: raw, aead: aead}
	if _, err := raw.Write(salt); err != nil {
		return fail(err)
	}
	// Request header + initial unit: the header seals with nonce 0, the
	// unit with nonce 1, later chunks continue the same sequence.
	var hdr [11]byte
	hdr[0] = 0x00
	binary.BigEndian.PutUint64(hdr[1:9], uint64(time.Now().Unix()))
	binary.BigEndian.PutUint16(hdr[9:11], uint16(len(initUnit)))
	if err := cw.sealUnit(hdr[:]); err != nil {
		return fail(err)
	}
	if err := cw.sealUnit(initUnit); err != nil {
		return fail(err)
	}
	return &ssClientConn{Conn: raw, psk: psk, reqSalt: salt, writer: cw}, nil
}
