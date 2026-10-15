package engine

// VMess (AEAD variant, AES-128-GCM body security), implemented from the
// protocol's public documentation and wire behavior:
//
//   user key      = MD5(uuid || "c48619fe-8f02-49e0-b9e9-edf763e17e21")
//   AuthID        = AES-128-ECB(KDF(key,"AES Auth ID Encryption")[:16],
//                   timestamp(8) | random(4) | crc32(first 12 bytes))
//   header wrap   = authID(16) | AEAD(len) | connNonce(8) | AEAD(header)
//                   with KDF(key, "VMess Header AEAD Key[_Length]", authID, nonce)
//                   and the authID as AEAD additional data
//   header        = version(1) | reqIV(16) | reqKey(16) | respAuth(1) | option(1)
//                   | padding<<4|security(1) | reserved(1) | command(1)
//                   | port+address | padding | FNV-1a-32(4)
//   body          = two-layer chunks: outer AEAD length records keyed by
//                   KDF(bodyKey,"auth_len"), inner AES-128-GCM chunks; both
//                   nonces are the base nonce with a big-endian counter in
//                   the first two bytes
//   response keys = SHA-256(reqKey)[:16] / SHA-256(reqNonce)[:16], header
//                   wrapped with KDF salts "AEAD Resp Header ..."

import (
	"bufio"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"hash/crc32"
	"hash/fnv"
	"io"
	"net"
	"time"

	"golang.org/x/crypto/sha3"
)

const (
	vmessVersion      = 1
	vmessSecurityAES  = 3 // AES-128-GCM
	vmessOptChunk     = 1 // chunk stream
	vmessOptAuthLen   = 16
	vmessCmdTCP       = 1
	vmessCmdUDP       = 2
	vmessAuthIDSalt   = "AES Auth ID Encryption"
	vmessKDFRoot      = "VMess AEAD KDF"
	vmessTimeWindow   = 300
)

// vmessUserKey derives the 16-byte user key from a UUID.
func vmessUserKey(uuidStr string) ([16]byte, error) {
	id, err := ParseUUID(uuidStr)
	if err != nil {
		return [16]byte{}, err
	}
	h := md5.New()
	h.Write(id[:])
	h.Write([]byte("c48619fe-8f02-49e0-b9e9-edf763e17e21"))
	var key [16]byte
	copy(key[:], h.Sum(nil))
	return key, nil
}

// vmessKDF is the nested-HMAC chain: HMAC-SHA256 rooted at
// "VMess AEAD KDF", then keyed by salt, then by each path element.
func vmessKDF(key []byte, salt string, path ...[]byte) []byte {
	create := func() hash.Hash { return hmac.New(sha256.New, []byte(vmessKDFRoot)) }
	wrap := func(parent func() hash.Hash, value []byte) func() hash.Hash {
		return func() hash.Hash { return hmac.New(parent, value) }
	}
	create = wrap(create, []byte(salt))
	for _, p := range path {
		create = wrap(create, p)
	}
	h := create()
	h.Write(key)
	return h.Sum(nil)
}

func vmessGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// makeAuthID builds the 16-byte AEAD auth ID for the user key.
func makeAuthID(userKey [16]byte, ts time.Time) []byte {
	var buf [16]byte
	binary.BigEndian.PutUint64(buf[0:8], uint64(ts.Unix()))
	_, _ = rand.Read(buf[8:12])
	binary.BigEndian.PutUint32(buf[12:16], crc32.ChecksumIEEE(buf[0:12]))
	encKey := vmessKDF(userKey[:], vmessAuthIDSalt)[:16]
	block, _ := aes.NewCipher(encKey)
	block.Encrypt(buf[:], buf[:])
	return buf[:]
}

// checkAuthID decrypts an auth ID and validates checksum + timestamp.
func checkAuthID(userKey [16]byte, authID []byte) bool {
	if len(authID) != 16 {
		return false
	}
	encKey := vmessKDF(userKey[:], vmessAuthIDSalt)[:16]
	block, _ := aes.NewCipher(encKey)
	var buf [16]byte
	block.Decrypt(buf[:], authID)
	if crc32.ChecksumIEEE(buf[0:12]) != binary.BigEndian.Uint32(buf[12:16]) {
		return false
	}
	ts := int64(binary.BigEndian.Uint64(buf[0:8]))
	delta := time.Now().Unix() - ts
	return delta <= vmessTimeWindow && delta >= -vmessTimeWindow
}

// vmessAddr encodes port-first VMess address form.
func vmessAddr(a Addr) ([]byte, error) {
	var buf bytes.Buffer
	var pb [2]byte
	binary.BigEndian.PutUint16(pb[:], uint16(a.Port))
	buf.Write(pb[:])
	switch {
	case a.IPv4:
		buf.WriteByte(0x01)
		buf.Write(net.ParseIP(a.Host).To4())
	case a.IPv6:
		buf.WriteByte(0x03)
		buf.Write(net.ParseIP(a.Host).To16())
	default:
		if len(a.Host) > 255 {
			return nil, fmt.Errorf("domain too long")
		}
		buf.WriteByte(0x02)
		buf.WriteByte(byte(len(a.Host)))
		buf.WriteString(a.Host)
	}
	return buf.Bytes(), nil
}

func readVMessAddr(r io.Reader) (Addr, error) {
	var pb [2]byte
	if _, err := io.ReadFull(r, pb[:]); err != nil {
		return Addr{}, err
	}
	a := Addr{Port: int(binary.BigEndian.Uint16(pb[:]))}
	var at [1]byte
	if _, err := io.ReadFull(r, at[:]); err != nil {
		return Addr{}, err
	}
	switch at[0] {
	case 0x01:
		var b [4]byte
		if _, err := io.ReadFull(r, b[:]); err != nil {
			return Addr{}, err
		}
		a.Host, a.IPv4 = net.IP(b[:]).String(), true
	case 0x02:
		var l [1]byte
		if _, err := io.ReadFull(r, l[:]); err != nil {
			return Addr{}, err
		}
		b := make([]byte, int(l[0]))
		if _, err := io.ReadFull(r, b); err != nil {
			return Addr{}, err
		}
		a.Host = string(b)
	case 0x03:
		var b [16]byte
		if _, err := io.ReadFull(r, b[:]); err != nil {
			return Addr{}, err
		}
		a.Host, a.IPv6 = net.IP(b[:]).String(), true
	default:
		return Addr{}, fmt.Errorf("vmess: bad address type %d", at[0])
	}
	return a, nil
}

// ---- body chunk layer ----
//
// VMess bodies are two nested layers: an inner per-chunk AES-128-GCM
// layer (body key; nonce = base nonce with a big-endian counter in the
// first two bytes) and an outer framing layer in one of two profiles
// chosen by the header's option byte:
//
//   - chunk masking (options 0x05, the reference client's default):
//     framing = uint16 length XOR SHAKE128(nonce) stream | raw ciphertext
//     blocks of that length, opened one by one by the inner layer.
//   - authenticated length (options 0x11): framing = separate AEAD
//     length records keyed by KDF(lenKey, "auth_len"); the length layer
//     is ALWAYS keyed from the request key/nonce, even in the response
//     direction — a protocol quirk confirmed against the reference.

const vmessOptMasking = 4 // RequestOptionChunkMasking

// makeBodyReader builds the layered body reader for one direction.
// dataKey/dataNonce belong to this direction; lenKey/lenNonce are the
// request key/nonce (used by the auth-length framing in both directions).
func makeBodyReader(r io.Reader, option byte, dataKey, dataNonce, lenKey, lenNonce []byte) (io.Reader, error) {
	if option&vmessOptAuthLen != 0 {
		return newVMessChunkReader(r, dataKey, dataNonce, lenKey, lenNonce)
	}
	// Masking profile: stream-chunk framing outside, AEAD chunks inside.
	framed, err := newMaskChunkReader(r, dataNonce)
	if err != nil {
		return nil, err
	}
	return newVMessAEADReader(framed, dataKey, dataNonce)
}

// makeBodyWriter builds the layered body writer for one direction.
func makeBodyWriter(w io.Writer, option byte, dataKey, dataNonce, lenKey, lenNonce []byte) (io.Writer, error) {
	if option&vmessOptAuthLen != 0 {
		return newVMessChunkWriter(w, dataKey, dataNonce, lenKey, lenNonce)
	}
	mw, err := newMaskChunkWriter(w, dataNonce)
	if err != nil {
		return nil, err
	}
	return &vmessAEADWriter{w: mw, key: dataKey, nonceBase: dataNonce}, nil
}

// ---- packet mode (UDP command): one chunk == one datagram ----

type vmessPacketReader interface {
	ReadPacket() ([]byte, error)
}

type vmessPacketWriter interface {
	WritePacket([]byte) error
}

// makePacketReader builds the packet-mode body reader for one direction.
func makePacketReader(r io.Reader, option byte, dataKey, dataNonce, lenKey, lenNonce []byte) (vmessPacketReader, error) {
	if option&vmessOptAuthLen != 0 {
		return newVMessChunkReader(r, dataKey, dataNonce, lenKey, lenNonce)
	}
	mr, err := newMaskChunkReader(r, dataNonce)
	if err != nil {
		return nil, err
	}
	aead, err := vmessGCM(dataKey[:16])
	if err != nil {
		return nil, err
	}
	return &maskPacketReader{mr: mr, aead: aead, nonceBase: dataNonce}, nil
}

// makePacketWriter builds the packet-mode body writer for one direction.
func makePacketWriter(w io.Writer, option byte, dataKey, dataNonce, lenKey, lenNonce []byte) (vmessPacketWriter, error) {
	if option&vmessOptAuthLen != 0 {
		return newVMessChunkWriter(w, dataKey, dataNonce, lenKey, lenNonce)
	}
	mw, err := newMaskChunkWriter(w, dataNonce)
	if err != nil {
		return nil, err
	}
	aead, err := vmessGCM(dataKey[:16])
	if err != nil {
		return nil, err
	}
	return &maskPacketWriter{mw: mw, aead: aead, nonceBase: dataNonce}, nil
}

// maskPacketReader opens one masked block per datagram (masking profile).
type maskPacketReader struct {
	mr        *maskChunkReader
	aead      cipher.AEAD
	nonceBase []byte
	cnt       uint16
}

func (pr *maskPacketReader) ReadPacket() ([]byte, error) {
	block, err := pr.mr.readBlock()
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, 12)
	copy(nonce, pr.nonceBase[:12])
	binary.BigEndian.PutUint16(nonce[0:2], pr.cnt)
	pr.cnt++
	data, err := pr.aead.Open(nil, nonce, block, nil)
	if err != nil {
		return nil, fmt.Errorf("vmess udp chunk: %w", err)
	}
	return data, nil
}

// maskPacketWriter seals one datagram as one chunk (masking profile).
type maskPacketWriter struct {
	mw        *maskChunkWriter
	aead      cipher.AEAD
	nonceBase []byte
	cnt       uint16
}

func (pw *maskPacketWriter) WritePacket(p []byte) error {
	if len(p) > 65535 {
		return errPayloadTooLarge
	}
	nonce := make([]byte, 12)
	copy(nonce, pw.nonceBase[:12])
	binary.BigEndian.PutUint16(nonce[0:2], pw.cnt)
	pw.cnt++
	sealed := pw.aead.Seal(nil, nonce, p, nil)
	_, err := pw.mw.Write(sealed)
	return err
}

// ---- masking stream-chunk framing ----

type maskChunkWriter struct {
	w     io.Writer
	shake io.Reader // SHAKE128 stream (as io.Reader via sha3.ShakeHash)
}

func newMaskChunkWriter(w io.Writer, nonce []byte) (*maskChunkWriter, error) {
	h := sha3.NewShake128()
	if _, err := h.Write(nonce); err != nil {
		return nil, err
	}
	return &maskChunkWriter{w: w, shake: h}, nil
}

func (mw *maskChunkWriter) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	var mask [2]byte
	if _, err := io.ReadFull(mw.shake, mask[:]); err != nil {
		return 0, err
	}
	length := uint16(len(p)) ^ binary.BigEndian.Uint16(mask[:])
	var lb [2]byte
	binary.BigEndian.PutUint16(lb[:], length)
	if _, err := mw.w.Write(lb[:]); err != nil {
		return 0, err
	}
	return mw.w.Write(p)
}

type maskChunkReader struct {
	r     io.Reader
	shake io.Reader
	buf   bytes.Buffer
}

func newMaskChunkReader(r io.Reader, nonce []byte) (*maskChunkReader, error) {
	h := sha3.NewShake128()
	if _, err := h.Write(nonce); err != nil {
		return nil, err
	}
	return &maskChunkReader{r: r, shake: h}, nil
}

func (mr *maskChunkReader) Read(p []byte) (int, error) {
	if mr.buf.Len() == 0 {
		block, err := mr.readBlock()
		if err != nil {
			return 0, err
		}
		mr.buf.Write(block)
	}
	return mr.buf.Read(p)
}

// readBlock returns the next raw masked block (one AEAD chunk's worth of
// ciphertext in packet mode). A zero-length block is the stream
// terminator and reports io.EOF.
func (mr *maskChunkReader) readBlock() ([]byte, error) {
	var lb [2]byte
	if _, err := io.ReadFull(mr.r, lb[:]); err != nil {
		return nil, err
	}
	var mask [2]byte
	if _, err := io.ReadFull(mr.shake, mask[:]); err != nil {
		return nil, err
	}
	length := binary.BigEndian.Uint16(lb[:]) ^ binary.BigEndian.Uint16(mask[:])
	if length == 0 {
		return nil, io.EOF
	}
	block := make([]byte, int(length))
	if _, err := io.ReadFull(mr.r, block); err != nil {
		return nil, err
	}
	return block, nil
}

// ---- inner AEAD chunk layer (counter nonce) ----

// vmessAEADWriter seals each Write as one AES-GCM chunk.
type vmessAEADWriter struct {
	w         io.Writer
	key       []byte
	nonceBase []byte
	aead      cipher.AEAD
	cnt       uint16
}

func (w *vmessAEADWriter) Write(p []byte) (int, error) {
	if w.aead == nil {
		aead, err := vmessGCM(w.key[:16])
		if err != nil {
			return 0, err
		}
		w.aead = aead
	}
	total := 0
	for len(p) > 0 {
		n := len(p)
		if n > 8192 {
			n = 8192
		}
		nonce := make([]byte, 12)
		copy(nonce, w.nonceBase[:12])
		binary.BigEndian.PutUint16(nonce[0:2], w.cnt)
		w.cnt++
		if _, err := w.w.Write(w.aead.Seal(nil, nonce, p[:n], nil)); err != nil {
			return total, err
		}
		total += n
		p = p[n:]
	}
	return total, nil
}

// vmessAEADReader opens one sealed block per underlying Read unit. The
// framing reader below it yields exactly one sealed chunk per Read.
type vmessAEADReader struct {
	r         io.Reader
	aead      cipher.AEAD
	nonceBase []byte
	cnt       uint16
	buf       bytes.Buffer
}

func newVMessAEADReader(r io.Reader, key, nonceBase []byte) (*vmessAEADReader, error) {
	aead, err := vmessGCM(key[:16])
	if err != nil {
		return nil, err
	}
	return &vmessAEADReader{r: r, aead: aead, nonceBase: nonceBase}, nil
}

func (rd *vmessAEADReader) Read(p []byte) (int, error) {
	if rd.buf.Len() == 0 {
		block := make([]byte, 8192+16)
		n, err := rd.r.Read(block)
		if err != nil {
			return 0, err
		}
		nonce := make([]byte, 12)
		copy(nonce, rd.nonceBase[:12])
		binary.BigEndian.PutUint16(nonce[0:2], rd.cnt)
		rd.cnt++
		data, err := rd.aead.Open(nil, nonce, block[:n], nil)
		if err != nil {
			return 0, fmt.Errorf("vmess data chunk: %w", err)
		}
		rd.buf.Write(data)
	}
	return rd.buf.Read(p)
}

// vmessChunkWriter seals data chunks: inner AES-GCM with the data key,
// outer length records with KDF(lenKey, "auth_len"). The two layers use
// different key material: the length layer is ALWAYS keyed from the
// request key/nonce (even in the response direction, where the data
// layer switches to the SHA-256-derived response key/nonce) — a quirk
// of the protocol confirmed against the reference implementation.
type vmessChunkWriter struct {
	w        io.Writer
	dataAEAD cipher.AEAD
	lenAEAD  cipher.AEAD
	nonce    [12]byte // data-layer base nonce
	lenNonce [12]byte // length-layer base nonce
	dataCnt  uint16
	lenCnt   uint16
}

func newVMessChunkWriter(w io.Writer, dataKey, dataNonce, lenKey, lenNonce []byte) (*vmessChunkWriter, error) {
	dataAEAD, err := vmessGCM(dataKey[:16])
	if err != nil {
		return nil, err
	}
	lenAEAD, err := vmessGCM(vmessKDF(lenKey[:16], "auth_len")[:16])
	if err != nil {
		return nil, err
	}
	cw := &vmessChunkWriter{w: w, dataAEAD: dataAEAD, lenAEAD: lenAEAD}
	copy(cw.nonce[:], dataNonce[:12])
	copy(cw.lenNonce[:], lenNonce[:12])
	return cw, nil
}

func counterNonce(base [12]byte, counter uint16) []byte {
	n := make([]byte, 12)
	copy(n, base[:])
	binary.BigEndian.PutUint16(n[0:2], counter)
	return n
}

func (cw *vmessChunkWriter) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	// Split like the reference writer (payloads are caller-chunked already
	// by io.Copy's buffer; cap at 8192 to stay well under the uint16 field).
	total := 0
	for len(p) > 0 {
		n := len(p)
		if n > 8192 {
			n = 8192
		}
		if err := cw.writeOne(p[:n]); err != nil {
			return total, err
		}
		total += n
		p = p[n:]
	}
	return total, nil
}

// WritePacket seals the whole datagram as a single chunk (UDP mode).
func (cw *vmessChunkWriter) WritePacket(p []byte) error {
	if len(p) > 65535 {
		return errPayloadTooLarge
	}
	return cw.writeOne(p)
}

func (cw *vmessChunkWriter) writeOne(chunk []byte) error {
	sealed := cw.dataAEAD.Seal(nil, counterNonce(cw.nonce, cw.dataCnt), chunk, nil)
	cw.dataCnt++
	var lenBuf [2]byte
	binary.BigEndian.PutUint16(lenBuf[:], uint16(len(chunk)))
	sealedLen := cw.lenAEAD.Seal(nil, counterNonce(cw.lenNonce, cw.lenCnt), lenBuf[:], nil)
	cw.lenCnt++
	if _, err := cw.w.Write(sealedLen); err != nil {
		return err
	}
	_, err := cw.w.Write(sealed)
	return err
}

// vmessChunkReader reverses vmessChunkWriter.
type vmessChunkReader struct {
	r        io.Reader
	dataAEAD cipher.AEAD
	lenAEAD  cipher.AEAD
	nonce    [12]byte
	lenNonce [12]byte
	dataCnt  uint16
	lenCnt   uint16
	buf      bytes.Buffer
}

func newVMessChunkReader(r io.Reader, dataKey, dataNonce, lenKey, lenNonce []byte) (*vmessChunkReader, error) {
	dataAEAD, err := vmessGCM(dataKey[:16])
	if err != nil {
		return nil, err
	}
	lenAEAD, err := vmessGCM(vmessKDF(lenKey[:16], "auth_len")[:16])
	if err != nil {
		return nil, err
	}
	cr := &vmessChunkReader{r: r, dataAEAD: dataAEAD, lenAEAD: lenAEAD}
	copy(cr.nonce[:], dataNonce[:12])
	copy(cr.lenNonce[:], lenNonce[:12])
	return cr, nil
}

func (cr *vmessChunkReader) Read(p []byte) (int, error) {
	if cr.buf.Len() == 0 {
		data, err := cr.readChunkData()
		if err != nil {
			return 0, err
		}
		cr.buf.Write(data)
	}
	return cr.buf.Read(p)
}

// ReadPacket returns exactly one chunk as one datagram (UDP mode).
func (cr *vmessChunkReader) ReadPacket() ([]byte, error) {
	return cr.readChunkData()
}

func (cr *vmessChunkReader) readChunkData() ([]byte, error) {
	sealedLen := make([]byte, 2+16)
	if _, err := io.ReadFull(cr.r, sealedLen); err != nil {
		return nil, err
	}
	lenBytes, err := cr.lenAEAD.Open(nil, counterNonce(cr.lenNonce, cr.lenCnt), sealedLen, nil)
	if err != nil {
		return nil, fmt.Errorf("vmess length chunk: %w", err)
	}
	cr.lenCnt++
	plainLen := int(binary.BigEndian.Uint16(lenBytes))
	sealed := make([]byte, plainLen+16)
	if _, err := io.ReadFull(cr.r, sealed); err != nil {
		return nil, err
	}
	data, err := cr.dataAEAD.Open(nil, counterNonce(cr.nonce, cr.dataCnt), sealed, nil)
	if err != nil {
		return nil, fmt.Errorf("vmess data chunk: %w", err)
	}
	cr.dataCnt++
	return data, nil
}

// ---- header build/parse ----

type vmessRequest struct {
	reqKey   [16]byte
	reqNonce [16]byte
	respAuth byte
	option   byte
	cmd      byte
	target   Addr
}

// buildHeaderPlaintext assembles the unencrypted header for target.
func buildHeaderPlaintext(target Addr, cmd byte, reqKey, reqNonce [16]byte, respAuth byte) ([]byte, error) {
	addrBytes, err := vmessAddr(target)
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	buf.WriteByte(vmessVersion)
	buf.Write(reqNonce[:])
	buf.Write(reqKey[:])
	buf.WriteByte(respAuth)
	buf.WriteByte(vmessOptChunk | vmessOptMasking)
	buf.WriteByte(vmessSecurityAES) // padding length 0 in the high nibble
	buf.WriteByte(0)
	buf.WriteByte(cmd)
	buf.Write(addrBytes)
	h := fnv.New32a()
	_, _ = h.Write(buf.Bytes())
	var sum [4]byte
	binary.BigEndian.PutUint32(sum[:], h.Sum32())
	buf.Write(sum[:])
	return buf.Bytes(), nil
}

// parseHeaderPlaintext validates the FNV checksum and decodes the header.
func parseHeaderPlaintext(plain []byte) (*vmessRequest, error) {
	if len(plain) < 1+16+16+1+1+1+1+1+4 {
		return nil, errors.New("vmess: header too short")
	}
	body := plain[:len(plain)-4]
	want := binary.BigEndian.Uint32(plain[len(plain)-4:])
	h := fnv.New32a()
	_, _ = h.Write(body)
	if h.Sum32() != want {
		return nil, errors.New("vmess: header checksum mismatch")
	}
	req := &vmessRequest{}
	r := bytes.NewReader(body)
	ver, _ := r.ReadByte()
	if ver != vmessVersion {
		return nil, fmt.Errorf("vmess: unsupported version %d", ver)
	}
	_, _ = io.ReadFull(r, req.reqNonce[:])
	_, _ = io.ReadFull(r, req.reqKey[:])
	req.respAuth, _ = r.ReadByte()
	req.option, _ = r.ReadByte()
	padSec, _ := r.ReadByte()
	if padSec&0x0F != vmessSecurityAES {
		return nil, fmt.Errorf("vmess: unsupported security %d", padSec&0x0F)
	}
	paddingLen := int(padSec >> 4)
	_, _ = r.ReadByte() // reserved
	cmd, _ := r.ReadByte()
	if cmd != vmessCmdTCP && cmd != vmessCmdUDP {
		return nil, fmt.Errorf("vmess: unsupported command %d", cmd)
	}
	req.cmd = cmd
	target, err := readVMessAddr(r)
	if err != nil {
		return nil, err
	}
	req.target = target
	if paddingLen > 0 {
		if _, err := io.CopyN(io.Discard, r, int64(paddingLen)); err != nil {
			return nil, err
		}
	}
	return req, nil
}

// wrapHeader seals the header plaintext the AEAD way.
func wrapHeader(userKey [16]byte, authID, plain []byte) ([]byte, error) {
	connNonce := make([]byte, 8)
	if _, err := rand.Read(connNonce); err != nil {
		return nil, err
	}
	lenKey := vmessKDF(userKey[:], "VMess Header AEAD Key_Length", authID, connNonce)[:16]
	lenNonce := vmessKDF(userKey[:], "VMess Header AEAD Nonce_Length", authID, connNonce)[:12]
	lenAEAD, err := vmessGCM(lenKey)
	if err != nil {
		return nil, err
	}
	var lenBuf [2]byte
	binary.BigEndian.PutUint16(lenBuf[:], uint16(len(plain)))
	sealedLen := lenAEAD.Seal(nil, lenNonce, lenBuf[:], authID)

	hdrKey := vmessKDF(userKey[:], "VMess Header AEAD Key", authID, connNonce)[:16]
	hdrNonce := vmessKDF(userKey[:], "VMess Header AEAD Nonce", authID, connNonce)[:12]
	hdrAEAD, err := vmessGCM(hdrKey)
	if err != nil {
		return nil, err
	}
	sealedHeader := hdrAEAD.Seal(nil, hdrNonce, plain, authID)

	var out bytes.Buffer
	out.Write(authID)
	out.Write(sealedLen)
	out.Write(connNonce)
	out.Write(sealedHeader)
	return out.Bytes(), nil
}

// ---- server ----

// VMessServer serves one VMess (AEAD) inbound.
type VMessServer struct {
	UUID string
	// UDPSocketFn creates outbound UDP sockets for UDP sessions;
	// nil uses real UDP sockets.
	UDPSocketFn udpSocketFunc
}

func (s *VMessServer) udpSocket() (net.PacketConn, error) {
	if s.UDPSocketFn != nil {
		return s.UDPSocketFn()
	}
	return defaultUDPSocket()
}

// Handle processes one accepted connection.
func (s *VMessServer) Handle(conn net.Conn) {
	defer conn.Close()
	userKey, err := vmessUserKey(s.UUID)
	if err != nil {
		return
	}
	br := bufio.NewReader(conn)
	authID := make([]byte, 16)
	if _, err := io.ReadFull(br, authID); err != nil {
		return
	}
	if !checkAuthID(userKey, authID) {
		return
	}
	sealedLen := make([]byte, 2+16)
	if _, err := io.ReadFull(br, sealedLen); err != nil {
		return
	}
	connNonce := make([]byte, 8)
	if _, err := io.ReadFull(br, connNonce); err != nil {
		return
	}
	lenKey := vmessKDF(userKey[:], "VMess Header AEAD Key_Length", authID, connNonce)[:16]
	lenNonce := vmessKDF(userKey[:], "VMess Header AEAD Nonce_Length", authID, connNonce)[:12]
	lenAEAD, err := vmessGCM(lenKey)
	if err != nil {
		return
	}
	lenBytes, err := lenAEAD.Open(nil, lenNonce, sealedLen, authID)
	if err != nil {
		return
	}
	headerLen := int(binary.BigEndian.Uint16(lenBytes))
	sealedHeader := make([]byte, headerLen+16)
	if _, err := io.ReadFull(br, sealedHeader); err != nil {
		return
	}
	hdrKey := vmessKDF(userKey[:], "VMess Header AEAD Key", authID, connNonce)[:16]
	hdrNonce := vmessKDF(userKey[:], "VMess Header AEAD Nonce", authID, connNonce)[:12]
	hdrAEAD, err := vmessGCM(hdrKey)
	if err != nil {
		return
	}
	plain, err := hdrAEAD.Open(nil, hdrNonce, sealedHeader, authID)
	if err != nil {
		return
	}
	req, err := parseHeaderPlaintext(plain)
	if err != nil {
		return
	}

	// Response: keys from SHA-256 of the request key/nonce.
	respKeyFull := sha256.Sum256(req.reqKey[:])
	respNonceFull := sha256.Sum256(req.reqNonce[:])
	respKey, respNonce := respKeyFull[:16], respNonceFull[:16]

	// Response header payload: respAuth echo | option | 0 | 0 (4 bytes,
	// no version byte — matches the reference server exactly).
	respPlain := []byte{req.respAuth, req.option, 0, 0}
	rLenKey := vmessKDF(respKey, "AEAD Resp Header Len Key")[:16]
	rLenNonce := vmessKDF(respNonce, "AEAD Resp Header Len IV")[:12]
	rLenAEAD, err := vmessGCM(rLenKey)
	if err != nil {
		return
	}
	var rLenBuf [2]byte
	binary.BigEndian.PutUint16(rLenBuf[:], uint16(len(respPlain)))
	if _, err := conn.Write(rLenAEAD.Seal(nil, rLenNonce, rLenBuf[:], nil)); err != nil {
		return
	}
	rHdrKey := vmessKDF(respKey, "AEAD Resp Header Key")[:16]
	rHdrNonce := vmessKDF(respNonce, "AEAD Resp Header IV")[:12]
	rHdrAEAD, err := vmessGCM(rHdrKey)
	if err != nil {
		return
	}
	if _, err := conn.Write(rHdrAEAD.Seal(nil, rHdrNonce, respPlain, nil)); err != nil {
		return
	}

	if req.cmd == vmessCmdUDP {
		s.serveUDP(conn, br, req, respKey, respNonce)
		return
	}

	upstream, err := DialDirect(req.target)
	if err != nil {
		return
	}
	defer upstream.Close()

	bodyReader, err := makeBodyReader(br, req.option, req.reqKey[:], req.reqNonce[:], req.reqKey[:], req.reqNonce[:])
	if err != nil {
		return
	}
	bodyWriter, err := makeBodyWriter(conn, req.option, respKey, respNonce, req.reqKey[:], req.reqNonce[:])
	if err != nil {
		return
	}
	done := make(chan struct{}, 2)
	go func() {
		_, _ = io.Copy(upstream, bodyReader)
		closeWrite(upstream)
		done <- struct{}{}
	}()
	go func() {
		_, _ = io.Copy(bodyWriter, upstream)
		done <- struct{}{}
	}()
	<-done
}

// serveUDP runs a VMess UDP session (command 0x02): body chunks map
// one-to-one to datagrams toward the header's fixed target.
func (s *VMessServer) serveUDP(conn net.Conn, br *bufio.Reader, req *vmessRequest, respKey, respNonce []byte) {
	ua, err := resolveUDPAddr(req.target)
	if err != nil {
		return
	}
	out, err := s.udpSocket()
	if err != nil {
		return
	}
	defer out.Close()
	packetReader, err := makePacketReader(br, req.option, req.reqKey[:], req.reqNonce[:], req.reqKey[:], req.reqNonce[:])
	if err != nil {
		return
	}
	packetWriter, err := makePacketWriter(conn, req.option, respKey, respNonce, req.reqKey[:], req.reqNonce[:])
	if err != nil {
		return
	}
	go udpReplyPump(out, func(src Addr, payload []byte) {
		_ = packetWriter.WritePacket(payload)
	})
	for {
		payload, err := packetReader.ReadPacket()
		if err != nil {
			return
		}
		_, _ = out.WriteTo(payload, ua)
	}
}

// ---- client ----

type vmessClientConn struct {
	net.Conn
	reader   io.Reader
	writer   io.Writer
	respAuth byte
	reqKey   [16]byte
	reqNonce [16]byte
	parsed   bool
	parseErr error
}

func (c *vmessClientConn) Read(p []byte) (int, error) {
	if !c.parsed {
		c.parsed = true
		c.parseErr = c.readResponseHeader()
		if c.parseErr == nil {
			c.reader, c.parseErr = makeBodyReader(c.Conn, vmessOptChunk|vmessOptMasking, c.respKey(), c.respNonce(), c.reqKey[:], c.reqNonce[:])
		}
	}
	if c.parseErr != nil {
		return 0, c.parseErr
	}
	return c.reader.Read(p)
}

func (c *vmessClientConn) Write(p []byte) (int, error) { return c.writer.Write(p) }

func (c *vmessClientConn) respKey() []byte {
	k := sha256.Sum256(c.reqKey[:])
	return k[:16]
}

func (c *vmessClientConn) respNonce() []byte {
	n := sha256.Sum256(c.reqNonce[:])
	return n[:16]
}

func (c *vmessClientConn) readResponseHeader() error {
	respKey, respNonce := c.respKey(), c.respNonce()
	rLenKey := vmessKDF(respKey, "AEAD Resp Header Len Key")[:16]
	rLenNonce := vmessKDF(respNonce, "AEAD Resp Header Len IV")[:12]
	rLenAEAD, err := vmessGCM(rLenKey)
	if err != nil {
		return err
	}
	sealedLen := make([]byte, 2+16)
	if _, err := io.ReadFull(c.Conn, sealedLen); err != nil {
		return err
	}
	lenBytes, err := rLenAEAD.Open(nil, rLenNonce, sealedLen, nil)
	if err != nil {
		return fmt.Errorf("vmess response length: %w", err)
	}
	headerLen := int(binary.BigEndian.Uint16(lenBytes))
	rHdrKey := vmessKDF(respKey, "AEAD Resp Header Key")[:16]
	rHdrNonce := vmessKDF(respNonce, "AEAD Resp Header IV")[:12]
	rHdrAEAD, err := vmessGCM(rHdrKey)
	if err != nil {
		return err
	}
	sealed := make([]byte, headerLen+16)
	if _, err := io.ReadFull(c.Conn, sealed); err != nil {
		return err
	}
	plain, err := rHdrAEAD.Open(nil, rHdrNonce, sealed, nil)
	if err != nil {
		return fmt.Errorf("vmess response header: %w", err)
	}
	if len(plain) < 4 || plain[0] != c.respAuth {
		return errors.New("vmess: bad response header")
	}
	return nil
}

// DialVMess opens a VMess AEAD tunnel to target through server.
func DialVMess(server, uuid string, target Addr) (net.Conn, error) {
	userKey, err := vmessUserKey(uuid)
	if err != nil {
		return nil, err
	}
	raw, err := net.Dial("tcp", server)
	if err != nil {
		return nil, err
	}
	fail := func(err error) (net.Conn, error) {
		raw.Close()
		return nil, err
	}
	var reqKey, reqNonce [16]byte
	if _, err := rand.Read(reqKey[:]); err != nil {
		return fail(err)
	}
	if _, err := rand.Read(reqNonce[:]); err != nil {
		return fail(err)
	}
	var respAuth [1]byte
	if _, err := rand.Read(respAuth[:]); err != nil {
		return fail(err)
	}
	plain, err := buildHeaderPlaintext(target, vmessCmdTCP, reqKey, reqNonce, respAuth[0])
	if err != nil {
		return fail(err)
	}
	authID := makeAuthID(userKey, time.Now())
	wrapped, err := wrapHeader(userKey, authID, plain)
	if err != nil {
		return fail(err)
	}
	if _, err := raw.Write(wrapped); err != nil {
		return fail(err)
	}
	writer, err := makeBodyWriter(raw, vmessOptChunk|vmessOptMasking, reqKey[:], reqNonce[:], reqKey[:], reqNonce[:])
	if err != nil {
		return fail(err)
	}
	return &vmessClientConn{Conn: raw, writer: writer, respAuth: respAuth[0], reqKey: reqKey, reqNonce: reqNonce}, nil
}

// ---- UDP client ----

// VMessUDPConn is the client side of a VMess UDP session (fixed target).
type VMessUDPConn struct {
	net.Conn
	writer   vmessPacketWriter
	reader   vmessPacketReader
	respAuth byte
	reqKey   [16]byte
	reqNonce [16]byte
	parsed   bool
	parseErr error
}

func (c *VMessUDPConn) respKey() []byte {
	k := sha256.Sum256(c.reqKey[:])
	return k[:16]
}

func (c *VMessUDPConn) respNonce() []byte {
	n := sha256.Sum256(c.reqNonce[:])
	return n[:16]
}

// DialVMessUDP opens a VMess UDP session to target through server.
func DialVMessUDP(server, uuid string, target Addr) (*VMessUDPConn, error) {
	userKey, err := vmessUserKey(uuid)
	if err != nil {
		return nil, err
	}
	raw, err := net.Dial("tcp", server)
	if err != nil {
		return nil, err
	}
	fail := func(err error) (*VMessUDPConn, error) {
		raw.Close()
		return nil, err
	}
	var reqKey, reqNonce [16]byte
	if _, err := rand.Read(reqKey[:]); err != nil {
		return fail(err)
	}
	if _, err := rand.Read(reqNonce[:]); err != nil {
		return fail(err)
	}
	var respAuth [1]byte
	if _, err := rand.Read(respAuth[:]); err != nil {
		return fail(err)
	}
	plain, err := buildHeaderPlaintext(target, vmessCmdUDP, reqKey, reqNonce, respAuth[0])
	if err != nil {
		return fail(err)
	}
	authID := makeAuthID(userKey, time.Now())
	wrapped, err := wrapHeader(userKey, authID, plain)
	if err != nil {
		return fail(err)
	}
	if _, err := raw.Write(wrapped); err != nil {
		return fail(err)
	}
	writer, err := makePacketWriter(raw, vmessOptChunk|vmessOptMasking, reqKey[:], reqNonce[:], reqKey[:], reqNonce[:])
	if err != nil {
		return fail(err)
	}
	return &VMessUDPConn{Conn: raw, writer: writer, respAuth: respAuth[0], reqKey: reqKey, reqNonce: reqNonce}, nil
}

// WritePacket sends one datagram to the session target.
func (c *VMessUDPConn) WritePacket(payload []byte) error {
	return c.writer.WritePacket(payload)
}

// ReadPacket receives the next datagram from the session target.
func (c *VMessUDPConn) ReadPacket() ([]byte, error) {
	if !c.parsed {
		c.parsed = true
		c.parseErr = c.readResponseHeader()
		if c.parseErr == nil {
			c.reader, c.parseErr = makePacketReader(c.Conn, vmessOptChunk|vmessOptMasking, c.respKey(), c.respNonce(), c.reqKey[:], c.reqNonce[:])
		}
	}
	if c.parseErr != nil {
		return nil, c.parseErr
	}
	return c.reader.ReadPacket()
}

// readResponseHeader consumes and validates the AEAD response header.
// (Same wire form as the TCP client's; kept separate because the UDP
// conn type does not embed vmessClientConn.)
func (c *VMessUDPConn) readResponseHeader() error {
	respKey, respNonce := c.respKey(), c.respNonce()
	rLenKey := vmessKDF(respKey, "AEAD Resp Header Len Key")[:16]
	rLenNonce := vmessKDF(respNonce, "AEAD Resp Header Len IV")[:12]
	rLenAEAD, err := vmessGCM(rLenKey)
	if err != nil {
		return err
	}
	sealedLen := make([]byte, 2+16)
	if _, err := io.ReadFull(c.Conn, sealedLen); err != nil {
		return err
	}
	lenBytes, err := rLenAEAD.Open(nil, rLenNonce, sealedLen, nil)
	if err != nil {
		return fmt.Errorf("vmess response length: %w", err)
	}
	headerLen := int(binary.BigEndian.Uint16(lenBytes))
	rHdrKey := vmessKDF(respKey, "AEAD Resp Header Key")[:16]
	rHdrNonce := vmessKDF(respNonce, "AEAD Resp Header IV")[:12]
	rHdrAEAD, err := vmessGCM(rHdrKey)
	if err != nil {
		return err
	}
	sealed := make([]byte, headerLen+16)
	if _, err := io.ReadFull(c.Conn, sealed); err != nil {
		return err
	}
	plain, err := rHdrAEAD.Open(nil, rHdrNonce, sealed, nil)
	if err != nil {
		return fmt.Errorf("vmess response header: %w", err)
	}
	if len(plain) < 4 || plain[0] != c.respAuth {
		return errors.New("vmess: bad response header")
	}
	return nil
}
