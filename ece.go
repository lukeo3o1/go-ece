package ece

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"slices"
	"unicode/utf8"

	"github.com/lukeo3o1/go-ece/hkdf"
)

// Coding represents the interface for encryption coding methods (e.g. aes128gcm, aes256gcm).
type Coding interface {
	method() string
	String() string
}

type codingMethod string

func (c codingMethod) method() string { return string(c) }
func (c codingMethod) String() string { return string(c) }

// Supported encryption coding methods
var (
	aes128gcm = codingMethod("aes128gcm")
	aes256gcm = codingMethod("aes256gcm")
)

// AES-256-GCM coding
func AES256GCM() Coding {
	return aes256gcm
}

const maxKeyIDLen = 255        // Maximum allowed KeyID length
const DefaultRecordSize = 4096 // Default ECE record size

// Validates record size (RFC requires >= 18 bytes to allow encryption overhead).
func checkRecordSize(rs uint32) error {
	if rs <= 18 {
		return fmt.Errorf("ece: invalid record size %d (must be >= 18)", rs)
	}
	return nil
}

// HeaderTable defines the metadata for an ECE encrypted stream.
type HeaderTable struct {
	Salt       [16]byte // Random salt for HKDF derivation
	RecordSize uint32   // Size of encrypted records
	idLen      uint8    // Length of KeyID
	KeyID      []byte   // Optional identifier for keys
}

func (ht HeaderTable) IDLen() uint8 { return ht.idLen }

// Serializes HeaderTable into binary format and writes it to a writer.
func (ht HeaderTable) WriteTo(w io.Writer) (int64, error) {
	var b bytes.Buffer

	// Write salt (16 bytes)
	b.Write(ht.Salt[:])

	// Write record size (4 bytes big-endian)
	rs := make([]byte, 4)
	binary.BigEndian.PutUint32(rs, ht.RecordSize)
	b.Write(rs)

	// Write KeyID length
	idLen := len(ht.KeyID)
	if idLen > maxKeyIDLen {
		return 0, fmt.Errorf("ece: keyid too long %d bytes, max %d", idLen, maxKeyIDLen)
	}
	b.WriteByte(byte(idLen))

	// Write KeyID (if present)
	if idLen > 0 {
		b.Write(ht.KeyID)
	}

	// Output to destination writer
	n, err := w.Write(b.Bytes())
	return int64(n), err
}

// Reads HeaderTable from binary format (parses salt, record size, key id).
func (ht *HeaderTable) ReadFrom(r io.Reader) (int64, error) {
	b := make([]byte, 21) // 16 salt + 4 record size + 1 idLen
	if _, err := io.ReadFull(r, b); err != nil {
		return 0, err
	}
	copy(ht.Salt[:], b[0:16])
	ht.RecordSize = binary.BigEndian.Uint32(b[16:20])
	ht.idLen = b[20]

	// Validate record size
	if err := checkRecordSize(ht.RecordSize); err != nil {
		return 0, err
	}

	total := int64(len(b))

	// If no KeyID, done
	if ht.idLen == 0 {
		return total, nil
	}

	// Read KeyID
	keyid := make([]byte, ht.idLen)
	n, err := io.ReadFull(r, keyid)
	if err != nil {
		return 0, err
	}
	if n != int(ht.idLen) {
		return 0, fmt.Errorf("ece: failed to read key id: read %d bytes, expected %d bytes", n, ht.idLen)
	}
	ht.KeyID = keyid
	total += int64(n)
	return total, nil
}

// Converts an ECDH curve object into a string identifier.
func curveString(curve ecdh.Curve) string {
	switch curve {
	case ecdh.P256():
		return "P-256"
	case ecdh.P384():
		return "P-384"
	case ecdh.P521():
		return "P-521"
	case ecdh.X25519():
		return "Curve25519"
	default:
		return "Unknown"
	}
}

// Helper: construct an HKDF "info" parameter for key derivation.
func makeInfo(label string, a ...byte) []byte {
	var b bytes.Buffer
	b.WriteString("Content-Encoding: ")
	b.WriteString(label)
	b.Write(a)
	return b.Bytes()
}

// Derives CEK (Content Encryption Key) and Nonce from ECDH exchange using HKDF.
func deriveCEKNonce(priv *ecdh.PrivateKey, sender, receiver *ecdh.PublicKey, coding Coding, salt []byte) (cek []byte, nonce []byte, err error) {
	if sender.Curve() != receiver.Curve() {
		return nil, nil, fmt.Errorf("ece: key curves do not match: %q vs %q", curveString(sender.Curve()), curveString(receiver.Curve()))
	}

	pub := sender
	// Ensure we don't derive with own public key
	if priv.PublicKey().Equal(pub) {
		pub = receiver
	}

	// Perform ECDH to get shared secret
	var secret []byte
	if secret, err = priv.ECDH(pub); err != nil {
		return
	}

	// Allocate CEK size based on algorithm
	switch coding {
	case aes128gcm:
		cek = make([]byte, 16)
	case aes256gcm:
		cek = make([]byte, 32)
	default:
		err = fmt.Errorf("ece: unkonwn coding %q", coding)
		return
	}

	// Derive CEK with HKDF
	cekInfo := makeInfo(coding.String(), 0)
	cekHKDF := hkdf.New(sha256.New, secret, salt, cekInfo)
	if _, err = io.ReadFull(cekHKDF, cek); err != nil {
		return
	}

	// Derive base nonce (12 bytes) with HKDF
	nonce = make([]byte, 12)
	nonceInfo := makeInfo("nonce", 0)
	nonceHKDF := hkdf.New(sha256.New, secret, salt, nonceInfo)
	if _, err = io.ReadFull(nonceHKDF, nonce); err != nil {
		return
	}

	return
}

// Generates per-record nonce by XORing baseNonce with sequence counter.
func nextNonce(baseNonce []byte, seq uint64) []byte {
	nonce := slices.Clone(baseNonce)

	// Build 12-byte counter (big-endian, high 4 bytes zero)
	var seqBytes [12]byte
	binary.BigEndian.PutUint64(seqBytes[4:], seq)

	// XOR counter with base nonce
	for i := 0; i < 12; i++ {
		nonce[i] ^= seqBytes[i]
	}
	return nonce
}

var emptySalt [16]byte

// Writer handles writing ECE-encrypted records to a stream.
type Writer struct {
	ht        HeaderTable
	sender    *ecdh.PrivateKey
	receiver  *ecdh.PublicKey
	coding    Coding
	dst       io.Writer
	baseNonce []byte
	aead      cipher.AEAD
	seq       uint64
	err       error
	closed    bool
	buf       bytes.Buffer
}

// NewWriter initializes a Writer with default settings.
func NewWriter(sender *ecdh.PrivateKey, receiver *ecdh.PublicKey, dst io.Writer) *Writer {
	return &Writer{
		sender:   sender,
		receiver: receiver,
		coding:   aes128gcm,
		dst:      dst,
		ht: HeaderTable{
			RecordSize: DefaultRecordSize,
		},
	}
}

func (e *Writer) Coding() Coding { return e.coding }

// Configure record size (validated).
func (e *Writer) SetRecordSize(rs uint32) error {
	if err := checkRecordSize(rs); err != nil {
		return err
	}
	e.ht.RecordSize = rs
	return nil
}

// Configure encryption coding (defaults to AES-128-GCM if nil).
func (e *Writer) SetCoding(c Coding) {
	if c == nil {
		c = aes128gcm
	}
	e.coding = c
}

// Set KeyID (must be UTF-8 valid).
func (e *Writer) SetKeyID(keyid []byte) error {
	if !utf8.Valid(keyid) {
		return fmt.Errorf("keyid parameter should be a utf-8-encoded")
	}
	e.ht.KeyID = keyid
	return nil
}

// Initializes AEAD cipher and derives CEK + Nonce.
func (e *Writer) newAEAD() (err error) {
	var cek []byte
	if cek, e.baseNonce, err = deriveCEKNonce(e.sender, e.sender.PublicKey(), e.receiver, e.coding, e.ht.Salt[:]); err != nil {
		return
	}
	var block cipher.Block
	if block, err = aes.NewCipher(cek); err != nil {
		return
	}
	if e.aead, err = cipher.NewGCM(block); err != nil {
		return
	}
	e.seq = 0
	return
}

// Encrypts and writes a single record (prepends header if first record).
func (e *Writer) encode(plain []byte) (err error) {
	if e.seq == 0 {
		if _, err = e.ht.WriteTo(e.dst); err != nil {
			return
		}
	}

	nonce := nextNonce(e.baseNonce, e.seq)

	// Encrypt with AEAD
	ciphertext := e.aead.Seal(nil, nonce, plain, nil)

	if _, err = e.dst.Write(ciphertext); err != nil {
		return
	}

	e.seq++
	return
}

// Encryption overhead: delimiter + GCM tag
func (e *Writer) overhead() int {
	return 1 + e.aead.Overhead()
}

// Effective block size for plaintext (record size - overhead).
func (e *Writer) blockSize() int {
	return int(e.ht.RecordSize) - e.overhead()
}

var ErrClosed = errors.New("ece: already closed")

// Write buffers plaintext, splitting into encrypted records when enough data is available.
func (e *Writer) Write(p []byte) (n int, err error) {
	if e.err != nil {
		return 0, e.err
	}
	if e.closed {
		return 0, ErrClosed
	}

	// Lazy AEAD init on first write
	if e.aead == nil {
		if e.ht.Salt == emptySalt {
			if _, err = rand.Read(e.ht.Salt[:]); err != nil {
				return
			}
		}
		if err = e.newAEAD(); err != nil {
			return
		}
	}

	// Buffer input
	if n, err = e.buf.Write(p); err != nil {
		return
	}

	var block []byte
	blockLen := e.blockSize()

	// Encode full intermediate blocks
	for e.buf.Len() >= blockLen*2 {
		if block == nil {
			block = make([]byte, blockLen)
		}
		copy(block, e.buf.Next(blockLen))

		block[blockLen-1] = 1 // Intermediate delimiter = 1

		if err = e.encode(block); err != nil {
			e.err = err
			return
		}
	}

	return
}

// Close finalizes the stream by flushing remaining data and writing final record.
func (e *Writer) Close() error {
	if e.err != nil {
		return e.err
	}
	if e.closed {
		return ErrClosed
	}
	e.closed = true

	var block []byte
	blockLen := e.blockSize()
	isFinal := false

	// Drain buffer until all records written
	for !isFinal {
		if block == nil {
			block = make([]byte, blockLen)
		}

		n, err := io.ReadFull(&e.buf, block[:blockLen-1])
		switch err {
		case io.EOF:
			return nil
		case io.ErrUnexpectedEOF:
			block = block[:n+1]
			isFinal = true
		default:
			return err
		}

		last := len(block) - 1
		if !isFinal {
			block[last] = 1
		} else {
			block[last] = 2 // Final delimiter = 2
		}

		if err := e.encode(block); err != nil {
			e.err = err
			return err
		}
	}

	return nil
}

// Reader handles reading and decrypting ECE-encrypted records.
type Reader struct {
	ht        HeaderTable
	receiver  *ecdh.PrivateKey
	sender    *ecdh.PublicKey
	coding    Coding
	src       io.Reader
	baseNonce []byte
	aead      cipher.AEAD
	seq       uint64
	err       error
	buf       bytes.Buffer // plaintext buffer
}

// NewReader initializes a Reader.
func NewReader(receiver *ecdh.PrivateKey, sender *ecdh.PublicKey, src io.Reader) *Reader {
	return &Reader{
		receiver: receiver,
		sender:   sender,
		coding:   aes128gcm,
		src:      src,
	}
}

func (d *Reader) recordSize() int { return int(d.ht.RecordSize) }

// Configure encryption coding (defaults to AES-128-GCM if nil).
func (d *Reader) SetCoding(c Coding) {
	if c == nil {
		c = aes128gcm
	}
	d.coding = c
}

var errEmptyPlaintext = errors.New("ece: empty plaintext")

// Read decrypts ciphertext records and returns plaintext to caller.
func (d *Reader) Read(p []byte) (int, error) {
	if d.err != nil && d.err != io.EOF {
		return 0, d.err
	}

	// Initialize AEAD and base nonce on first use
	if d.aead == nil {
		if _, err := d.ht.ReadFrom(d.src); err != nil {
			return 0, err
		}
		cek, nonce, err := deriveCEKNonce(d.receiver, d.sender, d.receiver.PublicKey(), d.coding, d.ht.Salt[:])
		if err != nil {
			return 0, err
		}
		d.baseNonce = nonce
		var block cipher.Block
		if block, err = aes.NewCipher(cek); err != nil {
			return 0, err
		}
		if d.aead, err = cipher.NewGCM(block); err != nil {
			return 0, err
		}
	}

	// Return buffered plaintext if already available
	if d.buf.Len() >= len(p) && len(p) > 0 {
		return d.buf.Read(p)
	}

	ctRecordSize := d.recordSize() - 1 // ciphertext block size

	// Keep decrypting records until enough plaintext is buffered
	for d.buf.Len() < len(p) && d.err != io.EOF {
		tmp := make([]byte, ctRecordSize)
		n, err := io.ReadFull(d.src, tmp)
		var ct []byte
		isFinal := false

		if err == io.EOF {
			d.err = io.EOF
			break
		} else if err == io.ErrUnexpectedEOF {
			ct = tmp[:n]
			isFinal = true
			d.err = io.EOF
		} else if err != nil {
			return 0, err
		} else {
			ct = tmp
		}

		// Decrypt record
		nonce := nextNonce(d.baseNonce, d.seq)
		plain, err := d.aead.Open(nil, nonce, ct, nil)
		if err != nil {
			return 0, err
		}
		if len(plain) == 0 {
			return 0, errEmptyPlaintext
		}

		// Verify delimiter correctness
		delimiter := plain[len(plain)-1]
		if isFinal {
			if delimiter != 2 {
				return 0, fmt.Errorf("ece: invalid final delimiter %d", delimiter)
			}
		} else {
			if delimiter != 1 {
				return 0, fmt.Errorf("ece: invalid intermediate delimiter %d", delimiter)
			}
		}

		// Remove delimiter and strip trailing zero padding
		plain = plain[:len(plain)-1]
		for len(plain) > 0 && plain[len(plain)-1] == 0 {
			plain = plain[:len(plain)-1]
		}

		d.buf.Write(plain)
		d.seq++

		// Stop if buffer is sufficient
		if d.buf.Len() >= len(p) && len(p) > 0 {
			break
		}
	}

	if d.buf.Len() == 0 {
		if d.err == io.EOF {
			return 0, io.EOF
		}
		return 0, nil
	}
	return d.buf.Read(p)
}
