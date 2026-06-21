// Package obfs provides a lightweight, dependency-free obfuscation layer for
// Backhaul tunnel connections.
//
// Stock Backhaul sends the security token in cleartext inside a fixed
// [2-byte length][1-byte transport][token] structure, the peer echoes the same
// token back, and the control channel emits fixed single-byte heartbeats. All of
// these are easy static signatures for a DPI box to fingerprint and then block
// the peer IP, even when the underlying protocol itself is not blocked.
//
// ObfConn removes those tells. Every wrapped connection:
//   - is encrypted end-to-end with AES-256-CTR, keyed by SHA-256 of the token,
//     so the token never appears on the wire and the byte stream looks random;
//   - sends a fresh random 16-byte IV per direction, so two connections with the
//     same token never share an opening byte pattern;
//   - prepends a random-length (16..1024 byte) padding preamble, so the size of
//     the first data record varies run to run and connection to connection.
//
// Both peers must enable obfuscation (obfuscation = true) and share the same
// token. The wrapper is fully symmetric: each side encrypts its own writes with
// its own IV and decrypts the peer's reads using the peer's IV.
package obfs

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"io"
	"net"
	"sync"
)

const (
	ivLen     = 16   // AES block size; also the per-direction IV length
	minPad    = 16   // minimum random padding bytes in the preamble
	padSpread = 1009 // padding range spread (prime, keeps sizes irregular)
)

// deriveKey turns an arbitrary token into a fixed 32-byte AES-256 key. The
// domain-separation prefix keeps this key distinct from any other use of the
// token elsewhere in the program.
func deriveKey(token string) []byte {
	sum := sha256.Sum256([]byte("backhaul-obfs-v1\x00" + token))
	return sum[:]
}

// ObfConn wraps a net.Conn and transparently obfuscates everything written to
// and read from it. All net.Conn methods other than Read/Write (deadlines,
// addresses, Close) pass straight through to the embedded connection.
type ObfConn struct {
	net.Conn
	key []byte

	wOnce sync.Once
	wErr  error
	w     cipher.Stream

	rOnce sync.Once
	rErr  error
	r     cipher.Stream
}

// Wrap returns conn wrapped with token-keyed obfuscation. The handshake (IV
// exchange + padding preamble) is performed lazily on the first Read/Write, so
// wrapping never blocks and existing read deadlines still apply normally.
func Wrap(conn net.Conn, token string) net.Conn {
	return &ObfConn{Conn: conn, key: deriveKey(token)}
}

func (c *ObfConn) initWrite() {
	iv := make([]byte, ivLen)
	if _, err := rand.Read(iv); err != nil {
		c.wErr = err
		return
	}
	// IV goes out in the clear; on its own it is indistinguishable from random.
	if _, err := c.Conn.Write(iv); err != nil {
		c.wErr = err
		return
	}

	block, err := aes.NewCipher(c.key)
	if err != nil {
		c.wErr = err
		return
	}
	c.w = cipher.NewCTR(block, iv)

	// Random-length padding preamble: [2-byte padLen][padLen random bytes],
	// encrypted like everything else. The receiver decrypts and discards it.
	seed := make([]byte, 2)
	if _, err := rand.Read(seed); err != nil {
		c.wErr = err
		return
	}
	padN := minPad + int(binary.BigEndian.Uint16(seed)%padSpread)

	pre := make([]byte, 2+padN)
	binary.BigEndian.PutUint16(pre[:2], uint16(padN))
	if _, err := rand.Read(pre[2:]); err != nil {
		c.wErr = err
		return
	}
	c.w.XORKeyStream(pre, pre)
	if _, err := c.Conn.Write(pre); err != nil {
		c.wErr = err
		return
	}
}

func (c *ObfConn) initRead() {
	iv := make([]byte, ivLen)
	if _, err := io.ReadFull(c.Conn, iv); err != nil {
		c.rErr = err
		return
	}

	block, err := aes.NewCipher(c.key)
	if err != nil {
		c.rErr = err
		return
	}
	c.r = cipher.NewCTR(block, iv)

	lenBuf := make([]byte, 2)
	if _, err := io.ReadFull(c.Conn, lenBuf); err != nil {
		c.rErr = err
		return
	}
	c.r.XORKeyStream(lenBuf, lenBuf)
	padN := int(binary.BigEndian.Uint16(lenBuf))
	if padN > 0 {
		pad := make([]byte, padN)
		if _, err := io.ReadFull(c.Conn, pad); err != nil {
			c.rErr = err
			return
		}
		c.r.XORKeyStream(pad, pad) // advance keystream; discard plaintext
	}
}

// Write encrypts p and sends it. Go's net.Conn guarantees a full write or an
// error, so the CTR keystream stays in sync with the bytes actually sent.
func (c *ObfConn) Write(p []byte) (int, error) {
	c.wOnce.Do(c.initWrite)
	if c.wErr != nil {
		return 0, c.wErr
	}
	if len(p) == 0 {
		return 0, nil
	}
	buf := make([]byte, len(p))
	c.w.XORKeyStream(buf, p)
	return c.Conn.Write(buf)
}

// Read decrypts whatever is read from the underlying connection. CTR decryption
// is byte-aligned, so arbitrary read chunking is fine.
func (c *ObfConn) Read(p []byte) (int, error) {
	c.rOnce.Do(c.initRead)
	if c.rErr != nil {
		return 0, c.rErr
	}
	n, err := c.Conn.Read(p)
	if n > 0 {
		c.r.XORKeyStream(p[:n], p[:n])
	}
	return n, err
}
