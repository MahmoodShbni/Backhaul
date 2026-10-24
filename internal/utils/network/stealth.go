package network

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	mrand "math/rand/v2"
	"net"
	"sync"
	"time"
)

// The stealth transport.
//
// Backhaul's other transports announce themselves. A raw TCP stream opens with
// a two-byte cleartext length and a token in the clear; wss carries a TLS
// ClientHello whose fingerprint a censor recognises. This one has no such tell.
// Each connection opens with an X25519 key exchange whose keys are mixed with
// the tunnel token, wrapped in a per-connection obfuscation layer so the opening
// is bytes indistinguishable from random, and the stream that follows is an
// AES-256-GCM record layer that looks the same. There is nothing for deep packet
// inspection to match against.
//
// The key material is derived from the tunnel token, which both ends already
// hold, so the transport needs no key of its own. Because the token is mixed in,
// a peer without it derives different keys: the responder's confirmation does
// not open for a wrong-token initiator, and a wrong-token responder's records do
// not authenticate — the connection is dropped and (for the initiator) nothing
// is sent back, so a probe finds a dead port rather than a service to
// fingerprint.
//
// # Security construction
//
// This is an ephemeral-ephemeral X25519 exchange authenticated by a pre-shared
// key — the same shape as Noise's NNpsk0 pattern, built on the Go standard
// library so the transport carries no third-party cryptography dependency:
//
//   - Each side generates a fresh ephemeral X25519 key per connection and sends
//     the public key (masked, see below). The shared secret is X25519(mine,
//     theirs), which gives forward secrecy: a connection's keys cannot be
//     recovered from the token alone after the ephemerals are gone.
//   - The token is the HKDF salt, so both ends derive the same keys only if both
//     hold the token. The derivation binds the transcript (both ephemeral public
//     keys), so an active attacker who substitutes an ephemeral cannot steer two
//     honest ends onto the same key without the token.
//   - The responder proves it holds the token with an AES-GCM tag over the
//     transcript, which the initiator verifies before the handshake returns — so
//     a wrong token fails fast and visibly rather than hanging. The initiator
//     proves it holds the token implicitly: its first record (the channel's
//     token frame) is AES-GCM under a key a non-token peer cannot derive, so a
//     forged connection's first record fails to authenticate and is dropped.
//
// AES-256-GCM is used for both the record layer and the confirmation because it
// is in the standard library and, with AES-NI (every server CPU this runs on),
// it is very fast — which matters because Backhaul opens a pool of connections
// and grows it under load, so a handshake runs on the hot path of connection
// setup. The cost per connection is one X25519 operation and a few symmetric
// ops; the server runs each connection's handshake in its own goroutine so one
// slow peer never blocks the accept loop or the connections behind it.
//
// # The obfuscation layer
//
// A bare key exchange still leaves tells a statistical censor tests for: a raw
// X25519 public key is a field element with detectable bias, not a uniform
// string; the record length prefix is two cleartext bytes in front of every
// record; and the handshake messages are a fixed size. The obfuscation layer
// removes all three. It is keyed by the token, so it needs no handshake of its
// own:
//
//  1. The initiator opens with a random seed. From HKDF(token, seed) both ends
//     derive four AES-CTR keystreams — a length-mask and a handshake-mask per
//     direction.
//  2. Every two-byte length prefix is XORed with the length keystream, so the
//     only cleartext framing becomes uniform random.
//  3. Each handshake message — the ephemeral key and the confirmation tag — is
//     XORed with the handshake keystream, making it a uniform string, and padded
//     with a random amount of filler so it is not a fixed size.
//
// The record payloads are already uniform AES-GCM ciphertext, so they are left
// untouched: the steady-state cost is two bytes of XOR per record and nothing
// else. The layer is not authenticated and does not need to be — it is
// obfuscation, not security. Everything it wraps is authenticated by GCM; a
// flipped bit in the masked stream corrupts the inner record and its AEAD
// rejects it.
//
// # Distinctness from other stealth tunnels
//
// The domain-separation labels (stealthPSKSalt-less derivation, stealthObfsLabel,
// stealthDataLabel) and the construction's own algebra are unique to Backhaul,
// so a censor that has catalogued other Noise-based stealth tunnels does not see
// this as one of them. Change the labels and the wire fingerprint changes again
// without touching the security argument.

const (
	// Domain-separation labels. They make this tunnel's key material and wire
	// fingerprint distinct from every other stealth tunnel; change them and the
	// fingerprint changes without touching the construction.
	stealthObfsLabel = "backhaul-stealth-obfs-v1:"
	stealthDataLabel = "backhaul-stealth-data-v1:"

	// stealthHandshakeTimeout bounds the handshake so a silent peer cannot hold
	// a half-open connection forever.
	stealthHandshakeTimeout = 15 * time.Second

	// stealthMaxPad is the most filler a record can carry — enough that a
	// record's length says little about its payload, small enough that the
	// average cost is noise.
	stealthMaxPad = 255

	// Frame sizing. A record on the wire is a two-byte length prefix and then
	// the GCM ciphertext (plaintext + 16-byte tag). The plaintext is a one-byte
	// pad length, the payload and up to stealthMaxPad bytes of filler.
	stealthLenPrefix        = 2
	stealthMaxFrame         = 65535
	stealthGCMOverhead      = 16
	stealthPaddedMaxPayload = stealthMaxFrame - stealthGCMOverhead - 1 - stealthMaxPad

	// stealthSeedLen is the random seed the initiator opens with; it keys the
	// per-connection keystreams, is drawn fresh every connection and sent in the
	// clear (revealing it tells a watcher without the token nothing).
	stealthSeedLen = 16

	// stealthKeyLen is the AES-256 key size used throughout.
	stealthKeyLen = 32

	// X25519 public keys are 32 bytes; the responder's confirmation tag is the
	// 16-byte GCM tag over an empty message.
	stealthPubLen     = 32
	stealthConfirmLen = 16

	// stealthMinHandshakePad and stealthHandshakePadRange bound the filler added
	// to each handshake message so it is not a fixed size.
	stealthMinHandshakePad   = 24
	stealthHandshakePadRange = 320
)

// hkdfExtract is the extract step of HKDF-SHA256: PRK = HMAC(salt, ikm).
func hkdfExtract(salt, ikm []byte) []byte {
	m := hmac.New(sha256.New, salt)
	m.Write(ikm)
	return m.Sum(nil)
}

// hkdfExpand is the expand step of HKDF-SHA256, returning n bytes of output
// keying material for the given info.
func hkdfExpand(prk, info []byte, n int) []byte {
	out := make([]byte, 0, n)
	var t []byte
	for i := byte(1); len(out) < n; i++ {
		m := hmac.New(sha256.New, prk)
		m.Write(t)
		m.Write(info)
		m.Write([]byte{i})
		t = m.Sum(nil)
		out = append(out, t...)
	}
	return out[:n]
}

// obfsStreams are the four keystreams the obfuscation layer uses, already
// assigned to this end's send and receive directions.
type obfsStreams struct {
	sendLen, recvLen cipher.Stream // mask the two-byte length prefixes
	sendHS, recvHS   cipher.Stream // mask the handshake message bodies
}

// obfsCipher derives one AES-CTR keystream from the token and the per-connection
// seed. A distinct label per stream keeps the four independent and the set
// domain-separated. A zero IV is safe: the key is unique to this connection (the
// seed is random) and to this stream (the label), so no keystream is reused.
func obfsCipher(token string, seed []byte, label string) (cipher.Stream, error) {
	prk := hkdfExtract([]byte(token), seed)
	key := hkdfExpand(prk, []byte(stealthObfsLabel+label), stealthKeyLen)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewCTR(block, make([]byte, aes.BlockSize)), nil
}

// newObfs derives the four keystreams and hands each end the two it sends with
// and the two it receives with. "c2s" is initiator→responder, "s2c" the reverse.
func newObfs(token string, seed []byte, initiator bool) (*obfsStreams, error) {
	c2sLen, err := obfsCipher(token, seed, "c2s-len")
	if err != nil {
		return nil, err
	}
	c2sHS, err := obfsCipher(token, seed, "c2s-hs")
	if err != nil {
		return nil, err
	}
	s2cLen, err := obfsCipher(token, seed, "s2c-len")
	if err != nil {
		return nil, err
	}
	s2cHS, err := obfsCipher(token, seed, "s2c-hs")
	if err != nil {
		return nil, err
	}
	if initiator {
		return &obfsStreams{sendLen: c2sLen, sendHS: c2sHS, recvLen: s2cLen, recvHS: s2cHS}, nil
	}
	return &obfsStreams{sendLen: s2cLen, sendHS: s2cHS, recvLen: c2sLen, recvHS: c2sHS}, nil
}

// sessionKeys derives the two directional AES-256-GCM keys from the shared
// secret, the token and the transcript. The token is the HKDF salt, so a peer
// without it derives different keys; the transcript (both ephemeral public keys)
// is bound in so the two ends agree only on a handshake they both saw.
func sessionKeys(token string, shared, ephI, ephR []byte) (c2s, s2c cipher.AEAD, err error) {
	prk := hkdfExtract([]byte(token), shared)
	transcript := make([]byte, 0, len(stealthDataLabel)+2*stealthPubLen)
	transcript = append(transcript, []byte(stealthDataLabel)...)
	transcript = append(transcript, ephI...)
	transcript = append(transcript, ephR...)

	kC2S := hkdfExpand(prk, append([]byte("c2s:"), transcript...), stealthKeyLen)
	kS2C := hkdfExpand(prk, append([]byte("s2c:"), transcript...), stealthKeyLen)

	c2s, err = newGCM(kC2S)
	if err != nil {
		return nil, nil, err
	}
	s2c, err = newGCM(kS2C)
	if err != nil {
		return nil, nil, err
	}
	return c2s, s2c, nil
}

func newGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// gcmNonce builds the 12-byte nonce for a record counter: the counter as a
// big-endian value in the low 8 bytes, the rest zero. Each direction has its own
// key and a strictly increasing counter, so no (key, nonce) pair ever repeats.
func gcmNonce(counter uint64) [12]byte {
	var n [12]byte
	binary.BigEndian.PutUint64(n[4:], counter)
	return n
}

// transcriptAAD is the additional data the responder's confirmation is computed
// over: the two ephemeral public keys, binding the confirmation to this exact
// handshake.
func transcriptAAD(ephI, ephR []byte) []byte {
	aad := make([]byte, 0, 2*stealthPubLen)
	aad = append(aad, ephI...)
	aad = append(aad, ephR...)
	return aad
}

// StealthClientConn performs the initiator side of the handshake over raw and,
// on success, returns a net.Conn that transparently encrypts everything written
// to it and decrypts everything read from it.
func StealthClientConn(raw net.Conn, token string, timeout time.Duration) (net.Conn, error) {
	return stealthHandshake(raw, token, true, timeout)
}

// StealthServerConn is the responder side of StealthClientConn.
func StealthServerConn(raw net.Conn, token string, timeout time.Duration) (net.Conn, error) {
	return stealthHandshake(raw, token, false, timeout)
}

func stealthHandshake(raw net.Conn, token string, initiator bool, timeout time.Duration) (net.Conn, error) {
	if timeout <= 0 {
		timeout = stealthHandshakeTimeout
	}
	// A deadline for the whole handshake; cleared once it completes so the
	// connection's normal deadlines apply from then on.
	_ = raw.SetDeadline(time.Now().Add(timeout))

	curve := ecdh.X25519()
	priv, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("stealth: generating ephemeral key: %w", err)
	}
	myPub := priv.PublicKey().Bytes()

	// The obfuscation layer. The seed goes first on the wire — the initiator
	// draws it, the responder reads it — and keys the keystreams that mask
	// everything after.
	ob, err := exchangeObfsSeed(raw, token, initiator)
	if err != nil {
		return nil, err
	}

	var c2s, s2c cipher.AEAD
	var ephI, ephR []byte

	if initiator {
		ephI = myPub
		// -> ephI
		if err := writeObfsHandshake(raw, handshakeBody(ephI), ob.sendLen, ob.sendHS); err != nil {
			return nil, err
		}
		// <- ephR || confirm
		in, err := readObfsHandshake(raw, ob.recvLen, ob.recvHS)
		if err != nil {
			return nil, err
		}
		if len(in) < stealthPubLen+stealthConfirmLen {
			return nil, fmt.Errorf("stealth: responder message too short")
		}
		ephR = in[:stealthPubLen]
		confirm := in[stealthPubLen : stealthPubLen+stealthConfirmLen]

		peerPub, err := curve.NewPublicKey(ephR)
		if err != nil {
			return nil, fmt.Errorf("stealth: bad responder key: %w", err)
		}
		shared, err := priv.ECDH(peerPub)
		if err != nil {
			return nil, fmt.Errorf("stealth: key agreement: %w", err)
		}
		c2s, s2c, err = sessionKeys(token, shared, ephI, ephR)
		if err != nil {
			return nil, err
		}
		// Verify the responder holds the token. The confirmation is a GCM tag
		// over the transcript under s2c with nonce 0; a wrong token yields a
		// different s2c and the open fails.
		nonce := gcmNonce(0)
		if _, err := s2c.Open(nil, nonce[:], confirm, transcriptAAD(ephI, ephR)); err != nil {
			return nil, fmt.Errorf("stealth: handshake rejected (wrong token or not a stealth peer): %w", err)
		}
	} else {
		// <- ephI
		in, err := readObfsHandshake(raw, ob.recvLen, ob.recvHS)
		if err != nil {
			return nil, err
		}
		if len(in) < stealthPubLen {
			return nil, fmt.Errorf("stealth: initiator message too short")
		}
		ephI = in[:stealthPubLen]
		ephR = myPub

		peerPub, err := curve.NewPublicKey(ephI)
		if err != nil {
			return nil, fmt.Errorf("stealth: bad initiator key: %w", err)
		}
		shared, err := priv.ECDH(peerPub)
		if err != nil {
			return nil, fmt.Errorf("stealth: key agreement: %w", err)
		}
		c2s, s2c, err = sessionKeys(token, shared, ephI, ephR)
		if err != nil {
			return nil, err
		}
		// -> ephR || confirm. The confirmation proves to the initiator that this
		// end holds the token.
		nonce := gcmNonce(0)
		confirm := s2c.Seal(nil, nonce[:], nil, transcriptAAD(ephI, ephR))
		body := append(append([]byte{}, ephR...), confirm...)
		if err := writeObfsHandshake(raw, handshakeBody(body), ob.sendLen, ob.sendHS); err != nil {
			return nil, err
		}
	}

	_ = raw.SetDeadline(time.Time{})

	// Assign directions. The confirmation consumed s2c nonce 0, so the s2c
	// record stream starts at counter 1 on both ends; c2s starts at 0.
	conn := &stealthConn{Conn: raw}
	if initiator {
		conn.send, conn.sendNonce = c2s, 0
		conn.recv, conn.recvNonce = s2c, 1
		conn.sendLenMask, conn.recvLenMask = ob.sendLen, ob.recvLen
	} else {
		conn.send, conn.sendNonce = s2c, 1
		conn.recv, conn.recvNonce = c2s, 0
		conn.sendLenMask, conn.recvLenMask = ob.sendLen, ob.recvLen
	}
	return conn, nil
}

// exchangeObfsSeed sends (initiator) or reads (responder) the seed and derives
// the keystreams from it.
func exchangeObfsSeed(raw net.Conn, token string, initiator bool) (*obfsStreams, error) {
	seed := make([]byte, stealthSeedLen)
	if initiator {
		if _, err := rand.Read(seed); err != nil {
			return nil, fmt.Errorf("stealth: drawing the obfuscation seed: %w", err)
		}
		if _, err := raw.Write(seed); err != nil {
			return nil, fmt.Errorf("stealth: sending the obfuscation seed: %w", err)
		}
	} else {
		if _, err := io.ReadFull(raw, seed); err != nil {
			return nil, fmt.Errorf("stealth: reading the obfuscation seed: %w", err)
		}
	}
	return newObfs(token, seed, initiator)
}

// handshakeBody appends a random amount of filler to a handshake message so it
// is not a fixed size. The filler rides inside the masked message; the peer
// takes the fixed-length fields from the front and discards the rest.
func handshakeBody(fields []byte) []byte {
	pad := stealthMinHandshakePad + mrand.IntN(stealthHandshakePadRange)
	out := make([]byte, len(fields)+pad)
	copy(out, fields)
	return out
}

// stealthConn is an encrypted net.Conn: an AES-256-GCM record layer over a
// completed handshake. Plaintext written to it is split into records, each
// padded, encrypted and length-prefixed; ciphertext read from it is decrypted
// and buffered.
type stealthConn struct {
	net.Conn

	// sendLenMask and recvLenMask mask the two-byte length prefix of every
	// record, continuing the keystreams the handshake started. The record
	// payloads are never masked: they are already uniform ciphertext.
	sendLenMask, recvLenMask cipher.Stream

	writeMu   sync.Mutex
	send      cipher.AEAD
	sendNonce uint64
	padBuf    []byte // reused plaintext buffer: length byte, payload, filler
	frameBuf  []byte // record as it goes on the wire, built in place and reused

	readMu    sync.Mutex
	recv      cipher.AEAD
	recvNonce uint64
	readBuf   []byte // decrypted plaintext not yet handed to the caller
	inBuf     []byte // record as it comes off the wire, decrypted in place
}

// Write encrypts p and sends it as one or more records. It honours net.Conn
// semantics: on success every byte of p has been written.
func (c *stealthConn) Write(p []byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()

	total := 0
	for len(p) > 0 {
		chunk := p
		if len(chunk) > stealthPaddedMaxPayload {
			chunk = chunk[:stealthPaddedMaxPayload]
		}
		// Two bytes reserved for the length, then the ciphertext sealed in after
		// them, so the record is built once and written once.
		if cap(c.frameBuf) < stealthLenPrefix {
			c.frameBuf = make([]byte, stealthLenPrefix, 4096)
		}
		c.frameBuf = c.frameBuf[:stealthLenPrefix]
		nonce := gcmNonce(c.sendNonce)
		frame := c.send.Seal(c.frameBuf, nonce[:], c.plaintext(chunk), nil)
		c.sendNonce++
		c.frameBuf = frame
		if len(frame)-stealthLenPrefix > stealthMaxFrame {
			return total, fmt.Errorf("stealth: message too large (%d bytes)", len(frame)-stealthLenPrefix)
		}
		binary.BigEndian.PutUint16(frame[:stealthLenPrefix], uint16(len(frame)-stealthLenPrefix))
		// Mask the length prefix; the two bytes continue the same stream the
		// handshake's prefixes used, so the other end stays in step.
		c.sendLenMask.XORKeyStream(frame[:stealthLenPrefix], frame[:stealthLenPrefix])
		if _, err := c.Conn.Write(frame); err != nil {
			return total, err
		}
		total += len(chunk)
		p = p[len(chunk):]
	}
	return total, nil
}

// plaintext wraps the chunk in a length byte and a random amount of filler. The
// caller holds writeMu, which is also what makes reusing the buffer safe.
func (c *stealthConn) plaintext(chunk []byte) []byte {
	padLen := mrand.IntN(stealthMaxPad + 1)
	need := 1 + len(chunk) + padLen
	if cap(c.padBuf) < need {
		c.padBuf = make([]byte, need)
	}
	c.padBuf = c.padBuf[:need]

	c.padBuf[0] = byte(padLen)
	copy(c.padBuf[1:], chunk)
	// The filler is reused across records, so it must be zeroed rather than left
	// as whatever the buffer held.
	clear(c.padBuf[1+len(chunk):])

	return c.padBuf
}

// unpad strips what plaintext added. It is strict about the lengths because a
// record that does not describe itself is either a bug or a peer that should not
// be trusted to keep going.
func (c *stealthConn) unpad(plain []byte) ([]byte, error) {
	if len(plain) < 1 {
		return nil, fmt.Errorf("stealth: padded record is empty")
	}
	padLen := int(plain[0])
	if 1+padLen > len(plain) {
		return nil, fmt.Errorf("stealth: padded record claims %d bytes of padding in %d bytes", padLen, len(plain))
	}
	return plain[1 : len(plain)-padLen], nil
}

// Read returns decrypted plaintext, reading and decrypting another record only
// when its buffer is empty.
func (c *stealthConn) Read(p []byte) (int, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()

	// A loop rather than a single attempt: a padded record can legitimately
	// carry no payload at all, and returning (0, nil) from Read is the kind of
	// answer callers are entitled not to expect.
	for len(c.readBuf) == 0 {
		frame, err := readFrameInto(c.Conn, c.inBuf, c.recvLenMask)
		if err != nil {
			return 0, err
		}
		c.inBuf = frame
		nonce := gcmNonce(c.recvNonce)
		plain, err := c.recv.Open(frame[:0], nonce[:], frame, nil)
		if err != nil {
			return 0, fmt.Errorf("stealth: record failed authentication: %w", err)
		}
		c.recvNonce++
		if plain, err = c.unpad(plain); err != nil {
			return 0, err
		}
		c.readBuf = plain
	}

	n := copy(p, c.readBuf)
	c.readBuf = c.readBuf[n:]
	return n, nil
}

// writeObfsHandshake writes one handshake message with the length prefix masked
// by the length keystream and the body masked by the handshake keystream, so
// nothing on the wire is distinguishable from random.
func writeObfsHandshake(w io.Writer, msg []byte, lenMask, bodyMask cipher.Stream) error {
	if len(msg) > stealthMaxFrame {
		return fmt.Errorf("stealth: message too large (%d bytes)", len(msg))
	}
	buf := make([]byte, stealthLenPrefix+len(msg))
	binary.BigEndian.PutUint16(buf[:stealthLenPrefix], uint16(len(msg)))
	lenMask.XORKeyStream(buf[:stealthLenPrefix], buf[:stealthLenPrefix])
	copy(buf[stealthLenPrefix:], msg)
	bodyMask.XORKeyStream(buf[stealthLenPrefix:], buf[stealthLenPrefix:])
	_, err := w.Write(buf)
	return err
}

// readObfsHandshake reads one masked handshake message: demask the length, read
// that many bytes, demask the body.
func readObfsHandshake(r io.Reader, lenMask, bodyMask cipher.Stream) ([]byte, error) {
	var hdr [stealthLenPrefix]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	lenMask.XORKeyStream(hdr[:], hdr[:])
	n := int(binary.BigEndian.Uint16(hdr[:]))
	if n == 0 || n > stealthMaxFrame {
		return nil, fmt.Errorf("stealth: bad frame length")
	}
	body := make([]byte, n)
	if _, err := io.ReadFull(r, body); err != nil {
		return nil, err
	}
	bodyMask.XORKeyStream(body, body)
	return body, nil
}

// readFrameInto reads one length-prefixed record into buf, growing it only when
// the record does not fit, and returns it. lenMask demasks the two-byte length
// prefix with the receive keystream so a record's prefix is read back exactly as
// the sender masked it.
func readFrameInto(r io.Reader, buf []byte, lenMask cipher.Stream) ([]byte, error) {
	if cap(buf) < stealthLenPrefix {
		buf = make([]byte, stealthLenPrefix, 4096)
	}
	hdr := buf[:stealthLenPrefix]
	if _, err := io.ReadFull(r, hdr); err != nil {
		return nil, err
	}
	lenMask.XORKeyStream(hdr, hdr)
	n := int(binary.BigEndian.Uint16(hdr))
	if n < stealthGCMOverhead || n > stealthMaxFrame {
		return nil, fmt.Errorf("stealth: bad record length %d", n)
	}
	if cap(buf) < n {
		buf = make([]byte, n)
	}
	buf = buf[:n]
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, err
	}
	return buf, nil
}
