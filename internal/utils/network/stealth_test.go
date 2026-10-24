package network

import (
	"bytes"
	"crypto/sha256"
	"io"
	"net"
	"testing"
	"time"
)

// stealthPipe brings up both ends of a stealth connection over a real socket
// pair and returns them. A real socket, not net.Pipe: net.Pipe is unbuffered
// and the seed write at the start of the handshake would block.
func stealthPipe(t *testing.T, clientTok, serverTok string) (client, server net.Conn) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	type res struct {
		c   net.Conn
		err error
	}
	got := make(chan res, 1)
	go func() {
		raw, err := ln.Accept()
		if err != nil {
			got <- res{nil, err}
			return
		}
		c, err := StealthServerConn(raw, serverTok, 3*time.Second)
		got <- res{c, err}
	}()

	raw, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	client, err = StealthClientConn(raw, clientTok, 3*time.Second)
	if clientTok == serverTok && err != nil {
		t.Fatalf("client handshake: %v", err)
	}
	r := <-got
	if clientTok == serverTok && r.err != nil {
		t.Fatalf("server handshake: %v", r.err)
	}
	if client != nil {
		t.Cleanup(func() { client.Close() })
	}
	if r.c != nil {
		t.Cleanup(func() { r.c.Close() })
	}
	return client, r.c
}

// The stealth channel carries bytes, unchanged, in both directions and at sizes
// that exercise padding and the 64 KiB record split.
func TestStealthRoundTrips(t *testing.T) {
	const token = "stealth-round-trip-token-0123456789"
	client, server := stealthPipe(t, token, token)

	for _, n := range []int{1, 100, 1400, 70000} {
		msg := bytes.Repeat([]byte{byte(n)}, n)
		done := make(chan error, 1)
		go func() {
			_, err := client.Write(msg)
			done <- err
		}()
		got := make([]byte, 0, n)
		buf := make([]byte, 32<<10)
		for len(got) < n {
			server.SetReadDeadline(time.Now().Add(3 * time.Second))
			r, err := server.Read(buf)
			if err != nil {
				t.Fatalf("n=%d read: %v", n, err)
			}
			got = append(got, buf[:r]...)
		}
		if err := <-done; err != nil {
			t.Fatalf("n=%d write: %v", n, err)
		}
		if !bytes.Equal(got, msg) {
			t.Fatalf("n=%d round-trip corrupted", n)
		}
	}

	// And the other direction.
	want := []byte("server speaks too")
	go server.Write(want)
	buf := make([]byte, 64)
	client.SetReadDeadline(time.Now().Add(3 * time.Second))
	r, err := client.Read(buf)
	if err != nil || !bytes.Equal(buf[:r], want) {
		t.Fatalf("reverse direction: %q %v", buf[:r], err)
	}
}

// A peer with the wrong token is rejected: the obfuscation masks and the Noise
// PSK are both keyed by the token, so a peer without it cannot produce a message
// the responder accepts, and no traffic crosses.
func TestStealthWrongTokenFails(t *testing.T) {
	client, server := stealthPipe(t, "token-aaaaaaaaaaaaaaaaaaaaaaaaaaaa", "token-bbbbbbbbbbbbbbbbbbbbbbbbbbbb")
	if client != nil && server != nil {
		go client.Write([]byte("should not arrive"))
		server.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		if _, err := server.Read(make([]byte, 32)); err == nil {
			t.Fatal("a peer with the wrong token exchanged traffic")
		}
		return
	}
	// The ordinary outcome: at least one side refused the handshake.
}

// captureOpening returns the raw bytes the initiator puts on the wire before the
// responder answers: the seed, then the first masked frame.
func captureOpening(t *testing.T, token string) []byte {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	out := make(chan []byte, 1)
	go func() {
		raw, err := ln.Accept()
		if err != nil {
			out <- nil
			return
		}
		raw.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
		b, _ := io.ReadAll(raw)
		raw.Close()
		out <- b
	}()

	raw, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	go func() { _, _ = StealthClientConn(raw, token, time.Second) }()

	select {
	case b := <-out:
		return b
	case <-time.After(3 * time.Second):
		t.Fatal("timed out capturing the opening flight")
		return nil
	}
}

// The opening has no fixed shape: the first message is not a fixed size and the
// opening bytes are high-entropy with no readable length prefix.
func TestStealthOpeningHasNoFixedShape(t *testing.T) {
	const token = "stealth-shape-token-0123456789abcd"

	sizes := map[int]int{}
	var first []byte
	for i := 0; i < 32; i++ {
		b := captureOpening(t, token)
		if len(b) < stealthSeedLen+2 {
			t.Fatalf("opening flight too short: %d bytes", len(b))
		}
		sizes[len(b)]++
		if first == nil {
			first = b
		}
	}
	if len(sizes) < 4 {
		t.Errorf("the opening flight took only %d distinct sizes over 32 connections; it is still close to fixed-size", len(sizes))
	}
	if isLowEntropy(first[:min(48, len(first))]) {
		t.Error("the opening bytes are low-entropy and would stand out")
	}
}

// The opening differs on every connection: the seed is fresh, so the derived
// masks are fresh, so no two connections share an opening prefix even on the
// same token. A censor cannot pin a per-token signature.
func TestStealthOpeningDiffersEveryConnection(t *testing.T) {
	const token = "stealth-vary-token-0123456789abcdef"
	seen := map[[32]byte]bool{}
	const n = 24
	for i := 0; i < n; i++ {
		b := captureOpening(t, token)
		if len(b) < stealthSeedLen+2 {
			t.Fatalf("short flight: %d", len(b))
		}
		key := sha256.Sum256(b[:stealthSeedLen+2])
		if seen[key] {
			t.Fatalf("two connections opened with the same seed+prefix — the seed is not fresh")
		}
		seen[key] = true
	}
	if len(seen) != n {
		t.Fatalf("only %d of %d openings were distinct", len(seen), n)
	}
}

// isLowEntropy is a crude check that a short byte slice is not obviously
// structured: it counts distinct byte values and flags a slice that uses very
// few of them. Random bytes over 48 samples use many distinct values; a
// cleartext header or a biased key uses few.
func isLowEntropy(b []byte) bool {
	if len(b) == 0 {
		return true
	}
	seen := map[byte]bool{}
	for _, x := range b {
		seen[x] = true
	}
	return len(seen) < len(b)/2
}

// The initiator detects a wrong-token responder during the handshake, via the
// responder's confirmation tag — so a misconfigured peer fails fast and
// visibly rather than hanging until the first data record.
func TestStealthClientDetectsWrongServerToken(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	go func() {
		raw, err := ln.Accept()
		if err != nil {
			return
		}
		// Responder holds a different token; it completes its own side but the
		// confirmation it sends will not verify on the initiator.
		_, _ = StealthServerConn(raw, "server-has-a-different-token-00000", 3*time.Second)
	}()

	raw, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	if _, err := StealthClientConn(raw, "client-token-aaaaaaaaaaaaaaaaaaaa", 3*time.Second); err == nil {
		t.Fatal("initiator accepted a responder with the wrong token")
	}
}
