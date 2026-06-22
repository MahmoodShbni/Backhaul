// Package tlsutil wraps Backhaul tunnel connections in a real TLS session so the
// traffic looks like an ordinary HTTPS connection to a real domain instead of a
// raw high-entropy stream.
//
// The dialing side (the Backhaul client) uses uTLS to emit a ClientHello whose
// fingerprint (JA3/JA4) matches a real browser such as Chrome, and sends a real
// SNI. The listening side (the Backhaul server) terminates TLS with a standard
// library TLS server, using either a user-supplied certificate or a self-signed
// certificate generated for the configured SNI.
//
// TLS is applied as the OUTERMOST layer (it touches the raw socket), so the very
// first bytes on the wire are a browser-shaped ClientHello.
package tlsutil

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"net"
	"strings"
	"time"

	utls "github.com/refraction-networking/utls"
)

// FingerprintID maps a human-friendly name to a uTLS ClientHello fingerprint.
// Unknown or empty names fall back to the latest Chrome fingerprint.
func FingerprintID(name string) utls.ClientHelloID {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "firefox":
		return utls.HelloFirefox_Auto
	case "safari":
		return utls.HelloSafari_Auto
	case "edge":
		return utls.HelloEdge_Auto
	case "ios":
		return utls.HelloIOS_Auto
	case "android":
		return utls.HelloAndroid_11_OkHttp
	case "random", "randomized":
		return utls.HelloRandomizedALPN
	case "", "chrome":
		fallthrough
	default:
		return utls.HelloChrome_Auto
	}
}

// ClientWrap performs a uTLS handshake over conn as a TLS client. It sends the
// given SNI and mimics the chosen browser fingerprint. When insecure is true the
// server certificate is not verified (appropriate when both ends are yours and
// the server uses a self-signed certificate). The returned net.Conn carries all
// subsequent tunnel traffic inside TLS records.
func ClientWrap(conn net.Conn, sni, fingerprint string, insecure bool, timeout time.Duration) (net.Conn, error) {
	cfg := &utls.Config{
		ServerName:         sni,
		InsecureSkipVerify: insecure,
		MinVersion:         tls.VersionTLS12,
	}
	uconn := utls.UClient(conn, cfg, FingerprintID(fingerprint))

	ctx := context.Background()
	if timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}
	if err := uconn.HandshakeContext(ctx); err != nil {
		return nil, fmt.Errorf("utls client handshake failed: %w", err)
	}
	return uconn, nil
}

// ServerWrap terminates TLS over conn as a TLS server using cert.
func ServerWrap(conn net.Conn, cert *tls.Certificate, timeout time.Duration) (net.Conn, error) {
	cfg := &tls.Config{
		Certificates: []tls.Certificate{*cert},
		MinVersion:   tls.VersionTLS12,
	}
	tconn := tls.Server(conn, cfg)

	ctx := context.Background()
	if timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}
	if err := tconn.HandshakeContext(ctx); err != nil {
		return nil, fmt.Errorf("tls server handshake failed: %w", err)
	}
	return tconn, nil
}

// LoadOrSelfSign returns a TLS certificate for the server. If both certFile and
// keyFile are provided it loads them (use this with a real certificate for the
// SNI domain for the strongest camouflage). Otherwise it generates an in-memory
// self-signed certificate for the given SNI.
func LoadOrSelfSign(certFile, keyFile, sni string) (*tls.Certificate, error) {
	if certFile != "" && keyFile != "" {
		c, err := tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			return nil, fmt.Errorf("failed to load tls cert/key: %w", err)
		}
		return &c, nil
	}

	host := strings.TrimSpace(sni)
	if host == "" {
		host = "www.cloudflare.com" // harmless default SNI for the self-signed cert
	}

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
	}
	tmpl := x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: host},
		DNSNames:              []string{host},
		NotBefore:             time.Now().Add(-24 * time.Hour),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &priv.PublicKey, priv)
	if err != nil {
		return nil, err
	}
	cert := &tls.Certificate{
		Certificate: [][]byte{der},
		PrivateKey:  priv,
	}
	return cert, nil
}
