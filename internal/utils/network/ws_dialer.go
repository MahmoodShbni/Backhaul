package network

import (
	"context"
	"fmt"
	"math/rand"
	"net"
	"net/http"
	"strconv"
	"time"

	"github.com/gorilla/websocket"
	"github.com/musix/backhaul/config"
	utls "github.com/refraction-networking/utls"
)

// uTLS hello specs — هر بار یکی تصادفی انتخاب میشه
// از Auto استفاده میکنیم که در همه نسخه‌های utls وجود داره
// و همیشه جدیدترین fingerprint هر مرورگر رو انتخاب میکنه
var chromeHelloIDs = []utls.ClientHelloID{
	utls.HelloChrome_Auto,
	utls.HelloChrome_Auto,
	utls.HelloChrome_Auto,
	utls.HelloFirefox_Auto,
	utls.HelloEdge_Auto,
	utls.HelloSafari_Auto,
}

func randomHelloID() utls.ClientHelloID {
	return chromeHelloIDs[rand.Intn(len(chromeHelloIDs))]
}

// dialUTLS — TCP میزنه بعد TLS handshake با fingerprint مرورگر
func dialUTLS(ctx context.Context, edgeIP string, sni string, timeout time.Duration, keepalive time.Duration, nodelay bool, SO_RCVBUF int, SO_SNDBUF int) (net.Conn, error) {
	tcpConn, err := TcpDialer(ctx, edgeIP, "", timeout, keepalive, nodelay, 1, SO_RCVBUF, SO_SNDBUF, 0)
	if err != nil {
		return nil, fmt.Errorf("TCP dial failed: %w", err)
	}

	uConn := utls.UClient(tcpConn, &utls.Config{
		ServerName:         sni,
		InsecureSkipVerify: true,
	}, randomHelloID())

	if err := uConn.HandshakeContext(ctx); err != nil {
		tcpConn.Close()
		return nil, fmt.Errorf("uTLS handshake failed: %w", err)
	}

	return uConn, nil
}

func WebSocketDialer(ctx context.Context, addr string, edgeIP string, path string, timeout time.Duration, keepalive time.Duration, nodelay bool, token string, mode config.TransportType, retry int, SO_RCVBUF int, SO_SNDBUF int) (*websocket.Conn, error) {
	var tunnelWSConn *websocket.Conn
	var err error

	retries := retry
	backoff := 1 * time.Second

	for i := 0; i < retries; i++ {
		tunnelWSConn, err = attemptDialWebSocket(ctx, addr, edgeIP, path, timeout, keepalive, nodelay, token, mode, SO_RCVBUF, SO_SNDBUF)
		if err == nil {
			return tunnelWSConn, nil
		}

		if i == retries-1 {
			break
		}

		time.Sleep(backoff)
		backoff *= 2
	}

	return nil, err
}

func attemptDialWebSocket(ctx context.Context, addr string, edgeIP string, path string, timeout time.Duration, keepalive time.Duration, nodelay bool, token string, mode config.TransportType, SO_RCVBUF int, SO_SNDBUF int) (*websocket.Conn, error) {
	randomUserID := rand.Int31()

	userAgents := []string{
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 14_2_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
	}
	randomUserAgent := userAgents[rand.Intn(len(userAgents))]

	headers := http.Header{}
	headers.Add("Authorization", fmt.Sprintf("Bearer %v", token))
	headers.Add("X-User-Id", fmt.Sprintf("%d", randomUserID))
	headers.Add("User-Agent", randomUserAgent)

	// edgeIP — اگه CDN fronting داری اینجا overrideمیشه
	targetAddr := addr
	if edgeIP != "" {
		_, port, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, fmt.Errorf("invalid address format: %w", err)
		}
		targetAddr = fmt.Sprintf("%s:%s", edgeIP, port)
	}

	// SNI همیشه از addr اصلی (domain)، نه edgeIP
	sni, _, _ := net.SplitHostPort(addr)
	if sni == "" {
		sni = addr
	}

	if path != "/channel" {
		path = fmt.Sprintf("%s/%s", path, strconv.Itoa(int(randomUserID)))
	}

	var wsURL string
	var dialer websocket.Dialer

	switch mode {
	case config.WS, config.WSMUX:
		wsURL = fmt.Sprintf("ws://%s%s", addr, path)

		dialer = websocket.Dialer{
			EnableCompression: true,
			HandshakeTimeout:  45 * time.Second,
			NetDial: func(_, _ string) (net.Conn, error) {
				return TcpDialer(ctx, targetAddr, "", timeout, keepalive, nodelay, 1, SO_RCVBUF, SO_SNDBUF, 0)
			},
		}

	case config.WSS, config.WSSMUX:
		wsURL = fmt.Sprintf("wss://%s%s", addr, path)

		dialer = websocket.Dialer{
			EnableCompression: true,
			HandshakeTimeout:  45 * time.Second,
			// NetDialTLSContext — TLS رو خودمون با uTLS انجام میدیم
			// gorilla دیگه TLS نمیزنه، ما میزنیم
			NetDialTLSContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return dialUTLS(ctx, targetAddr, sni, timeout, keepalive, nodelay, SO_RCVBUF, SO_SNDBUF)
			},
		}
	}

	tunnelWSConn, _, err := dialer.Dial(wsURL, headers)
	if err != nil {
		return nil, err
	}
	return tunnelWSConn, nil
}
