package transport

import (
	"context"
	"crypto/rand"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/musix/backhaul/config"
	"github.com/musix/backhaul/internal/utils"
	"github.com/musix/backhaul/internal/utils/handlers"
	"github.com/musix/backhaul/internal/web"

	"github.com/gorilla/websocket"
	"github.com/sirupsen/logrus"
)

type WsTransport struct {
	config         *WsConfig
	parentctx      context.Context
	ctx            context.Context
	cancel         context.CancelFunc
	logger         *logrus.Logger
	tunnelChannel  chan TunnelChannel
	localChannel   chan LocalTCPConn
	reqNewConnChan chan struct{}
	controlChannel *websocket.Conn
	restartMutex   sync.Mutex
	usageMonitor   *web.Usage
}

type WsConfig struct {
	BindAddr     string
	SnifferLog   string
	TLSCertFile  string
	TLSKeyFile   string
	TunnelStatus string
	Token        string
	Ports        []string
	Nodelay      bool
	Sniffer      bool
	KeepAlive    time.Duration
	Heartbeat    time.Duration
	ChannelSize  int
	WebPort      int
	Mode         config.TransportType
}

// cryptoRandInt returns a random int in [0, n) using crypto/rand
func cryptoRandInt(n int) int {
	if n <= 0 {
		return 0
	}
	val, err := rand.Int(rand.Reader, big.NewInt(int64(n)))
	if err != nil {
		return 0
	}
	return int(val.Int64())
}

// randPadding returns a random byte slice of length in [minLen, maxLen]
func randPadding(minLen, maxLen int) []byte {
	size := minLen + cryptoRandInt(maxLen-minLen+1)
	buf := make([]byte, size)
	rand.Read(buf)
	return buf
}

// jitteredSleep sleeps base ± (jitterFrac * base)
func jitteredSleep(base time.Duration, jitterFrac float64) {
	jitter := time.Duration(float64(base) * jitterFrac)
	// random value in [-jitter, +jitter]
	delta := time.Duration(cryptoRandInt(int(2*jitter+1))) - jitter
	d := base + delta
	if d < 500*time.Millisecond {
		d = 500 * time.Millisecond
	}
	time.Sleep(d)
}

func NewWSServer(parentCtx context.Context, config *WsConfig, logger *logrus.Logger) *WsTransport {
	ctx, cancel := context.WithCancel(parentCtx)
	server := &WsTransport{
		config:         config,
		parentctx:      parentCtx,
		ctx:            ctx,
		cancel:         cancel,
		logger:         logger,
		tunnelChannel:  make(chan TunnelChannel, config.ChannelSize),
		localChannel:   make(chan LocalTCPConn, config.ChannelSize),
		reqNewConnChan: make(chan struct{}, config.ChannelSize),
		controlChannel: nil,
		usageMonitor:   web.NewDataStore(fmt.Sprintf(":%v", config.WebPort), ctx, config.SnifferLog, config.Sniffer, &config.TunnelStatus, logger),
	}
	return server
}

func (s *WsTransport) Start() {
	if s.config.WebPort > 0 {
		go s.usageMonitor.Monitor()
	}
	s.config.TunnelStatus = fmt.Sprintf("Disconnected (%s)", s.config.Mode)
	go s.tunnelListener()
}

func (s *WsTransport) Restart() {
	if !s.restartMutex.TryLock() {
		s.logger.Warn("server restart already in progress, skipping restart attempt")
		return
	}
	defer s.restartMutex.Unlock()

	s.logger.Info("restarting server...")
	level := s.logger.Level
	s.logger.SetLevel(logrus.FatalLevel)

	if s.cancel != nil {
		s.cancel()
	}
	if s.controlChannel != nil {
		s.controlChannel.Close()
	}

	time.Sleep(2 * time.Second)

	ctx, cancel := context.WithCancel(s.parentctx)
	s.ctx = ctx
	s.cancel = cancel
	s.tunnelChannel = make(chan TunnelChannel, s.config.ChannelSize)
	s.localChannel = make(chan LocalTCPConn, s.config.ChannelSize)
	s.reqNewConnChan = make(chan struct{}, s.config.ChannelSize)
	s.controlChannel = nil
	s.usageMonitor = web.NewDataStore(fmt.Sprintf(":%v", s.config.WebPort), ctx, s.config.SnifferLog, s.config.Sniffer, &s.config.TunnelStatus, s.logger)
	s.config.TunnelStatus = ""
	s.logger.SetLevel(level)

	go s.Start()
}

func (s *WsTransport) channelHandler() {
	messageChan := make(chan byte, 10)

	// Reader goroutine — reads first byte; rest is padding, ignored
	go func() {
		for {
			select {
			case <-s.ctx.Done():
				return
			default:
				_, msg, err := s.controlChannel.ReadMessage()
				if err != nil {
					if s.cancel != nil {
						s.logger.Error("failed to read from channel connection. ", err)
						go s.Restart()
					}
					return
				}
				messageChan <- msg[0] // only first byte is the signal
			}
		}
	}()

	// Heartbeat goroutine — jittered interval, randompadded payload
	// Runs independently so reqNewConnChan select is never blocked by sleep
	go func() {
		for {
			jitteredSleep(s.config.Heartbeat, 0.4) // ±40% jitter
			select {
			case <-s.ctx.Done():
				return
			default:
				payload := append([]byte{utils.SG_HB}, randPadding(16, 96)...)
				if err := s.controlChannel.WriteMessage(websocket.BinaryMessage, payload); err != nil {
					s.logger.Errorf("failed to send heartbeat signal. Error: %v.", err)
					go s.Restart()
					return
				}
				s.logger.Debug("heartbeat signal sent successfully")
			}
		}
	}()

	for {
		select {
		case <-s.ctx.Done():
			_ = s.controlChannel.WriteMessage(websocket.BinaryMessage, []byte{utils.SG_Closed})
			return

		case <-s.reqNewConnChan:
			// Pad SG_Chan so it looks the same size as heartbeats
			payload := append([]byte{utils.SG_Chan}, randPadding(8, 48)...)
			err := s.controlChannel.WriteMessage(websocket.BinaryMessage, payload)
			if err != nil {
				s.logger.Error("failed to send request new connection signal. ", err)
				go s.Restart()
				return
			}

		case msg, ok := <-messageChan:
			if !ok {
				s.logger.Error("channel closed, likely due to an error in WebSocket read")
				return
			}
			switch msg {
			case utils.SG_HB:
				s.logger.Trace("heartbeat signal received successfully")
			case utils.SG_Closed:
				s.logger.Warn("control channel has been closed by the client")
				s.Restart()
				return
			default:
				s.logger.Errorf("unexpected response from channel: %v", msg)
				go s.Restart()
				return
			}
		}
	}
}

func (s *WsTransport) tunnelListener() {
	addr := s.config.BindAddr
	upgrader := websocket.Upgrader{
		ReadBufferSize:   16 * 1024,
		WriteBufferSize:  16 * 1024,
		HandshakeTimeout: 45 * time.Second,
		CheckOrigin:      func(r *http.Request) bool { return true },
	}

	server := &http.Server{
		Addr:        addr,
		IdleTimeout: -1,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			s.logger.Tracef("received http request from %s", r.RemoteAddr)

			authHeader := r.Header.Get("Authorization")
			if authHeader != fmt.Sprintf("Bearer %v", s.config.Token) {
				s.logger.Warnf("unauthorized request from %s, closing connection", r.RemoteAddr)
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}

			conn, err := upgrader.Upgrade(w, r, nil)
			if err != nil {
				s.logger.Errorf("failed to upgrade connection from %s: %v", r.RemoteAddr, err)
				return
			}

			if r.URL.Path == "/channel" {
				if s.controlChannel != nil {
					s.logger.Warn("new control channel requested.")
					s.controlChannel.Close()
					conn.Close()
					go s.Restart()
					return
				}
				s.controlChannel = conn
				s.logger.Info("control channel established successfully")

				numCPU := runtime.NumCPU()
				if numCPU > 4 {
					numCPU = 4
				}
				go s.channelHandler()
				go s.parsePortMappings()
				s.logger.Infof("starting %d handle loops on each CPU thread", numCPU)
				for i := 0; i < numCPU; i++ {
					go s.handleLoop()
				}
				s.config.TunnelStatus = fmt.Sprintf("Connected (%s)", s.config.Mode)

			} else if strings.HasPrefix(r.URL.Path, "/tunnel") {
				wsConn := TunnelChannel{
					conn: conn,
					ping: make(chan struct{}),
					mu:   &sync.Mutex{},
				}
				select {
				case s.tunnelChannel <- wsConn:
					go s.keepAlive(&wsConn)
					s.logger.Debugf("websocket connection accepted from %s", conn.RemoteAddr().String())
				default:
					s.logger.Warnf("websocket tunnel channel is full, closing connection from %s", conn.RemoteAddr().String())
					conn.Close()
				}
			}
		}),
	}

	if s.config.Mode == config.WS {
		go func() {
			s.logger.Infof("ws server starting, listening on %s", addr)
			if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				s.logger.Fatalf("failed to listen on %s: %v", addr, err)
			}
		}()
	} else {
		go func() {
			s.logger.Infof("wss server starting, listening on %s", addr)
			if err := server.ListenAndServeTLS(s.config.TLSCertFile, s.config.TLSKeyFile); err != nil && err != http.ErrServerClosed {
				s.logger.Fatalf("failed to listen on %s: %v", addr, err)
			}
		}()
	}

	<-s.ctx.Done()

	s.logger.Infof("shutting down the webSocket server on %s", addr)
	if err := server.Shutdown(context.Background()); err != nil {
		s.logger.Errorf("Failed to gracefully shutdown the server: %v", err)
	}
	if s.controlChannel != nil {
		s.controlChannel.Close()
	}
}

func (s *WsTransport) parsePortMappings() {
	for _, portMapping := range s.config.Ports {
		parts := strings.Split(portMapping, "=")
		var localAddr, remoteAddr string

		if len(parts) == 1 {
			localPortOrRange := strings.TrimSpace(parts[0])
			remoteAddr = localPortOrRange
			if strings.Contains(localPortOrRange, "-") {
				rangeParts := strings.Split(localPortOrRange, "-")
				if len(rangeParts) != 2 {
					s.logger.Fatalf("invalid port range format: %s", localPortOrRange)
				}
				startPort, err := strconv.Atoi(strings.TrimSpace(rangeParts[0]))
				if err != nil || startPort < 1 || startPort > 65535 {
					s.logger.Fatalf("invalid start port in range: %s", rangeParts[0])
				}
				endPort, err := strconv.Atoi(strings.TrimSpace(rangeParts[1]))
				if err != nil || endPort < 1 || endPort > 65535 || endPort < startPort {
					s.logger.Fatalf("invalid end port in range: %s", rangeParts[1])
				}
				for port := startPort; port <= endPort; port++ {
					localAddr = fmt.Sprintf(":%d", port)
					go s.localListener(localAddr, strconv.Itoa(port))
					time.Sleep(1 * time.Millisecond)
				}
				continue
			} else {
				port, err := strconv.Atoi(localPortOrRange)
				if err != nil || port < 1 || port > 65535 {
					s.logger.Fatalf("invalid port format: %s", localPortOrRange)
				}
				localAddr = fmt.Sprintf(":%d", port)
			}
		} else if len(parts) == 2 {
			localPortOrRange := strings.TrimSpace(parts[0])
			remoteAddr = strings.TrimSpace(parts[1])
			if strings.Contains(localPortOrRange, "-") {
				rangeParts := strings.Split(localPortOrRange, "-")
				if len(rangeParts) != 2 {
					s.logger.Fatalf("invalid port range format: %s", localPortOrRange)
				}
				startPort, err := strconv.Atoi(strings.TrimSpace(rangeParts[0]))
				if err != nil || startPort < 1 || startPort > 65535 {
					s.logger.Fatalf("invalid start port in range: %s", rangeParts[0])
				}
				endPort, err := strconv.Atoi(strings.TrimSpace(rangeParts[1]))
				if err != nil || endPort < 1 || endPort > 65535 || endPort < startPort {
					s.logger.Fatalf("invalid end port in range: %s", rangeParts[1])
				}
				for port := startPort; port <= endPort; port++ {
					localAddr = fmt.Sprintf(":%d", port)
					go s.localListener(localAddr, remoteAddr)
					time.Sleep(1 * time.Millisecond)
				}
				continue
			} else {
				port, err := strconv.Atoi(localPortOrRange)
				if err == nil && port > 1 && port < 65535 {
					localAddr = fmt.Sprintf(":%d", port)
				} else {
					localAddr = localPortOrRange
				}
			}
		} else {
			s.logger.Fatalf("invalid port mapping format: %s", portMapping)
		}
		go s.localListener(localAddr, remoteAddr)
	}
}

func (s *WsTransport) localListener(localAddr string, remoteAddr string) {
	portListener, err := net.Listen("tcp", localAddr)
	if err != nil {
		s.logger.Fatalf("failed to start listener on %s: %v", localAddr, err)
		return
	}
	defer portListener.Close()
	s.logger.Infof("listener started successfully, listening on address: %s", portListener.Addr().String())
	go s.acceptLocalConn(portListener, remoteAddr)
	<-s.ctx.Done()
}

func (s *WsTransport) acceptLocalConn(listener net.Listener, remoteAddr string) {
	for {
		select {
		case <-s.ctx.Done():
			return
		default:
			s.logger.Debugf("waiting to accept incoming connection on %s", listener.Addr().String())
			conn, err := listener.Accept()
			if err != nil {
				s.logger.Debugf("failed to accept connection on %s: %v", listener.Addr().String(), err)
				continue
			}

			tcpConn, ok := conn.(*net.TCPConn)
			if !ok {
				s.logger.Warnf("disarded non-TCP connection from %s", conn.RemoteAddr().String())
				conn.Close()
				continue
			}

			if !s.config.Nodelay {
				if err := tcpConn.SetNoDelay(s.config.Nodelay); err != nil {
					s.logger.Warnf("failed to set TCP_NODELAY for %s: %v", tcpConn.RemoteAddr().String(), err)
				}
			}
			if err := tcpConn.SetKeepAlive(true); err != nil {
				s.logger.Warnf("failed to enable TCP keep-alive for %s: %v", tcpConn.RemoteAddr().String(), err)
			}
			if err := tcpConn.SetKeepAlivePeriod(s.config.KeepAlive); err != nil {
				s.logger.Warnf("failed to set TCP keep-alive period for %s: %v", tcpConn.RemoteAddr().String(), err)
			}

			select {
			case s.localChannel <- LocalTCPConn{conn: conn, remoteAddr: remoteAddr, timeCreated: time.Now().UnixMilli()}:
				select {
				case s.reqNewConnChan <- struct{}{}:
				default:
					s.logger.Warn("channel is full, cannot request a new connection")
				}
				s.logger.Debugf("accepted incoming TCP connection from %s", tcpConn.RemoteAddr().String())
			default:
				s.logger.Warnf("channel with listener %s is full, discarding TCP connection from %s", listener.Addr().String(), tcpConn.LocalAddr().String())
				conn.Close()
			}
		}
	}
}

func (s *WsTransport) handleLoop() {
	for {
		select {
		case <-s.ctx.Done():
			return
		case localConn := <-s.localChannel:
		loop:
			for {
				if time.Now().UnixMilli()-localConn.timeCreated > 3000 {
					s.logger.Debugf("timeouted local connection: %d ms", time.Now().UnixMilli()-localConn.timeCreated)
					localConn.conn.Close()
					break loop
				}
				select {
				case <-s.ctx.Done():
					return
				case tunnelConnection := <-s.tunnelChannel:
					close(tunnelConnection.ping)
					tunnelConnection.mu.Lock()
					if err := tunnelConnection.conn.WriteMessage(websocket.TextMessage, []byte(localConn.remoteAddr)); err != nil {
						s.logger.Debugf("%v", err)
						tunnelConnection.conn.Close()
						continue loop
					}
					go handlers.WSConnectionHandler(s.ctx, tunnelConnection.conn, localConn.conn, s.logger, s.usageMonitor, localConn.conn.LocalAddr().(*net.TCPAddr).Port, s.config.Sniffer)
					break loop
				}
			}
		}
	}
}

func (s *WsTransport) keepAlive(conn *TunnelChannel) {
	for {
		// Jittered sleep instead of fixed ticker — breaks regularity fingerprint
		jitteredSleep(s.config.Heartbeat, 0.4)

		select {
		case <-s.ctx.Done():
			conn.conn.Close()
			return
		case <-conn.ping:
			s.logger.Trace("ping channel closed")
			return
		default:
			locked := conn.mu.TryLock()
			if !locked {
				s.logger.Trace("write operation in progress, stopping pingSender")
				return
			}
			// Padded ping: variable size so all signals look the same in traffic analysis
			payload := append([]byte{utils.SG_Ping}, randPadding(8, 64)...)
			if err := conn.conn.WriteMessage(websocket.BinaryMessage, payload); err != nil {
				conn.mu.Unlock()
				conn.conn.Close()
				return
			}
			conn.mu.Unlock()
			s.logger.Trace("ping sent to the client")
		}
	}
}
