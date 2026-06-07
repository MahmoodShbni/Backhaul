package transport

import (
	"context"
	"encoding/binary"
	"fmt"
	"math/rand"
	"net"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/musix/backhaul/internal/utils"
	"github.com/musix/backhaul/internal/utils/network"
	"github.com/musix/backhaul/internal/web"
	"github.com/sirupsen/logrus"
)

// ---- tuning constants -------------------------------------------------------

const (
	udpMaxPacket   = 65535 // largest UDP payload we will carry
	udpBufSize     = utils.UDPHeaderSize + udpMaxPacket
	udpSocketBuf   = 16 << 20         // 16 MiB SO_RCVBUF/SO_SNDBUF per socket
	udpIdleTimeout = 60 * time.Second // drop a session after this much silence
	udpJanitorTick = 15 * time.Second // how often to sweep idle sessions
	udpMaxWorkers  = 8                // cap on REUSEPORT sockets/reader goroutines
)

// reusable packet buffers, sized to fit header + a max UDP datagram.
var udpBufPool = sync.Pool{New: func() any { b := make([]byte, udpBufSize); return &b }}

func getUDPBuf() *[]byte  { return udpBufPool.Get().(*[]byte) }
func putUDPBuf(b *[]byte) { udpBufPool.Put(b) }

func udpWorkers() int {
	w := runtime.GOMAXPROCS(0)
	if w > udpMaxWorkers {
		w = udpMaxWorkers
	}
	if w < 1 {
		w = 1
	}
	return w
}

// ---- types ------------------------------------------------------------------

// serverSession is one end-user flow. The server originates every session: the
// first packet from a fresh end-user address allocates an id and an OP_NEW frame
// carrying the target is pushed into the tunnel. Replies arriving from the
// tunnel are written back to the end-user on the same local socket.
type serverSession struct {
	id         uint64
	enduser    *net.UDPAddr
	localConn  *net.UDPConn // local listener socket to reply to the end-user on
	clientAddr *net.UDPAddr // authenticated client tunnel endpoint this session is pinned to
	tunnelOut  *net.UDPConn // server tunnel socket used to reach the client
	enduserKey string       // cached map key, for O(1) deletion
	lastSeen   int64        // atomic, UnixNano
}

type UdpConfig struct {
	BindAddr     string
	Token        string
	SnifferLog   string
	TunnelStatus string
	Ports        []string
	Sniffer      bool
	Heartbeat    time.Duration
	ChannelSize  int
	WebPort      int
}

type UdpTransport struct {
	config    *UdpConfig
	parentctx context.Context
	ctx       context.Context
	cancel    context.CancelFunc
	logger    *logrus.Logger

	controlChannel net.Conn
	restartMutex   sync.Mutex
	usageMonitor   *web.Usage
	rtt            int64

	workers     int
	tunnelConns []*net.UDPConn // persistent REUSEPORT tunnel sockets (set once, then read-only)

	mu            sync.RWMutex
	sessByID      map[uint64]*serverSession
	sessByEnduser map[string]*serverSession

	clientMu   sync.RWMutex
	clientList []*net.UDPAddr   // authenticated client tunnel endpoints
	clientSeen map[string]int64 // endpoint string -> lastSeen UnixNano
	rr         uint64           // round-robin cursor for client selection

	seq uint64 // atomic session-id counter (random base so ids are unpredictable)
}

func NewUDPServer(parentCtx context.Context, config *UdpConfig, logger *logrus.Logger) *UdpTransport {
	ctx, cancel := context.WithCancel(parentCtx)

	return &UdpTransport{
		config:        config,
		parentctx:     parentCtx,
		ctx:           ctx,
		cancel:        cancel,
		logger:        logger,
		usageMonitor:  web.NewDataStore(fmt.Sprintf(":%v", config.WebPort), ctx, config.SnifferLog, config.Sniffer, &config.TunnelStatus, logger),
		workers:       udpWorkers(),
		sessByID:      make(map[uint64]*serverSession),
		sessByEnduser: make(map[string]*serverSession),
		clientSeen:    make(map[string]int64),
		seq:           rand.Uint64(),
	}
}

func (s *UdpTransport) Start() {
	s.config.TunnelStatus = "Disconnected (UDP)"

	if s.config.WebPort > 0 {
		go s.usageMonitor.Monitor()
	}

	go s.channelHandshake()
}

func (s *UdpTransport) Restart() {
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
	for _, c := range s.tunnelConns {
		c.Close()
	}

	time.Sleep(2 * time.Second)

	ctx, cancel := context.WithCancel(s.parentctx)
	s.ctx = ctx
	s.cancel = cancel

	s.usageMonitor = web.NewDataStore(fmt.Sprintf(":%v", s.config.WebPort), ctx, s.config.SnifferLog, s.config.Sniffer, &s.config.TunnelStatus, s.logger)
	s.config.TunnelStatus = ""
	s.controlChannel = nil
	s.tunnelConns = nil
	s.mu.Lock()
	s.sessByID = make(map[uint64]*serverSession)
	s.sessByEnduser = make(map[string]*serverSession)
	s.mu.Unlock()
	s.clientMu.Lock()
	s.clientList = nil
	s.clientSeen = make(map[string]int64)
	s.clientMu.Unlock()

	s.logger.SetLevel(level)

	go s.Start()
}

// ---- control channel (TCP) --------------------------------------------------

func (s *UdpTransport) channelHandshake() {
	listener, err := net.Listen("tcp", s.config.BindAddr)
	if err != nil {
		s.logger.Fatalf("failed to start listener on %s: %v", s.config.BindAddr, err)
		return
	}
	s.logger.Infof("server started successfully, listening on address: %s", listener.Addr().String())
	defer listener.Close()

loop:
	for {
		select {
		case <-s.ctx.Done():
			return
		default:
			conn, err := listener.Accept()
			if err != nil {
				s.logger.Debugf("failed to accept control channel connection: %v", err)
				continue
			}

			if err := conn.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
				conn.Close()
				continue
			}

			msg, transport, err := utils.ReceiveBinaryTransportString(conn)
			if transport != utils.SG_Chan {
				s.logger.Error("invalid signal received for channel, discarding connection")
				conn.Close()
				continue
			} else if err != nil {
				s.logger.Errorf("failed to receive control channel signal: %v", err)
				conn.Close()
				continue
			}

			conn.SetReadDeadline(time.Time{})

			if msg != s.config.Token {
				s.logger.Warnf("invalid security token received: %s", msg)
				conn.Close()
				continue
			}

			if err = utils.SendBinaryTransportString(conn, s.config.Token, utils.SG_Chan); err != nil {
				s.logger.Errorf("failed to send security token: %v", err)
				conn.Close()
				continue
			}

			s.controlChannel = conn
			s.logger.Info("control channel successfully established.")
			break loop
		}
	}

	s.config.TunnelStatus = "Connected (UDP)"

	s.startTunnel()
	go s.parsePortMappings()
	go s.channelHandler()
	go s.janitor()

	<-s.ctx.Done()
}

func (s *UdpTransport) channelHandler() {
	ticker := time.NewTicker(s.config.Heartbeat)
	defer ticker.Stop()

	messageChan := make(chan byte, 1)

	go func() {
		for {
			select {
			case <-s.ctx.Done():
				return
			default:
				message, err := utils.ReceiveBinaryByte(s.controlChannel)
				if err != nil {
					if s.cancel != nil {
						s.logger.Error("failed to read from control channel. ", err)
						go s.Restart()
					}
					return
				}
				messageChan <- message
			}
		}
	}()

	rtt := time.Now()
	if err := utils.SendBinaryByte(s.controlChannel, utils.SG_RTT); err != nil {
		s.logger.Error("failed to send RTT signal, restarting...")
		go s.Restart()
		return
	}

	for {
		select {
		case <-s.ctx.Done():
			_ = utils.SendBinaryByte(s.controlChannel, utils.SG_Closed)
			return

		case <-ticker.C:
			if err := utils.SendBinaryByte(s.controlChannel, utils.SG_HB); err != nil {
				s.logger.Error("failed to send heartbeat signal")
				go s.Restart()
				return
			}
			s.logger.Trace("heartbeat signal sent successfully")

		case message, ok := <-messageChan:
			if !ok {
				return
			}
			switch message {
			case utils.SG_Closed:
				s.logger.Warn("control channel has been closed by the client")
				go s.Restart()
				return
			case utils.SG_RTT:
				s.rtt = time.Since(rtt).Milliseconds()
				s.logger.Infof("Round Trip Time (RTT): %d ms", s.rtt)
			}
		}
	}
}

// ---- tunnel data plane ------------------------------------------------------

func (s *UdpTransport) startTunnel() {
	lc := net.ListenConfig{Control: network.ReusePortControl}
	conns := make([]*net.UDPConn, 0, s.workers)

	for i := 0; i < s.workers; i++ {
		pc, err := lc.ListenPacket(s.ctx, "udp", s.config.BindAddr)
		if err != nil {
			s.logger.Fatalf("failed to open tunnel UDP socket on %s: %v", s.config.BindAddr, err)
			return
		}
		uc := pc.(*net.UDPConn)
		_ = uc.SetReadBuffer(udpSocketBuf)
		_ = uc.SetWriteBuffer(udpSocketBuf)
		conns = append(conns, uc)
	}

	s.tunnelConns = conns
	for _, uc := range conns {
		go s.tunnelReader(uc)
	}

	s.logger.Infof("UDP tunnel listening on %s with %d worker socket(s)", s.config.BindAddr, s.workers)
}

// tunnelReader consumes frames coming back from the client over one tunnel socket.
func (s *UdpTransport) tunnelReader(uc *net.UDPConn) {
	for {
		bp := getUDPBuf()
		buf := *bp

		n, src, err := uc.ReadFromUDP(buf)
		if err != nil {
			putUDPBuf(bp)
			select {
			case <-s.ctx.Done():
				return
			default:
			}
			s.logger.Debugf("tunnel read error: %v", err)
			return
		}
		if n < utils.UDPHeaderSize {
			putUDPBuf(bp)
			continue
		}

		op, id := utils.ParseUDPHeader(buf)
		switch op {
		case utils.UDPOpKeepalive:
			if string(buf[utils.UDPHeaderSize:n]) == s.config.Token {
				s.registerClient(src)
			} else {
				s.logger.Warnf("invalid token in keepalive from %s", src.String())
			}

		case utils.UDPOpData:
			if !s.clientAuthed(src) {
				putUDPBuf(bp)
				continue
			}
			s.mu.RLock()
			sess := s.sessByID[id]
			s.mu.RUnlock()
			if sess != nil {
				atomic.StoreInt64(&sess.lastSeen, time.Now().UnixNano())
				if _, err := sess.localConn.WriteToUDP(buf[utils.UDPHeaderSize:n], sess.enduser); err != nil {
					s.logger.Debugf("write to end-user failed: %v", err)
				} else if s.config.Sniffer {
					s.usageMonitor.AddOrUpdatePort(sess.localConn.LocalAddr().(*net.UDPAddr).Port, uint64(n-utils.UDPHeaderSize))
				}
			}

		case utils.UDPOpClose:
			s.closeSession(id)
		}

		putUDPBuf(bp)
	}
}

func (s *UdpTransport) registerClient(addr *net.UDPAddr) {
	key := addr.String()
	now := time.Now().UnixNano()
	s.clientMu.Lock()
	if _, ok := s.clientSeen[key]; !ok {
		s.clientList = append(s.clientList, addr)
		s.logger.Infof("registered client tunnel endpoint %s", key)
	}
	s.clientSeen[key] = now
	s.clientMu.Unlock()
}

func (s *UdpTransport) clientAuthed(addr *net.UDPAddr) bool {
	s.clientMu.RLock()
	_, ok := s.clientSeen[addr.String()]
	s.clientMu.RUnlock()
	return ok
}

func (s *UdpTransport) pickClient() *net.UDPAddr {
	s.clientMu.RLock()
	defer s.clientMu.RUnlock()
	if len(s.clientList) == 0 {
		return nil
	}
	i := atomic.AddUint64(&s.rr, 1)
	return s.clientList[int(i)%len(s.clientList)]
}

// ---- local listeners (end-user side) ----------------------------------------

func (s *UdpTransport) localListener(localAddr, remoteAddr string) {
	lc := net.ListenConfig{Control: network.ReusePortControl}

	for i := 0; i < s.workers; i++ {
		pc, err := lc.ListenPacket(s.ctx, "udp", localAddr)
		if err != nil {
			s.logger.Fatalf("failed to listen on local UDP %s: %v", localAddr, err)
			return
		}
		uc := pc.(*net.UDPConn)
		_ = uc.SetReadBuffer(udpSocketBuf)
		_ = uc.SetWriteBuffer(udpSocketBuf)
		go s.localReader(uc, remoteAddr)
	}

	s.logger.Infof("UDP local listener on %s -> %s (%d worker socket(s))", localAddr, remoteAddr, s.workers)
}

// localReader forwards datagrams from end-users into the tunnel. Header room is
// reserved at the front of the buffer so the frame header can be stamped in
// place without copying the payload.
func (s *UdpTransport) localReader(uc *net.UDPConn, target string) {
	localPort := uc.LocalAddr().(*net.UDPAddr).Port

	for {
		bp := getUDPBuf()
		buf := *bp

		n, src, err := uc.ReadFromUDP(buf[utils.UDPHeaderSize:])
		if err != nil {
			putUDPBuf(bp)
			select {
			case <-s.ctx.Done():
				return
			default:
			}
			s.logger.Debugf("local read error: %v", err)
			return
		}

		key := strconv.Itoa(localPort) + "|" + src.String()

		s.mu.RLock()
		sess := s.sessByEnduser[key]
		s.mu.RUnlock()

		if sess != nil {
			atomic.StoreInt64(&sess.lastSeen, time.Now().UnixNano())
			utils.PutUDPHeader(buf, utils.UDPOpData, sess.id)
			_, _ = sess.tunnelOut.WriteToUDP(buf[:utils.UDPHeaderSize+n], sess.clientAddr)
			if s.config.Sniffer {
				s.usageMonitor.AddOrUpdatePort(localPort, uint64(n))
			}
			putUDPBuf(bp)
			continue
		}

		// brand-new flow: pick a client endpoint and open a session inline.
		clientAddr := s.pickClient()
		if clientAddr == nil {
			s.logger.Warn("no client tunnel endpoint registered yet, dropping UDP packet")
			putUDPBuf(bp)
			continue
		}

		id := atomic.AddUint64(&s.seq, 1)
		tunnelOut := s.tunnelConns[int(id)%len(s.tunnelConns)]
		sess = &serverSession{
			id:         id,
			enduser:    src,
			localConn:  uc,
			clientAddr: clientAddr,
			tunnelOut:  tunnelOut,
			enduserKey: key,
			lastSeen:   time.Now().UnixNano(),
		}

		s.mu.Lock()
		s.sessByID[id] = sess
		s.sessByEnduser[key] = sess
		s.mu.Unlock()

		// OP_NEW carries the target then the first payload; assembled in a
		// separate buffer because the layout differs from the steady-state path.
		ob := getUDPBuf()
		out := *ob
		utils.PutUDPHeader(out, utils.UDPOpNew, id)
		tb := []byte(target)
		binary.BigEndian.PutUint16(out[utils.UDPHeaderSize:], uint16(len(tb)))
		off := utils.UDPHeaderSize + 2
		off += copy(out[off:], tb)
		off += copy(out[off:], buf[utils.UDPHeaderSize:utils.UDPHeaderSize+n])
		_, _ = tunnelOut.WriteToUDP(out[:off], clientAddr)
		putUDPBuf(ob)

		if s.config.Sniffer {
			s.usageMonitor.AddOrUpdatePort(localPort, uint64(n))
		}
		s.logger.Debugf("opened session %d for end-user %s -> %s", id, src.String(), target)
		putUDPBuf(bp)
	}
}

func (s *UdpTransport) closeSession(id uint64) {
	s.mu.Lock()
	if sess, ok := s.sessByID[id]; ok {
		delete(s.sessByID, id)
		delete(s.sessByEnduser, sess.enduserKey)
	}
	s.mu.Unlock()
}

func (s *UdpTransport) janitor() {
	t := time.NewTicker(udpJanitorTick)
	defer t.Stop()

	for {
		select {
		case <-s.ctx.Done():
			return
		case <-t.C:
			now := time.Now().UnixNano()

			s.mu.Lock()
			for id, sess := range s.sessByID {
				if now-atomic.LoadInt64(&sess.lastSeen) > int64(udpIdleTimeout) {
					delete(s.sessByID, id)
					delete(s.sessByEnduser, sess.enduserKey)
				}
			}
			s.mu.Unlock()

			s.clientMu.Lock()
			kept := s.clientList[:0]
			for _, a := range s.clientList {
				if s.config.Heartbeat == 0 || now-s.clientSeen[a.String()] <= int64(3*s.config.Heartbeat) {
					kept = append(kept, a)
				} else {
					delete(s.clientSeen, a.String())
				}
			}
			s.clientList = kept
			s.clientMu.Unlock()
		}
	}
}

// ---- port-mapping parsing (setup path) --------------------------------------

func (s *UdpTransport) parsePortMappings() {
	for _, portMapping := range s.config.Ports {
		parts := strings.Split(portMapping, "=")

		var localAddr, remoteAddr string

		switch len(parts) {
		case 1:
			localPortOrRange := strings.TrimSpace(parts[0])
			remoteAddr = localPortOrRange

			if strings.Contains(localPortOrRange, "-") {
				start, end := s.parseRange(localPortOrRange)
				for port := start; port <= end; port++ {
					go s.localListener(fmt.Sprintf(":%d", port), strconv.Itoa(port))
					time.Sleep(time.Millisecond)
				}
				continue
			}
			port, err := strconv.Atoi(localPortOrRange)
			if err != nil || port < 1 || port > 65535 {
				s.logger.Fatalf("invalid port format: %s", localPortOrRange)
			}
			localAddr = fmt.Sprintf(":%d", port)

		case 2:
			localPortOrRange := strings.TrimSpace(parts[0])
			remoteAddr = strings.TrimSpace(parts[1])

			if strings.Contains(localPortOrRange, "-") {
				start, end := s.parseRange(localPortOrRange)
				for port := start; port <= end; port++ {
					go s.localListener(fmt.Sprintf(":%d", port), remoteAddr)
					time.Sleep(time.Millisecond)
				}
				continue
			}
			if port, err := strconv.Atoi(localPortOrRange); err == nil && port > 1 && port < 65535 {
				localAddr = fmt.Sprintf(":%d", port)
			} else {
				localAddr = localPortOrRange
			}

		default:
			s.logger.Fatalf("invalid port mapping format: %s", portMapping)
		}

		go s.localListener(localAddr, remoteAddr)
	}
}

func (s *UdpTransport) parseRange(r string) (int, int) {
	rangeParts := strings.Split(r, "-")
	if len(rangeParts) != 2 {
		s.logger.Fatalf("invalid port range format: %s", r)
	}
	start, err := strconv.Atoi(strings.TrimSpace(rangeParts[0]))
	if err != nil || start < 1 || start > 65535 {
		s.logger.Fatalf("invalid start port in range: %s", rangeParts[0])
	}
	end, err := strconv.Atoi(strings.TrimSpace(rangeParts[1]))
	if err != nil || end < 1 || end > 65535 || end < start {
		s.logger.Fatalf("invalid end port in range: %s", rangeParts[1])
	}
	return start, end
}
