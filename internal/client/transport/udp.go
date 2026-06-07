package transport

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"runtime"
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
	udpMaxPacket    = 65535
	udpBufSize      = utils.UDPHeaderSize + udpMaxPacket
	udpSocketBuf    = 16 << 20 // 16 MiB SO_RCVBUF/SO_SNDBUF per socket
	udpIdleTimeout  = 60 * time.Second
	udpJanitorTick  = 15 * time.Second
	udpKeepaliveInt = 10 * time.Second
	udpMaxWorkers   = 8
)

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

// clientSession maps a server-assigned session id to a connected UDP socket
// toward the real target. Replies from the target are framed and pushed back to
// the server over the same tunnel socket the OP_NEW arrived on.
type clientSession struct {
	id         uint64
	targetConn *net.UDPConn
	tunnelConn *net.UDPConn
	lastSeen   int64 // atomic, UnixNano
}

type UdpConfig struct {
	RemoteAddr     string
	Token          string
	SnifferLog     string
	TunnelStatus   string
	RetryInterval  time.Duration
	DialTimeOut    time.Duration
	ConnPoolSize   int
	WebPort        int
	Sniffer        bool
	AggressivePool bool
}

type UdpTransport struct {
	config    *UdpConfig
	parentctx context.Context
	ctx       context.Context
	cancel    context.CancelFunc
	logger    *logrus.Logger

	controlChannel net.Conn
	usageMonitor   *web.Usage
	restartMutex   sync.Mutex

	workers     int
	tunnelConns []*net.UDPConn

	mu       sync.RWMutex
	sessions map[uint64]*clientSession
}

func NewUDPClient(parentCtx context.Context, config *UdpConfig, logger *logrus.Logger) *UdpTransport {
	ctx, cancel := context.WithCancel(parentCtx)

	return &UdpTransport{
		config:       config,
		parentctx:    parentCtx,
		ctx:          ctx,
		cancel:       cancel,
		logger:       logger,
		usageMonitor: web.NewDataStore(fmt.Sprintf(":%v", config.WebPort), ctx, config.SnifferLog, config.Sniffer, &config.TunnelStatus, logger),
		workers:      udpWorkers(),
		sessions:     make(map[uint64]*clientSession),
	}
}

func (c *UdpTransport) Start() {
	if c.config.WebPort > 0 {
		go c.usageMonitor.Monitor()
	}
	c.config.TunnelStatus = "Disconnected (UDP)"
	go c.channelDialer()
}

func (c *UdpTransport) Restart() {
	if !c.restartMutex.TryLock() {
		c.logger.Warn("client is already restarting")
		return
	}
	defer c.restartMutex.Unlock()

	c.logger.Info("restarting client...")

	level := c.logger.Level
	c.logger.SetLevel(logrus.FatalLevel)

	if c.cancel != nil {
		c.cancel()
	}
	if c.controlChannel != nil {
		c.controlChannel.Close()
	}
	for _, conn := range c.tunnelConns {
		conn.Close()
	}
	c.mu.Lock()
	for _, sess := range c.sessions {
		sess.targetConn.Close()
	}
	c.sessions = make(map[uint64]*clientSession)
	c.mu.Unlock()

	time.Sleep(2 * time.Second)

	ctx, cancel := context.WithCancel(c.parentctx)
	c.ctx = ctx
	c.cancel = cancel

	c.controlChannel = nil
	c.tunnelConns = nil
	c.usageMonitor = web.NewDataStore(fmt.Sprintf(":%v", c.config.WebPort), ctx, c.config.SnifferLog, c.config.Sniffer, &c.config.TunnelStatus, c.logger)
	c.config.TunnelStatus = ""

	c.logger.SetLevel(level)

	go c.Start()
}

// ---- control channel (TCP) --------------------------------------------------

func (c *UdpTransport) channelDialer() {
	c.logger.Info("attempting to establish a new control channel connection...")

	for {
		select {
		case <-c.ctx.Done():
			return
		default:
			tunnelTCPConn, err := network.TcpDialer(c.ctx, c.config.RemoteAddr, "", c.config.DialTimeOut, 30, true, 3, 0, 0, 0)
			if err != nil {
				c.logger.Errorf("channel dialer: %v", err)
				time.Sleep(c.config.RetryInterval)
				continue
			}

			if err = utils.SendBinaryTransportString(tunnelTCPConn, c.config.Token, utils.SG_Chan); err != nil {
				c.logger.Errorf("failed to send security token: %v", err)
				tunnelTCPConn.Close()
				continue
			}

			if err := tunnelTCPConn.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
				tunnelTCPConn.Close()
				continue
			}

			message, _, err := utils.ReceiveBinaryTransportString(tunnelTCPConn)
			if err != nil {
				c.logger.Errorf("failed to receive control channel response: %v", err)
				tunnelTCPConn.Close()
				time.Sleep(c.config.RetryInterval)
				continue
			}
			tunnelTCPConn.SetReadDeadline(time.Time{})

			if message != c.config.Token {
				c.logger.Errorf("invalid token received. retrying...")
				tunnelTCPConn.Close()
				time.Sleep(c.config.RetryInterval)
				continue
			}

			c.controlChannel = tunnelTCPConn
			c.logger.Info("control channel established successfully")
			c.config.TunnelStatus = "Connected (UDP)"

			c.startTunnel()
			go c.channelHandler()
			go c.janitor()
			return
		}
	}
}

func (c *UdpTransport) channelHandler() {
	msgChan := make(chan byte, 1000)

	go func() {
		for {
			select {
			case <-c.ctx.Done():
				return
			default:
				msg, err := utils.ReceiveBinaryByte(c.controlChannel)
				if err != nil {
					if c.cancel != nil {
						c.logger.Error("failed to read from control channel. ", err)
						go c.Restart()
					}
					return
				}
				msgChan <- msg
			}
		}
	}()

	for {
		select {
		case <-c.ctx.Done():
			_ = utils.SendBinaryByte(c.controlChannel, utils.SG_Closed)
			return

		case msg := <-msgChan:
			switch msg {
			case utils.SG_HB:
				c.logger.Debug("heartbeat signal received")
			case utils.SG_RTT:
				if err := utils.SendBinaryByte(c.controlChannel, utils.SG_RTT); err != nil {
					c.logger.Error("failed to send RTT signal, restarting client: ", err)
					go c.Restart()
					return
				}
			case utils.SG_Closed:
				c.logger.Warn("control channel has been closed by the server")
				go c.Restart()
				return
			default:
				// SG_Chan and others are unused by the multiplexed UDP data plane.
				c.logger.Tracef("ignoring control signal: %v", msg)
			}
		}
	}
}

// ---- tunnel data plane ------------------------------------------------------

func (c *UdpTransport) startTunnel() {
	raddr, err := net.ResolveUDPAddr("udp", c.config.RemoteAddr)
	if err != nil {
		c.logger.Errorf("failed to resolve tunnel address: %v", err)
		go c.Restart()
		return
	}

	conns := make([]*net.UDPConn, 0, c.workers)
	for i := 0; i < c.workers; i++ {
		uc, err := net.DialUDP("udp", nil, raddr)
		if err != nil {
			c.logger.Errorf("failed to dial tunnel: %v", err)
			continue
		}
		_ = uc.SetReadBuffer(udpSocketBuf)
		_ = uc.SetWriteBuffer(udpSocketBuf)
		conns = append(conns, uc)
	}
	if len(conns) == 0 {
		go c.Restart()
		return
	}

	c.tunnelConns = conns
	for _, uc := range conns {
		go c.tunnelReader(uc)
	}

	c.sendKeepalives() // register endpoints immediately so the server can route
	go c.keepaliveLoop()

	c.logger.Infof("UDP tunnel to %s established with %d worker socket(s)", c.config.RemoteAddr, len(conns))
}

func (c *UdpTransport) sendKeepalives() {
	bp := getUDPBuf()
	buf := *bp
	utils.PutUDPHeader(buf, utils.UDPOpKeepalive, 0)
	n := utils.UDPHeaderSize + copy(buf[utils.UDPHeaderSize:], c.config.Token)
	for _, uc := range c.tunnelConns {
		_, _ = uc.Write(buf[:n])
	}
	putUDPBuf(bp)
}

func (c *UdpTransport) keepaliveLoop() {
	t := time.NewTicker(udpKeepaliveInt)
	defer t.Stop()
	for {
		select {
		case <-c.ctx.Done():
			return
		case <-t.C:
			c.sendKeepalives()
		}
	}
}

// tunnelReader consumes frames from the server on one tunnel socket.
func (c *UdpTransport) tunnelReader(uc *net.UDPConn) {
	for {
		bp := getUDPBuf()
		buf := *bp

		n, err := uc.Read(buf)
		if err != nil {
			putUDPBuf(bp)
			select {
			case <-c.ctx.Done():
				return
			default:
			}
			c.logger.Debugf("tunnel read error: %v", err)
			return
		}
		if n < utils.UDPHeaderSize {
			putUDPBuf(bp)
			continue
		}

		op, id := utils.ParseUDPHeader(buf)
		switch op {
		case utils.UDPOpNew:
			if n < utils.UDPHeaderSize+2 {
				putUDPBuf(bp)
				continue
			}
			tlen := int(binary.BigEndian.Uint16(buf[utils.UDPHeaderSize:]))
			off := utils.UDPHeaderSize + 2
			if n < off+tlen {
				putUDPBuf(bp)
				continue
			}
			target := string(buf[off : off+tlen])
			c.handleNew(id, target, buf[off+tlen:n], uc)

		case utils.UDPOpData:
			c.mu.RLock()
			sess := c.sessions[id]
			c.mu.RUnlock()
			if sess != nil {
				atomic.StoreInt64(&sess.lastSeen, time.Now().UnixNano())
				_, _ = sess.targetConn.Write(buf[utils.UDPHeaderSize:n])
				if c.config.Sniffer {
					c.usageMonitor.AddOrUpdatePort(sess.targetConn.RemoteAddr().(*net.UDPAddr).Port, uint64(n-utils.UDPHeaderSize))
				}
			}

		case utils.UDPOpClose:
			c.closeSession(id)
		}

		putUDPBuf(bp)
	}
}

func (c *UdpTransport) handleNew(id uint64, target string, payload []byte, tun *net.UDPConn) {
	c.mu.RLock()
	sess := c.sessions[id]
	c.mu.RUnlock()
	if sess != nil {
		_, _ = sess.targetConn.Write(payload)
		return
	}

	raddr, err := net.ResolveUDPAddr("udp", target)
	if err != nil {
		c.logger.Errorf("failed to resolve target %s: %v", target, err)
		return
	}
	tc, err := net.DialUDP("udp", nil, raddr)
	if err != nil {
		c.logger.Errorf("failed to dial target %s: %v", target, err)
		return
	}
	_ = tc.SetReadBuffer(udpSocketBuf)
	_ = tc.SetWriteBuffer(udpSocketBuf)

	sess = &clientSession{
		id:         id,
		targetConn: tc,
		tunnelConn: tun,
		lastSeen:   time.Now().UnixNano(),
	}

	c.mu.Lock()
	c.sessions[id] = sess
	c.mu.Unlock()

	_, _ = tc.Write(payload)
	go c.targetReader(sess)

	c.logger.Debugf("opened session %d -> %s", id, target)
}

// targetReader pumps replies from the real target back into the tunnel. Header
// room is reserved at the front so the frame header is written without a copy.
func (c *UdpTransport) targetReader(sess *clientSession) {
	for {
		bp := getUDPBuf()
		buf := *bp

		n, err := sess.targetConn.Read(buf[utils.UDPHeaderSize:])
		if err != nil {
			putUDPBuf(bp)
			c.closeSession(sess.id)
			c.sendClose(sess)
			return
		}

		atomic.StoreInt64(&sess.lastSeen, time.Now().UnixNano())
		utils.PutUDPHeader(buf, utils.UDPOpData, sess.id)
		_, _ = sess.tunnelConn.Write(buf[:utils.UDPHeaderSize+n])
		if c.config.Sniffer {
			c.usageMonitor.AddOrUpdatePort(sess.targetConn.RemoteAddr().(*net.UDPAddr).Port, uint64(n))
		}

		putUDPBuf(bp)
	}
}

func (c *UdpTransport) sendClose(sess *clientSession) {
	var hb [utils.UDPHeaderSize]byte
	utils.PutUDPHeader(hb[:], utils.UDPOpClose, sess.id)
	_, _ = sess.tunnelConn.Write(hb[:])
}

func (c *UdpTransport) closeSession(id uint64) {
	c.mu.Lock()
	sess := c.sessions[id]
	delete(c.sessions, id)
	c.mu.Unlock()
	if sess != nil {
		sess.targetConn.Close()
	}
}

func (c *UdpTransport) janitor() {
	t := time.NewTicker(udpJanitorTick)
	defer t.Stop()
	for {
		select {
		case <-c.ctx.Done():
			return
		case <-t.C:
			now := time.Now().UnixNano()
			var stale []*clientSession
			c.mu.Lock()
			for id, sess := range c.sessions {
				if now-atomic.LoadInt64(&sess.lastSeen) > int64(udpIdleTimeout) {
					stale = append(stale, sess)
					delete(c.sessions, id)
				}
			}
			c.mu.Unlock()
			for _, sess := range stale {
				sess.targetConn.Close()
				c.sendClose(sess)
			}
		}
	}
}
