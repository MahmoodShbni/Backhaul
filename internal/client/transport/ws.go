package transport

import (
	"bytes"
	"context"
	"crypto/rand"
	"fmt"
	"math/big"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/musix/backhaul/config"
	"github.com/musix/backhaul/internal/utils"
	"github.com/musix/backhaul/internal/utils/handlers"
	"github.com/musix/backhaul/internal/utils/network"
	"github.com/musix/backhaul/internal/web"

	"github.com/gorilla/websocket"
	"github.com/sirupsen/logrus"
)

type WsTransport struct {
	config          *WsConfig
	parentctx       context.Context
	ctx             context.Context
	cancel          context.CancelFunc
	logger          *logrus.Logger
	controlChannel  *websocket.Conn
	restartMutex    sync.Mutex
	usageMonitor    *web.Usage
	poolConnections int32
	loadConnections int32
	controlFlow     chan struct{}
}

type WsConfig struct {
	RemoteAddr     string
	Token          string
	SnifferLog     string
	TunnelStatus   string
	Nodelay        bool
	Sniffer        bool
	KeepAlive      time.Duration
	RetryInterval  time.Duration
	DialTimeOut    time.Duration
	ConnPoolSize   int
	WebPort        int
	Mode           config.TransportType
	AggressivePool bool
	EdgeIP         string
}

// cryptoRandInt returns a random int in [0, n)
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

// jitteredSleep sleeps base ± (jitterFrac * base)
func jitteredSleep(base time.Duration, jitterFrac float64) {
	jitter := time.Duration(float64(base) * jitterFrac)
	delta := time.Duration(cryptoRandInt(int(2*jitter+1))) - jitter
	d := base + delta
	if d < 500*time.Millisecond {
		d = 500 * time.Millisecond
	}
	time.Sleep(d)
}

// randPadding returns a random byte slice of length in [minLen, maxLen]
func randPadding(minLen, maxLen int) []byte {
	size := minLen + cryptoRandInt(maxLen-minLen+1)
	buf := make([]byte, size)
	rand.Read(buf)
	return buf
}

func NewWSClient(parentCtx context.Context, config *WsConfig, logger *logrus.Logger) *WsTransport {
	ctx, cancel := context.WithCancel(parentCtx)
	client := &WsTransport{
		config:          config,
		parentctx:       parentCtx,
		ctx:             ctx,
		cancel:          cancel,
		logger:          logger,
		controlChannel:  nil,
		usageMonitor:    web.NewDataStore(fmt.Sprintf(":%v", config.WebPort), ctx, config.SnifferLog, config.Sniffer, &config.TunnelStatus, logger),
		poolConnections: 0,
		loadConnections: 0,
		controlFlow:     make(chan struct{}, 100),
	}
	return client
}

func (c *WsTransport) Start() {
	if c.config.WebPort > 0 {
		go c.usageMonitor.Monitor()
	}
	c.config.TunnelStatus = fmt.Sprintf("Disconnected (%s)", c.config.Mode)
	go c.channelDialer()
}

func (c *WsTransport) Restart() {
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

	time.Sleep(2 * time.Second)

	ctx, cancel := context.WithCancel(c.parentctx)
	c.ctx = ctx
	c.cancel = cancel
	c.controlChannel = nil
	c.usageMonitor = web.NewDataStore(fmt.Sprintf(":%v", c.config.WebPort), ctx, c.config.SnifferLog, c.config.Sniffer, &c.config.TunnelStatus, c.logger)
	c.config.TunnelStatus = ""
	c.poolConnections = 0
	c.loadConnections = 0
	c.controlFlow = make(chan struct{}, 100)
	c.logger.SetLevel(level)

	go c.Start()
}

func (c *WsTransport) channelDialer() {
	c.logger.Info("attempting to establish a new websocket control channel connection")

	for {
		select {
		case <-c.ctx.Done():
			return
		default:
			tunnelWSConn, err := network.WebSocketDialer(c.ctx, c.config.RemoteAddr, c.config.EdgeIP, "/channel", c.config.DialTimeOut, c.config.KeepAlive, true, c.config.Token, c.config.Mode, 3, 0, 0)
			if err != nil {
				c.logger.Errorf("control channel dialer: %v", err)
				time.Sleep(c.config.RetryInterval)
				continue
			}
			c.controlChannel = tunnelWSConn
			c.logger.Info("control channel established successfully")
			c.config.TunnelStatus = fmt.Sprintf("Connected (%s)", c.config.Mode)

			go c.poolMaintainer()
			go c.channelHandler()
			return
		}
	}
}

func (c *WsTransport) poolMaintainer() {
	// Stagger initial pool fill — avoids burst of simultaneous connections
	// which is a strong fingerprint for DPI detection
	for i := 0; i < c.config.ConnPoolSize; i++ {
		go c.tunnelDialer()
		// Random delay 200–700ms between each connection
		delay := time.Duration(200+cryptoRandInt(500)) * time.Millisecond
		time.Sleep(delay)
	}

	a := 4
	b := 5
	x := 3
	y := 4.0

	if c.config.AggressivePool {
		c.logger.Info("aggressive pool management enabled")
		a = 1
		b = 2
		x = 0
		y = 0.75
	}

	tickerPool := time.NewTicker(time.Second * 1)
	defer tickerPool.Stop()
	tickerLoad := time.NewTicker(time.Second * 10)
	defer tickerLoad.Stop()

	newPoolSize := c.config.ConnPoolSize
	var poolConnectionsSum int32 = 0

	for {
		select {
		case <-c.ctx.Done():
			return

		case <-tickerPool.C:
			atomic.AddInt32(&poolConnectionsSum, atomic.LoadInt32(&c.poolConnections))

		case <-tickerLoad.C:
			loadConnections := (int(atomic.LoadInt32(&c.loadConnections)) + 9) / 10
			atomic.StoreInt32(&c.loadConnections, 0)

			poolConnectionsAvg := (int(atomic.LoadInt32(&poolConnectionsSum)) + 9) / 10
			atomic.StoreInt32(&poolConnectionsSum, 0)

			if (loadConnections + a) > poolConnectionsAvg*b {
				c.logger.Debugf("increasing pool size: %d -> %d", newPoolSize, newPoolSize+1)
				newPoolSize++
				// Stagger new pool connections too
				go func() {
					time.Sleep(time.Duration(cryptoRandInt(300)) * time.Millisecond)
					c.tunnelDialer()
				}()
			} else if float64(loadConnections+x) < float64(poolConnectionsAvg)*y && newPoolSize > c.config.ConnPoolSize {
				c.logger.Debugf("decreasing pool size: %d -> %d", newPoolSize, newPoolSize-1)
				newPoolSize--
				c.controlFlow <- struct{}{}
			}
		}
	}
}

func (c *WsTransport) channelHandler() {
	msgChan := make(chan byte, 1000)

	go func() {
		for {
			select {
			case <-c.ctx.Done():
				return
			default:
				_, msg, err := c.controlChannel.ReadMessage()
				if err != nil {
					if c.cancel != nil {
						c.logger.Error("failed to read from channel connection. ", err)
						go c.Restart()
					}
					return
				}
				// Only first byte is the signal; rest is padding — ignore it
				msgChan <- msg[0]
			}
		}
	}()

	for {
		select {
		case <-c.ctx.Done():
			_ = c.controlChannel.WriteMessage(websocket.BinaryMessage, []byte{utils.SG_Closed})
			return

		case msg := <-msgChan:
			switch msg {
			case utils.SG_Chan:
				atomic.AddInt32(&c.loadConnections, 1)
				select {
				case <-c.controlFlow:
				default:
					c.logger.Debug("channel signal received, initiating tunnel dialer")
					go c.tunnelDialer()
				}

			case utils.SG_HB:
				c.logger.Debug("heartbeat signal received successfully")
				// Reply with padded heartbeat too
				payload := append([]byte{utils.SG_HB}, randPadding(16, 96)...)
				err := c.controlChannel.WriteMessage(websocket.BinaryMessage, payload)
				if err != nil {
					c.logger.Errorf("failed to send heartbeat: %v", msg)
					go c.Restart()
					return
				}
				c.logger.Trace("heartbeat signal sent successfully")

			case utils.SG_Closed:
				c.logger.Warn("control channel has been closed by the server")
				go c.Restart()
				return

			default:
				c.logger.Errorf("unexpected response from channel: %v", msg)
				go c.Restart()
				return
			}
		}
	}
}

func (c *WsTransport) tunnelDialer() {
	c.logger.Debugf("initiating new websocket tunnel connection to address %s", c.config.RemoteAddr)

	tunnelConn, err := network.WebSocketDialer(c.ctx, c.config.RemoteAddr, c.config.EdgeIP, "/tunnel", c.config.DialTimeOut, c.config.KeepAlive, c.config.Nodelay, c.config.Token, c.config.Mode, 3, 1024*1024, 1024*1024)
	if err != nil {
		c.logger.Errorf("tunnel server dialer: %v", err)
		return
	}

	atomic.AddInt32(&c.poolConnections, 1)

	for {
		select {
		case <-c.ctx.Done():
			return
		default:
			_, remoteAddrBytes, err := tunnelConn.ReadMessage()
			if err != nil {
				c.logger.Debugf("unable to get port from websocket connection %s: %v", tunnelConn.RemoteAddr().String(), err)
				tunnelConn.Close()
				atomic.AddInt32(&c.poolConnections, -1)
				return
			}

			// Check first byte only — server now sends padded pings
			if len(remoteAddrBytes) > 0 && remoteAddrBytes[0] == utils.SG_Ping {
				c.logger.Trace("ping received from the server")
				continue
			}

			// Legacy exact-match kept as fallback (for compatibility with unpatched servers)
			if bytes.Equal(remoteAddrBytes, []byte{utils.SG_Ping}) {
				c.logger.Trace("ping received from the server (legacy)")
				continue
			}

			atomic.AddInt32(&c.poolConnections, -1)

			remoteAddr := string(remoteAddrBytes)

			port, resolvedAddr, err := network.ResolveRemoteAddr(remoteAddr)
			if err != nil {
				c.logger.Infof("failed to resolve remote port: %v", err)
				tunnelConn.Close()
				return
			}

			c.localDialer(tunnelConn, resolvedAddr, port)
			return
		}
	}
}

func (c *WsTransport) localDialer(tunnelCon *websocket.Conn, remoteAddr string, port int) {
	var sendBuf, recvBuf int

	if strings.Contains(remoteAddr, "127.0.0.1") {
		sendBuf = 32 * 1024
		recvBuf = 32 * 1024
	} else {
		sendBuf = 0
		recvBuf = 0
	}

	localConnection, err := network.TcpDialer(c.ctx, remoteAddr, "", c.config.DialTimeOut, c.config.KeepAlive, true, 1, recvBuf, sendBuf, 0)
	if err != nil {
		c.logger.Errorf("local dialer: %v", err)
		tunnelCon.Close()
		return
	}
	c.logger.Debugf("connected to local address %s successfully", remoteAddr)

	handlers.WSConnectionHandler(c.ctx, tunnelCon, localConnection, c.logger, c.usageMonitor, int(port), c.config.Sniffer)
}
