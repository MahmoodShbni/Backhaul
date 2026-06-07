package utils

import (
	"net"
	"sync"
	"time"
)

// RelSession carries one TCP byte stream over the unreliable UDP tunnel.
//
// It is a compact, self-contained reliable-ordered protocol (a "TCP-lite"):
// byte-offset sequence numbers (uint64, so they never wrap), cumulative ACKs
// with advertised-window flow control, RTO-based retransmission with
// Jacobson/Karn RTT estimation, and 3-dup-ack fast retransmit. Close is modelled
// as a FIN that occupies a single sequence number, so it is delivered reliably
// and in order by the same machinery as data.
//
// One RelSession sits on each end of a session. The "local" side is the real TCP
// socket (the end-user connection on the server, the target connection on the
// client). Frames are emitted through the RelHooks callbacks, which the tunnel
// layer wires to the multiplexed UDP socket. The tunnel layer feeds incoming
// frames back in via OnData / OnAck / OnFin / OnReset.
type RelSession struct {
	local net.Conn
	hooks RelHooks

	mu      sync.Mutex
	sndCond *sync.Cond // signalled when the send window opens or the session ends
	dlvCond *sync.Cond // signalled when in-order data is ready or the session ends

	// sender side (bytes read from local, pushed to the peer)
	sndUna     uint64 // lowest unacked sequence (peer's cumulative ack)
	sndNxt     uint64 // next sequence to assign
	sndQ       []*relSeg
	peerWnd    uint32
	dupAck     int
	sndClosed  bool   // local read side hit EOF; FIN queued
	sndFinSeq  uint64 // sequence number of our FIN
	sndFinAckd bool

	// congestion control (AIMD with slow start) — paces sends so a full window
	// is never dumped onto the link at once, which would overflow socket buffers
	// and trigger a retransmit storm.
	cwnd          uint64
	ssthresh      uint64
	recoveryPoint uint64
	inRecovery    bool

	// rtt / rto
	srtt   time.Duration
	rttvar time.Duration
	rto    time.Duration

	// receiver side (bytes from the peer, delivered to local)
	rcvNxt     uint64
	rcvBuf     map[uint64][]byte // out-of-order segments, keyed by sequence
	rcvBytes   int               // bytes buffered (out-of-order + queued for delivery)
	dlvQ       [][]byte          // in-order bytes waiting to be written to local
	rcvFinSeq  int64             // sequence of peer FIN once known, else -1
	rcvClosed  bool              // peer FIN consumed in order
	rcvDone    bool              // all received bytes written and local write side closed
	rcvUnacked int               // received segments not yet acknowledged

	ackPending bool
	aborted    bool
	done       chan struct{}
	closeOnce  sync.Once

	maxInflight int
	maxRecvBuf  int
}

// RelHooks emit tunnel frames. Implementations must be safe for concurrent use.
type RelHooks struct {
	SendData  func(seq uint64, data []byte)
	SendAck   func(ack uint64, wnd uint32)
	SendFin   func(seq uint64)
	SendReset func()
}

type relSeg struct {
	seq    uint64
	data   []byte // nil for a FIN segment
	fin    bool
	sentAt time.Time
	xmit   int
}

const (
	relChunkSize  = 1200
	relMSS        = relChunkSize
	relInitCwnd   = 10 * relChunkSize // TCP-style initial window (IW10)
	relRTOMin     = 50 * time.Millisecond
	relRTOMax     = 10 * time.Second
	relRTOInit    = 200 * time.Millisecond
	relAckDelay   = 4 * time.Millisecond
	relTimerTick  = 5 * time.Millisecond
	relDefaultWin = 4 << 20 // 4 MiB send/recv window
)

var relChunkPool = sync.Pool{New: func() any { b := make([]byte, relChunkSize); return &b }}

func NewRelSession(local net.Conn, hooks RelHooks) *RelSession {
	rs := &RelSession{
		local:       local,
		hooks:       hooks,
		peerWnd:     relDefaultWin,
		rto:         relRTOInit,
		cwnd:        relInitCwnd,
		ssthresh:    relDefaultWin,
		rcvBuf:      make(map[uint64][]byte),
		rcvFinSeq:   -1,
		done:        make(chan struct{}),
		maxInflight: relDefaultWin,
		maxRecvBuf:  relDefaultWin,
	}
	rs.sndCond = sync.NewCond(&rs.mu)
	rs.dlvCond = sync.NewCond(&rs.mu)
	return rs
}

// Start launches the per-session goroutines.
func (rs *RelSession) Start() {
	go rs.senderLoop()
	go rs.deliverLoop()
	go rs.timerLoop()
}

// Done is closed when the session has fully torn down.
func (rs *RelSession) Done() <-chan struct{} { return rs.done }

// ---- sender: local -> peer --------------------------------------------------

func (rs *RelSession) senderLoop() {
	for {
		bp := relChunkPool.Get().(*[]byte)
		n, err := rs.local.Read(*bp)
		if n > 0 {
			seg := &relSeg{}
			seg.data = (*bp)[:n]
			rs.mu.Lock()
			// flow control: wait until the in-flight bytes fit the window
			for !rs.aborted {
				inflight := rs.sndNxt - rs.sndUna
				if inflight < rs.sendWindow() || inflight == 0 {
					break
				}
				rs.sndCond.Wait()
			}
			if rs.aborted {
				rs.mu.Unlock()
				return
			}
			seg.seq = rs.sndNxt
			seg.sentAt = time.Now()
			seg.xmit = 1
			rs.sndQ = append(rs.sndQ, seg)
			rs.sndNxt += uint64(n)
			rs.hooks.SendData(seg.seq, seg.data)
			rs.mu.Unlock()
		} else {
			relChunkPool.Put(bp)
		}
		if err != nil {
			rs.queueFIN()
			return
		}
	}
}

func (rs *RelSession) queueFIN() {
	rs.mu.Lock()
	if !rs.sndClosed {
		rs.sndClosed = true
		rs.sndFinSeq = rs.sndNxt
		seg := &relSeg{seq: rs.sndNxt, fin: true, sentAt: time.Now(), xmit: 1}
		rs.sndQ = append(rs.sndQ, seg)
		rs.sndNxt++
		rs.hooks.SendFin(seg.seq)
	}
	rs.mu.Unlock()
}

// OnAck processes a cumulative ack + advertised window from the peer.
func (rs *RelSession) OnAck(ack uint64, wnd uint32) {
	rs.mu.Lock()
	rs.peerWnd = wnd

	if ack > rs.sndUna {
		acked := ack - rs.sndUna
		rs.sndUna = ack
		rs.dupAck = 0
		// grow the congestion window: exponentially in slow start, linearly after.
		if rs.cwnd < rs.ssthresh {
			rs.cwnd += acked // slow start
			if rs.cwnd > rs.ssthresh {
				rs.cwnd = rs.ssthresh
			}
		} else {
			rs.cwnd += relMSS * acked / rs.cwnd // congestion avoidance
		}
		if rs.cwnd > uint64(rs.maxInflight) {
			rs.cwnd = uint64(rs.maxInflight)
		}
		if rs.inRecovery && ack >= rs.recoveryPoint {
			rs.inRecovery = false
		}
		// drop fully-acked segments, sampling RTT on first-transmission segments
		for len(rs.sndQ) > 0 {
			seg := rs.sndQ[0]
			end := seg.seq + segSpan(seg)
			if end > ack {
				break
			}
			if seg.xmit == 1 {
				rs.sampleRTT(time.Since(seg.sentAt))
			}
			if !seg.fin {
				rs.recycle(seg.data)
			}
			rs.sndQ = rs.sndQ[1:]
		}
		// NewReno: a partial ack during recovery means another segment in the
		// same window was lost — retransmit the new hole now, not at RTO.
		if rs.inRecovery && len(rs.sndQ) > 0 {
			rs.retransmitFront()
		}
		if rs.sndClosed && ack > rs.sndFinSeq {
			rs.sndFinAckd = true
		}
		rs.sndCond.Broadcast()
		rs.maybeDone()
	} else if ack == rs.sndUna && len(rs.sndQ) > 0 {
		rs.dupAck++
		if rs.dupAck == 3 && !rs.inRecovery {
			// fast retransmit + multiplicative decrease, once per loss event
			rs.enterRecovery()
			rs.retransmitFront()
		}
	}
	rs.mu.Unlock()
}

func (rs *RelSession) retransmitFront() {
	if len(rs.sndQ) == 0 {
		return
	}
	seg := rs.sndQ[0]
	seg.sentAt = time.Now()
	seg.xmit++
	if seg.fin {
		rs.hooks.SendFin(seg.seq)
	} else {
		rs.hooks.SendData(seg.seq, seg.data)
	}
}

// sendWindow is the number of in-flight bytes the sender may have outstanding:
// the smallest of the congestion window, the peer's advertised window and the
// local cap. Caller must hold rs.mu.
func (rs *RelSession) sendWindow() uint64 {
	w := rs.cwnd
	if uint64(rs.peerWnd) < w {
		w = uint64(rs.peerWnd)
	}
	if uint64(rs.maxInflight) < w {
		w = uint64(rs.maxInflight)
	}
	if w < relMSS {
		w = relMSS // always allow at least one segment in flight
	}
	return w
}

// enterRecovery applies the multiplicative decrease for a single loss event.
// Caller must hold rs.mu.
func (rs *RelSession) enterRecovery() {
	rs.ssthresh = rs.cwnd / 2
	if rs.ssthresh < 2*relMSS {
		rs.ssthresh = 2 * relMSS
	}
	rs.cwnd = rs.ssthresh
	rs.inRecovery = true
	rs.recoveryPoint = rs.sndNxt
}

func (rs *RelSession) sampleRTT(sample time.Duration) {
	if rs.srtt == 0 {
		rs.srtt = sample
		rs.rttvar = sample / 2
	} else {
		d := rs.srtt - sample
		if d < 0 {
			d = -d
		}
		rs.rttvar = (3*rs.rttvar + d) / 4
		rs.srtt = (7*rs.srtt + sample) / 8
	}
	rs.rto = rs.srtt + 4*rs.rttvar
	if rs.rto < relRTOMin {
		rs.rto = relRTOMin
	}
	if rs.rto > relRTOMax {
		rs.rto = relRTOMax
	}
}

// ---- receiver: peer -> local ------------------------------------------------

// OnData integrates a received data segment, delivering in-order bytes to local.
func (rs *RelSession) OnData(seq uint64, payload []byte) {
	rs.mu.Lock()
	defer rs.mu.Unlock()
	if rs.aborted {
		return
	}

	end := seq + uint64(len(payload))
	if end <= rs.rcvNxt { // entirely old
		rs.emitAckLocked()
		return
	}
	if seq < rs.rcvNxt { // trim already-received prefix
		off := rs.rcvNxt - seq
		payload = payload[off:]
		seq = rs.rcvNxt
	}

	if seq == rs.rcvNxt {
		rs.enqueueInOrder(payload)
		rs.absorbContiguous()
		// in-order: acknowledge every other segment (a delayed-ack safety net in
		// the timer covers the odd one out)
		rs.ackPending = true
		rs.rcvUnacked++
		if rs.rcvUnacked >= 2 {
			rs.emitAckLocked()
		}
	} else {
		// gap: buffer if it fits, and ack immediately so the sender sees a dup ack
		if rs.rcvBytes+len(payload) <= rs.maxRecvBuf {
			if _, ok := rs.rcvBuf[seq]; !ok {
				cp := rs.grab(payload)
				rs.rcvBuf[seq] = cp
				rs.rcvBytes += len(cp)
			}
		}
		rs.emitAckLocked()
	}
}

// OnFin records the peer FIN (one sequence number) and consumes it in order.
func (rs *RelSession) OnFin(seq uint64) {
	rs.mu.Lock()
	defer rs.mu.Unlock()
	if rs.aborted {
		return
	}
	rs.rcvFinSeq = int64(seq)
	rs.absorbContiguous()
	rs.emitAckLocked()
}

// OnReset aborts the session.
func (rs *RelSession) OnReset() { rs.abort() }

// enqueueInOrder appends bytes that start exactly at rcvNxt.
func (rs *RelSession) enqueueInOrder(p []byte) {
	cp := rs.grab(p)
	rs.dlvQ = append(rs.dlvQ, cp)
	rs.rcvBytes += len(cp)
	rs.rcvNxt += uint64(len(p))
	rs.dlvCond.Signal()
}

// absorbContiguous pulls buffered out-of-order segments (and the FIN) that have
// become contiguous with rcvNxt.
func (rs *RelSession) absorbContiguous() {
	for {
		if seg, ok := rs.rcvBuf[rs.rcvNxt]; ok {
			delete(rs.rcvBuf, rs.rcvNxt)
			rs.rcvBytes -= len(seg)
			rs.dlvQ = append(rs.dlvQ, seg)
			rs.rcvBytes += len(seg)
			rs.rcvNxt += uint64(len(seg))
			rs.dlvCond.Signal()
			continue
		}
		if rs.rcvFinSeq >= 0 && uint64(rs.rcvFinSeq) == rs.rcvNxt && !rs.rcvClosed {
			rs.rcvClosed = true
			rs.rcvNxt++ // FIN consumes one sequence number
			rs.dlvCond.Signal()
		}
		return
	}
}

func (rs *RelSession) deliverLoop() {
	for {
		rs.mu.Lock()
		for len(rs.dlvQ) == 0 && !rs.aborted && !(rs.rcvClosed && !rs.rcvDone) {
			rs.dlvCond.Wait()
		}
		if rs.aborted {
			rs.mu.Unlock()
			return
		}
		if len(rs.dlvQ) > 0 {
			chunk := rs.dlvQ[0]
			rs.dlvQ = rs.dlvQ[1:]
			rs.mu.Unlock()

			_, err := rs.local.Write(chunk)
			rs.recycle(chunk)

			rs.mu.Lock()
			rs.rcvBytes -= len(chunk)
			if err != nil {
				rs.mu.Unlock()
				rs.abort()
				return
			}
			rs.mu.Unlock()
			continue
		}
		// dlvQ drained and peer FIN consumed: half-close the local write side.
		rs.rcvDone = true
		if cw, ok := rs.local.(interface{ CloseWrite() error }); ok {
			cw.CloseWrite()
		}
		rs.maybeDone()
		rs.mu.Unlock()
		return
	}
}

// ---- acks, timers, teardown -------------------------------------------------

func (rs *RelSession) emitAckLocked() {
	rs.ackPending = false
	rs.rcvUnacked = 0
	free := rs.maxRecvBuf - rs.rcvBytes
	if free < 0 {
		free = 0
	}
	rs.hooks.SendAck(rs.rcvNxt, uint32(free))
}

func (rs *RelSession) timerLoop() {
	t := time.NewTicker(relTimerTick)
	defer t.Stop()
	var sinceAck time.Duration
	for {
		select {
		case <-rs.done:
			return
		case <-t.C:
			rs.mu.Lock()
			if rs.aborted {
				rs.mu.Unlock()
				return
			}
			// RTO: retransmit the oldest unacked segment if it is overdue
			if len(rs.sndQ) > 0 {
				if time.Since(rs.sndQ[0].sentAt) >= rs.rto {
					// timeout: severe congestion signal, collapse to slow start
					rs.ssthresh = rs.cwnd / 2
					if rs.ssthresh < 2*relMSS {
						rs.ssthresh = 2 * relMSS
					}
					rs.cwnd = relMSS
					rs.inRecovery = false
					rs.retransmitFront()
					rs.rto *= 2
					if rs.rto > relRTOMax {
						rs.rto = relRTOMax
					}
				}
			}
			// flush a delayed ack
			sinceAck += relTimerTick
			if rs.ackPending && sinceAck >= relAckDelay {
				sinceAck = 0
				rs.emitAckLocked()
			}
			rs.maybeDone()
			rs.mu.Unlock()
		}
	}
}

// maybeDone tears the session down once both directions are complete.
// Caller must hold rs.mu.
func (rs *RelSession) maybeDone() {
	if rs.sndClosed && rs.sndFinAckd && rs.rcvDone {
		rs.finishLocked()
	}
}

func (rs *RelSession) abort() {
	rs.mu.Lock()
	if !rs.aborted {
		rs.aborted = true
		if rs.hooks.SendReset != nil {
			rs.hooks.SendReset()
		}
	}
	rs.finishLocked()
	rs.mu.Unlock()
}

// Close tears the session down locally without sending a reset.
func (rs *RelSession) Close() {
	rs.mu.Lock()
	rs.aborted = true
	rs.finishLocked()
	rs.mu.Unlock()
}

// finishLocked performs idempotent teardown. Caller must hold rs.mu.
func (rs *RelSession) finishLocked() {
	rs.closeOnce.Do(func() {
		close(rs.done)
		rs.local.Close()
		rs.sndCond.Broadcast()
		rs.dlvCond.Broadcast()
	})
}

// ---- helpers ----------------------------------------------------------------

func segSpan(seg *relSeg) uint64 {
	if seg.fin {
		return 1
	}
	return uint64(len(seg.data))
}

// grab copies p into a buffer (pooled when it fits a chunk) owned by the session.
func (rs *RelSession) grab(p []byte) []byte {
	if len(p) <= relChunkSize {
		bp := relChunkPool.Get().(*[]byte)
		n := copy(*bp, p)
		return (*bp)[:n]
	}
	cp := make([]byte, len(p))
	copy(cp, p)
	return cp
}

func (rs *RelSession) recycle(b []byte) {
	if cap(b) == relChunkSize {
		full := b[:relChunkSize]
		relChunkPool.Put(&full)
	}
}
