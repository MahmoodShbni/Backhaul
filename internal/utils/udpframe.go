package utils

import "encoding/binary"

// UDP tunnel data-plane frame opcodes.
//
// These live entirely on the UDP data plane and are independent of the SG_*
// control-channel signals (which travel on a separate TCP connection). A single
// persistent, multiplexed UDP tunnel carries every end-user flow; each datagram
// starts with a fixed header so the peer can route it to the right session
// without any per-flow handshake.
const (
	UDPOpKeepalive byte = 0x01 // client -> server: register/refresh an authenticated tunnel source address
	UDPOpNew       byte = 0x02 // server -> client: open a new session toward a target ([2B targetLen][target][payload])
	UDPOpData      byte = 0x03 // both directions: payload for an existing session
	UDPOpClose     byte = 0x04 // both directions: tear a session down
)

// UDPHeaderSize is the size of the common frame header: [op:1][sessionID:8].
const UDPHeaderSize = 1 + 8

// PutUDPHeader writes the opcode and session id into the first UDPHeaderSize
// bytes of buf. The caller must guarantee len(buf) >= UDPHeaderSize.
func PutUDPHeader(buf []byte, op byte, sessionID uint64) {
	buf[0] = op
	binary.BigEndian.PutUint64(buf[1:], sessionID)
}

// ParseUDPHeader reads the opcode and session id from the front of buf.
// The caller must guarantee len(buf) >= UDPHeaderSize.
func ParseUDPHeader(buf []byte) (op byte, sessionID uint64) {
	return buf[0], binary.BigEndian.Uint64(buf[1:])
}
