package milter

import (
	"bufio"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/PhilAnderson1/SentinelMilter/internal/message"
)

type protocolPhase uint8

const (
	phaseNegotiation protocolPhase = iota
	phaseConnection
	phaseEnvelope
	phaseBody
)

type session struct {
	server    *Server
	conn      net.Conn
	reader    *bufio.Reader
	phase     protocolPhase
	connected bool
	message   *message.Message
}

func newSession(server *Server, conn net.Conn) *session {
	ss := &session{server: server, conn: conn, reader: bufio.NewReader(conn)}
	ss.resetMessage(phaseNegotiation)
	return ss
}

func (ss *session) run(ctx context.Context) {
	for {
		_ = ss.conn.SetDeadline(time.Now().Add(ss.server.cfg.Milter.Timeout.Value()))
		frame, bytesRead, err := readFrameProgress(ss.reader)
		if err != nil {
			if ss.handleReadError(ctx, bytesRead, err) {
				continue
			}
			return
		}
		if !ss.handleCommand(ctx, frame[0], frame[1:]) {
			return
		}
	}
}

func (ss *session) handleReadError(ctx context.Context, bytesRead int, err error) bool {
	if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
		if ctx.Err() != nil {
			return false
		}
		if bytesRead == 0 {
			ss.server.log.Debug("milter connection idle", "error", err)
			return true
		}
		ss.server.log.Warn("milter connection timed out during frame", "bytes_read", bytesRead, "error", err)
		return false
	}
	if err != io.EOF {
		ss.server.log.Warn("milter connection error", "error", err)
	}
	return false
}

func (ss *session) handleCommand(ctx context.Context, command byte, payload []byte) bool {
	// MACRO is explicitly allowed at any point for forward compatibility.
	if ss.phase == phaseNegotiation && command != commandOptionNegotiation && command != commandMacro && command != commandQuit {
		return ss.protocolError("milter command before option negotiation", "command", commandName(command))
	}

	switch command {
	case commandOptionNegotiation:
		return ss.negotiate(payload)
	case commandMacro:
		return true
	case commandAbort:
		ss.resetMessage(phaseConnection)
		return true
	case commandQuitConnection:
		ss.connected = false
		ss.resetMessage(phaseConnection)
		return true
	case commandConnect:
		if ss.phase != phaseConnection || ss.connected {
			return ss.protocolError("unexpected milter CONNECT command")
		}
		ss.connected = true
		return ss.sendContinue(command)
	case commandHelo:
		if ss.phase != phaseConnection {
			return ss.protocolError("milter HELO command during active message")
		}
		return ss.sendContinue(command)
	case commandMail:
		if ss.phase != phaseConnection {
			return ss.protocolError("milter MAIL command during active message")
		}
		ss.resetMessage(phaseEnvelope)
		return ss.sendContinue(command)
	case commandRecipient, commandData:
		if ss.phase != phaseEnvelope {
			return ss.protocolError("milter transaction command outside message", "command", commandName(command))
		}
		return ss.sendContinue(command)
	case commandUnknown:
		return ss.sendContinue(command)
	case commandHeader:
		return ss.addHeader(payload)
	case commandEndHeaders:
		if ss.phase != phaseEnvelope {
			return ss.protocolError("unexpected milter end-of-headers command")
		}
		ss.phase = phaseBody
		return ss.sendContinue(command)
	case commandBody:
		if ss.phase != phaseBody {
			return ss.protocolError("milter body outside body phase")
		}
		ss.message.AddBody(payload)
		return ss.sendContinue(command)
	case commandEndBody:
		return ss.finishMessage(ctx)
	case commandQuit:
		return false
	default:
		return ss.protocolError("unsupported milter command", "command", commandName(command))
	}
}

func (ss *session) negotiate(payload []byte) bool {
	if ss.phase != phaseNegotiation || len(payload) != optionPayloadBytes {
		return ss.protocolError("invalid milter option negotiation", "payload_bytes", len(payload), "repeated", ss.phase != phaseNegotiation)
	}
	version := binary.BigEndian.Uint32(payload[:4])
	if version < minimumProtocolVersion {
		return ss.protocolError("unsupported milter protocol version", "version", version)
	}
	if version > supportedProtocolVersion {
		version = supportedProtocolVersion
	}
	if !ss.send(commandOptionNegotiation, optionResponse(version)) {
		return false
	}
	ss.phase = phaseConnection
	return true
}

func (ss *session) addHeader(payload []byte) bool {
	if ss.phase != phaseEnvelope {
		return ss.protocolError("milter header outside header phase")
	}
	name, value, ok := parseHeader(payload)
	if !ok {
		return ss.protocolError("malformed milter header command")
	}
	ss.message.AddHeader(name, value)
	return ss.sendContinue(commandHeader)
}

func (ss *session) finishMessage(ctx context.Context) bool {
	if ss.phase != phaseBody {
		return ss.protocolError("unexpected milter end-of-body command")
	}
	_ = ss.conn.SetDeadline(time.Now().Add(ss.server.analysisTimeout()))
	result := ss.server.evaluate(ctx, ss.message)
	err := writeFrame(ss.conn, ss.server.encodeAction(result.selected))
	ss.server.logOutcome(ctx, ss.message, result, err == nil, err)
	if err != nil {
		return false
	}
	ss.resetMessage(phaseConnection)
	return true
}

func (ss *session) resetMessage(phase protocolPhase) {
	ss.message = message.New(ss.server.cfg.Milter.MaxMessageSize)
	ss.phase = phase
}

func (ss *session) sendContinue(command byte) bool {
	return ss.send(command, []byte{responseContinue})
}

func (ss *session) send(command byte, response []byte) bool {
	if err := writeFrame(ss.conn, response); err != nil {
		ss.server.log.Warn("cannot send milter response", "command", commandName(command), "error", err)
		return false
	}
	return true
}

func (ss *session) protocolError(message string, attrs ...any) bool {
	ss.server.log.Warn(message, attrs...)
	return false
}

func commandName(command byte) string {
	return fmt.Sprintf("0x%02x", command)
}
