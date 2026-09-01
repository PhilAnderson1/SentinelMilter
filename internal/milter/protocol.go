package milter

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"net/netip"
	"strings"
	"unicode/utf8"
)

const (
	commandAbort             = byte('A')
	commandBody              = byte('B')
	commandConnect           = byte('C')
	commandMacro             = byte('D')
	commandEndBody           = byte('E')
	commandHelo              = byte('H')
	commandHeader            = byte('L')
	commandMail              = byte('M')
	commandEndHeaders        = byte('N')
	commandOptionNegotiation = byte('O')
	commandQuit              = byte('Q')
	commandRecipient         = byte('R')
	commandData              = byte('T')
	commandUnknown           = byte('U')
	commandQuitConnection    = byte('K')

	responseAccept   = byte('a')
	responseContinue = byte('c')
	responseTempfail = byte('t')
	responseReply    = byte('y')

	minimumProtocolVersion   = uint32(2)
	supportedProtocolVersion = uint32(6)
	optionPayloadBytes       = 12
	maxFrameBytes            = 16 << 20
	maxSMTPReplyBytes        = 510 // Excludes the terminating CRLF.
)

type action uint8

const (
	actionAccept action = iota
	actionReject
	actionTempfail
)

func (a action) String() string {
	switch a {
	case actionReject:
		return "reject"
	case actionTempfail:
		return "tempfail"
	default:
		return "accept"
	}
}

func optionResponse(version uint32) []byte {
	response := make([]byte, 13)
	response[0] = commandOptionNegotiation
	binary.BigEndian.PutUint32(response[1:5], version)
	// SentinelMilter neither modifies messages nor suppresses protocol stages.
	binary.BigEndian.PutUint32(response[5:9], 0)
	binary.BigEndian.PutUint32(response[9:13], 0)
	return response
}

func replyCode(code, enhanced, text string) []byte {
	clean := func(value string) string {
		value = strings.ReplaceAll(value, "\x00", "")
		value = strings.ReplaceAll(value, "\r", " ")
		return strings.ReplaceAll(value, "\n", " ")
	}
	reply := clean(code) + " " + clean(enhanced) + " " + clean(text)
	reply = truncateUTF8(reply, maxSMTPReplyBytes)
	reply = strings.ReplaceAll(reply, "%", "%%")
	return append([]byte{responseReply}, []byte(reply+"\x00")...)
}

func truncateUTF8(value string, maxBytes int) string {
	if len(value) <= maxBytes {
		return value
	}
	value = value[:maxBytes]
	for !utf8.ValidString(value) {
		value = value[:len(value)-1]
	}
	return value
}

func parseHeader(payload []byte) (string, string, bool) {
	name, remainder, found := bytes.Cut(payload, []byte{0})
	if !found || len(name) == 0 || len(remainder) == 0 || remainder[len(remainder)-1] != 0 {
		return "", "", false
	}
	value := remainder[:len(remainder)-1]
	if bytes.IndexByte(value, 0) >= 0 {
		return "", "", false
	}
	return string(name), string(value), true
}

func parseConnectIP(payload []byte) (netip.Addr, bool) {
	_, remainder, found := bytes.Cut(payload, []byte{0})
	if !found || len(remainder) < 4 {
		return netip.Addr{}, false
	}
	family := remainder[0]
	if family != '4' && family != '6' {
		return netip.Addr{}, false
	}
	addressBytes := remainder[3:]
	if len(addressBytes) < 2 || addressBytes[len(addressBytes)-1] != 0 || bytes.IndexByte(addressBytes[:len(addressBytes)-1], 0) >= 0 {
		return netip.Addr{}, false
	}
	addr, err := netip.ParseAddr(string(addressBytes[:len(addressBytes)-1]))
	if err != nil || (family == '4' && !addr.Is4() && !addr.Is4In6()) || (family == '6' && !addr.Is6()) {
		return netip.Addr{}, false
	}
	return addr.Unmap(), true
}

func readFrame(reader io.Reader) ([]byte, error) {
	frame, _, err := readFrameProgress(reader)
	return frame, err
}

func readFrameProgress(reader io.Reader) ([]byte, int, error) {
	var header [4]byte
	headerBytes, err := io.ReadFull(reader, header[:])
	if err != nil {
		return nil, headerBytes, err
	}
	length := binary.BigEndian.Uint32(header[:])
	if length == 0 || length > maxFrameBytes {
		return nil, headerBytes, fmt.Errorf("invalid frame length %d", length)
	}
	frame := make([]byte, length)
	frameBytes, err := io.ReadFull(reader, frame)
	return frame, headerBytes + frameBytes, err
}

func writeFrame(writer io.Writer, payload []byte) error {
	var header [4]byte
	binary.BigEndian.PutUint32(header[:], uint32(len(payload)))
	if err := writeAll(writer, header[:]); err != nil {
		return err
	}
	return writeAll(writer, payload)
}

func writeAll(writer io.Writer, payload []byte) error {
	for len(payload) > 0 {
		written, err := writer.Write(payload)
		if err != nil {
			return err
		}
		if written <= 0 {
			return io.ErrShortWrite
		}
		payload = payload[written:]
	}
	return nil
}
