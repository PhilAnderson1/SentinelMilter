package milter

import (
	"context"
	"encoding/binary"
	"io"
	"log/slog"
	"net"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/PhilAnderson1/SentinelMilter/internal/ai"
	"github.com/PhilAnderson1/SentinelMilter/internal/config"
)

type fixedAnalyzer struct {
	decision ai.Decision
}

type shortWriter struct {
	max int
	b   strings.Builder
}

func (w *shortWriter) Write(p []byte) (int, error) {
	if len(p) > w.max {
		p = p[:w.max]
	}
	return w.b.Write(p)
}

func (a fixedAnalyzer) Analyze(context.Context, string) (ai.Decision, error) {
	return a.decision, nil
}

func testServer(t *testing.T, analyzer Analyzer) (*Server, net.Conn, <-chan struct{}) {
	t.Helper()
	serverConn, clientConn := net.Pipe()
	cfg := config.Config{
		Mode:   "enforce",
		Milter: config.MilterConfig{Timeout: config.Duration(200 * time.Millisecond), MaxMessageSize: 1024, MaxConcurrent: 1},
		AI:     config.AIConfig{Timeout: config.Duration(time.Second), MaxBodyChars: 1024},
		Policy: config.PolicyConfig{RejectScore: 0.9, AIErrorAction: "accept", RejectMessage: "blocked"},
	}
	s := NewServer(cfg, analyzer, slog.New(slog.NewTextHandler(io.Discard, nil)))
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer serverConn.Close()
		s.handle(context.Background(), serverConn)
	}()
	return s, clientConn, done
}

func expectNoFrame(t *testing.T, conn net.Conn) {
	t.Helper()
	if err := conn.SetReadDeadline(time.Now().Add(30 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	_, err := readFrame(conn)
	if netErr, ok := err.(net.Error); !ok || !netErr.Timeout() {
		t.Fatalf("expected no response, got %v", err)
	}
	if err := conn.SetReadDeadline(time.Time{}); err != nil {
		t.Fatal(err)
	}
}

func expectFrame(t *testing.T, conn net.Conn, want string) {
	t.Helper()
	got, err := readFrame(conn)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	if string(got) != want {
		t.Fatalf("response = %q, want %q", got, want)
	}
}

func negotiate(t *testing.T, conn net.Conn) {
	t.Helper()
	payload := make([]byte, 13)
	payload[0] = commandOptionNegotiation
	binary.BigEndian.PutUint32(payload[1:5], 6)
	if err := writeFrame(conn, payload); err != nil {
		t.Fatal(err)
	}
	reply, err := readFrame(conn)
	if err != nil || len(reply) != 13 || reply[0] != commandOptionNegotiation {
		t.Fatalf("option negotiation failed: reply=%q err=%v", reply, err)
	}
}

func sendContinueFrames(t *testing.T, conn net.Conn, frames ...[]byte) {
	t.Helper()
	for _, frame := range frames {
		if err := writeFrame(conn, frame); err != nil {
			t.Fatal(err)
		}
		expectFrame(t, conn, string([]byte{responseContinue}))
	}
}

func TestCommandResponseRequirements(t *testing.T) {
	for _, cmd := range []byte{commandConnect, commandHelo, commandMail, commandRecipient, commandData, commandEndHeaders, commandUnknown} {
		t.Run(string(cmd), func(t *testing.T) {
			_, conn, _ := testServer(t, fixedAnalyzer{})
			defer conn.Close()
			negotiate(t, conn)
			if cmd == commandRecipient || cmd == commandData || cmd == commandEndHeaders {
				if err := writeFrame(conn, []byte{commandMail}); err != nil {
					t.Fatal(err)
				}
				expectFrame(t, conn, "c")
			}
			if err := writeFrame(conn, []byte{cmd}); err != nil {
				t.Fatal(err)
			}
			expectFrame(t, conn, "c")
		})
	}
	for _, cmd := range []byte{commandAbort, commandMacro, commandQuitConnection} {
		t.Run(string(cmd)+"_no_response", func(t *testing.T) {
			_, conn, _ := testServer(t, fixedAnalyzer{})
			defer conn.Close()
			negotiate(t, conn)
			if err := writeFrame(conn, []byte{cmd}); err != nil {
				t.Fatal(err)
			}
			expectNoFrame(t, conn)
		})
	}
}

func TestOptionNegotiationResponse(t *testing.T) {
	_, conn, _ := testServer(t, fixedAnalyzer{})
	defer conn.Close()
	payload := make([]byte, 13)
	payload[0] = commandOptionNegotiation
	binary.BigEndian.PutUint32(payload[1:5], 6)
	if err := writeFrame(conn, payload); err != nil {
		t.Fatal(err)
	}
	reply, err := readFrame(conn)
	if err != nil {
		t.Fatal(err)
	}
	if len(reply) != 13 || reply[0] != commandOptionNegotiation || binary.BigEndian.Uint32(reply[1:5]) != 6 {
		t.Fatalf("unexpected negotiation response: %q", reply)
	}
}

func TestMalformedOptionNegotiationClosesConnection(t *testing.T) {
	_, conn, done := testServer(t, fixedAnalyzer{})
	defer conn.Close()
	if err := writeFrame(conn, []byte{commandOptionNegotiation, 0, 0, 0, 6}); err != nil {
		t.Fatal(err)
	}
	if _, err := readFrame(conn); err == nil {
		t.Fatal("expected malformed negotiation to close the connection")
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("handler did not exit after malformed negotiation")
	}
}

func TestProtocolRejectsInvalidSequences(t *testing.T) {
	tests := []struct {
		name    string
		setup   [][]byte
		invalid []byte
	}{
		{name: "header before mail", invalid: []byte{commandHeader}},
		{name: "body before end headers", setup: [][]byte{{commandMail}}, invalid: []byte{commandBody}},
		{name: "end body before end headers", setup: [][]byte{{commandMail}}, invalid: []byte{commandEndBody}},
		{name: "helo during message", setup: [][]byte{{commandMail}}, invalid: []byte{commandHelo}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, conn, done := testServer(t, fixedAnalyzer{})
			defer conn.Close()
			negotiate(t, conn)
			sendContinueFrames(t, conn, test.setup...)
			if err := writeFrame(conn, test.invalid); err != nil {
				t.Fatal(err)
			}
			if _, err := readFrame(conn); err == nil {
				t.Fatal("expected invalid sequence to close the connection")
			}
			select {
			case <-done:
			case <-time.After(time.Second):
				t.Fatal("handler did not exit after invalid sequence")
			}
		})
	}
}

func TestAbortDoesNotDesynchronizeNextTransaction(t *testing.T) {
	_, conn, done := testServer(t, fixedAnalyzer{decision: ai.Decision{
		Classification: "scam", Score: 1, Reasons: []string{"test"},
	}})
	defer conn.Close()
	negotiate(t, conn)
	if err := writeFrame(conn, []byte{commandMail}); err != nil {
		t.Fatal(err)
	}
	expectFrame(t, conn, "c")

	if err := writeFrame(conn, []byte{commandAbort}); err != nil {
		t.Fatal(err)
	}
	expectNoFrame(t, conn)

	for _, frame := range [][]byte{
		{commandHelo},
		{commandMail},
		append([]byte{commandHeader}, []byte("Subject\x00test\x00")...),
		{commandEndHeaders},
		append([]byte{commandBody}, []byte("test body")...),
	} {
		if err := writeFrame(conn, frame); err != nil {
			t.Fatal(err)
		}
		expectFrame(t, conn, "c")
	}
	if err := writeFrame(conn, []byte{commandEndBody}); err != nil {
		t.Fatal(err)
	}
	expectFrame(t, conn, "y550 5.7.1 blocked\x00")

	if err := writeFrame(conn, []byte{commandQuit}); err != nil {
		t.Fatal(err)
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("handler did not exit after quit")
	}
}

func TestUnsupportedCommandClosesConnection(t *testing.T) {
	_, conn, done := testServer(t, fixedAnalyzer{})
	defer conn.Close()
	if err := writeFrame(conn, []byte{'Z'}); err != nil {
		t.Fatal(err)
	}
	if _, err := readFrame(conn); err == nil || !strings.Contains(err.Error(), "EOF") {
		t.Fatalf("expected connection close, got %v", err)
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("handler did not exit for unsupported command")
	}
}

func TestHandleKeepsConnectionAfterIdleTimeout(t *testing.T) {
	serverConn, clientConn := net.Pipe()
	defer clientConn.Close()

	s := &Server{
		cfg: config.Config{
			Milter: config.MilterConfig{Timeout: config.Duration(20 * time.Millisecond)},
		},
		log: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer serverConn.Close()
		s.handle(context.Background(), serverConn)
	}()

	// Wait through several idle deadlines before sending a command. Postfix
	// keeps milter connections open and may reuse them after an idle period.
	time.Sleep(75 * time.Millisecond)
	negotiate(t, clientConn)
	if err := writeFrame(clientConn, []byte{commandHelo}); err != nil {
		t.Fatalf("write command after idle period: %v", err)
	}
	reply, err := readFrame(clientConn)
	if err != nil {
		t.Fatalf("read reply after idle period: %v", err)
	}
	if len(reply) != 1 || reply[0] != 'c' {
		t.Fatalf("unexpected reply: %q", reply)
	}

	if err := writeFrame(clientConn, []byte{commandQuit}); err != nil {
		t.Fatalf("write quit: %v", err)
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("handler did not exit after quit")
	}
}

func TestHandleClosesAfterPartialFrameTimeout(t *testing.T) {
	serverConn, clientConn := net.Pipe()
	defer clientConn.Close()
	s := &Server{cfg: config.Config{Milter: config.MilterConfig{Timeout: config.Duration(20 * time.Millisecond)}}, log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer serverConn.Close()
		s.handle(context.Background(), serverConn)
	}()

	if _, err := clientConn.Write([]byte{0, 0}); err != nil {
		t.Fatal(err)
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("handler retained a connection after a partial-frame timeout")
	}
}

func TestAnalysisTimeoutUsesAITimeoutWithResponseMargin(t *testing.T) {
	s := &Server{cfg: config.Config{
		Milter: config.MilterConfig{Timeout: config.Duration(30 * time.Second)},
		AI:     config.AIConfig{Timeout: config.Duration(60 * time.Second)},
	}}
	if got, want := s.analysisTimeout(), 65*time.Second; got != want {
		t.Fatalf("analysis timeout = %v, want %v", got, want)
	}
}

func TestAnalysisTimeoutPreservesLongerMilterTimeout(t *testing.T) {
	s := &Server{cfg: config.Config{
		Milter: config.MilterConfig{Timeout: config.Duration(90 * time.Second)},
		AI:     config.AIConfig{Timeout: config.Duration(60 * time.Second)},
	}}
	if got, want := s.analysisTimeout(), 90*time.Second; got != want {
		t.Fatalf("analysis timeout = %v, want %v", got, want)
	}
}

func TestReplyCodeWireFormat(t *testing.T) {
	got := replyCode("550", "5.7.1", "Message rejected: 100% spam\ntry again")
	want := []byte("y550 5.7.1 Message rejected: 100%% spam try again\x00")
	if string(got) != string(want) {
		t.Fatalf("reply code = %q, want %q", got, want)
	}
}

func TestReplyCodeLimitsSMTPLineAndPreservesUTF8(t *testing.T) {
	got := replyCode("550", "5.7.1", strings.Repeat("é", 600))
	line := got[1 : len(got)-1]
	smtpLine := strings.ReplaceAll(string(line), "%%", "%")
	if len(smtpLine) > maxSMTPReplyBytes {
		t.Fatalf("SMTP reply is %d bytes, limit is %d", len(smtpLine), maxSMTPReplyBytes)
	}
	if !utf8.ValidString(smtpLine) {
		t.Fatal("SMTP reply was truncated inside a UTF-8 sequence")
	}
}

func TestParseHeaderPreservesEmptyValue(t *testing.T) {
	name, value, ok := parseHeader([]byte("X-Empty\x00\x00"))
	if !ok || name != "X-Empty" || value != "" {
		t.Fatalf("parseHeader = %q, %q, %v", name, value, ok)
	}
}

func TestParseHeaderRejectsTrailingData(t *testing.T) {
	if _, _, ok := parseHeader([]byte("Subject\x00test\x00extra")); ok {
		t.Fatal("accepted header payload with trailing data")
	}
}

func TestWriteFrameHandlesShortWrites(t *testing.T) {
	w := &shortWriter{max: 2}
	if err := writeFrame(w, []byte("hello")); err != nil {
		t.Fatal(err)
	}
	want := "\x00\x00\x00\x05hello"
	if w.b.String() != want {
		t.Fatalf("framed output = %q, want %q", w.b.String(), want)
	}
}
