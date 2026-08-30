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

	"github.com/PhilAnderson1/SentinelMilter/internal/ai"
	"github.com/PhilAnderson1/SentinelMilter/internal/config"
)

type fixedAnalyzer struct {
	decision ai.Decision
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

func TestCommandResponseRequirements(t *testing.T) {
	for _, cmd := range []byte{'C', 'H', 'M', 'R', 'T', 'N', 'U'} {
		t.Run(string(cmd), func(t *testing.T) {
			_, conn, _ := testServer(t, fixedAnalyzer{})
			defer conn.Close()
			if err := writeFrame(conn, []byte{cmd}); err != nil {
				t.Fatal(err)
			}
			expectFrame(t, conn, "c")
		})
	}
	for _, cmd := range []byte{'A', 'D', 'K'} {
		t.Run(string(cmd)+"_no_response", func(t *testing.T) {
			_, conn, _ := testServer(t, fixedAnalyzer{})
			defer conn.Close()
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
	payload[0] = 'O'
	binary.BigEndian.PutUint32(payload[1:5], 6)
	if err := writeFrame(conn, payload); err != nil {
		t.Fatal(err)
	}
	reply, err := readFrame(conn)
	if err != nil {
		t.Fatal(err)
	}
	if len(reply) != 13 || reply[0] != 'O' || binary.BigEndian.Uint32(reply[1:5]) != 6 {
		t.Fatalf("unexpected negotiation response: %q", reply)
	}
}

func TestAbortDoesNotDesynchronizeNextTransaction(t *testing.T) {
	_, conn, done := testServer(t, fixedAnalyzer{decision: ai.Decision{
		Classification: "scam", Score: 1, Reasons: []string{"test"},
	}})
	defer conn.Close()

	if err := writeFrame(conn, []byte{'A'}); err != nil {
		t.Fatal(err)
	}
	expectNoFrame(t, conn)

	for _, frame := range [][]byte{
		{'H'},
		append([]byte{'L'}, []byte("Subject\x00test\x00")...),
		append([]byte{'B'}, []byte("test body")...),
	} {
		if err := writeFrame(conn, frame); err != nil {
			t.Fatal(err)
		}
		expectFrame(t, conn, "c")
	}
	if err := writeFrame(conn, []byte{'E'}); err != nil {
		t.Fatal(err)
	}
	expectFrame(t, conn, "y550 5.7.1 blocked\x00")

	if err := writeFrame(conn, []byte{'Q'}); err != nil {
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
	if err := writeFrame(clientConn, []byte{'H'}); err != nil {
		t.Fatalf("write command after idle period: %v", err)
	}
	reply, err := readFrame(clientConn)
	if err != nil {
		t.Fatalf("read reply after idle period: %v", err)
	}
	if len(reply) != 1 || reply[0] != 'c' {
		t.Fatalf("unexpected reply: %q", reply)
	}

	if err := writeFrame(clientConn, []byte{'Q'}); err != nil {
		t.Fatalf("write quit: %v", err)
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("handler did not exit after quit")
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
