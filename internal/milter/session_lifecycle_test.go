package milter

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/PhilAnderson1/MilterGuard/internal/ai"
	"github.com/PhilAnderson1/MilterGuard/internal/config"
)

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
	_, conn, done := testServer(t, fixedAnalyzer{decision: ai.Decision{Classification: "scam", Score: 1, Reasons: []string{"test"}}})
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
	for _, frame := range [][]byte{{commandHelo}, {commandMail}, append([]byte{commandHeader}, []byte("Subject\x00test\x00")...), {commandEndHeaders}, append([]byte{commandBody}, []byte("test body")...)} {
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
	var logOutput bytes.Buffer
	server := &Server{cfg: config.Config{Milter: config.MilterConfig{Timeout: config.Duration(20 * time.Millisecond)}}, log: slog.New(slog.NewTextHandler(&logOutput, &slog.HandlerOptions{Level: slog.LevelDebug}))}
	done := make(chan struct{})
	go func() { defer close(done); defer serverConn.Close(); server.handle(context.Background(), serverConn) }()
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
	logs := logOutput.String()
	for _, wanted := range []string{`msg="milter connection remains idle"`, `idle_interval=20ms`, `local_addr=pipe`, `remote_addr=pipe`} {
		if !strings.Contains(logs, wanted) {
			t.Errorf("idle log does not contain %q: %s", wanted, logs)
		}
	}
	if strings.Contains(logs, "error=") {
		t.Errorf("normal idle log contains an error field: %s", logs)
	}
}

func TestContextCancellationClosesIdleConnectionImmediately(t *testing.T) {
	serverConn, clientConn := net.Pipe()
	defer clientConn.Close()
	var logOutput bytes.Buffer
	server := &Server{cfg: config.Config{Milter: config.MilterConfig{Timeout: config.Duration(time.Hour)}}, log: slog.New(slog.NewTextHandler(&logOutput, nil))}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); server.handle(ctx, serverConn) }()
	negotiate(t, clientConn)
	started := time.Now()
	cancel()
	select {
	case <-done:
		if elapsed := time.Since(started); elapsed > 250*time.Millisecond {
			t.Fatalf("cancelled idle connection took %s to close", elapsed)
		}
	case <-time.After(time.Second):
		t.Fatal("idle connection remained blocked after context cancellation")
	}
	if logOutput.Len() != 0 {
		t.Fatalf("normal shutdown produced a connection warning: %s", logOutput.String())
	}
}

func TestHandleClosesAfterPartialFrameTimeout(t *testing.T) {
	serverConn, clientConn := net.Pipe()
	defer clientConn.Close()
	server := &Server{cfg: config.Config{Milter: config.MilterConfig{Timeout: config.Duration(20 * time.Millisecond)}}, log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	done := make(chan struct{})
	go func() { defer close(done); defer serverConn.Close(); server.handle(context.Background(), serverConn) }()
	if _, err := clientConn.Write([]byte{0, 0}); err != nil {
		t.Fatal(err)
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("handler retained a connection after a partial-frame timeout")
	}
}
