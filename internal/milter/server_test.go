package milter

import (
	"context"
	"io"
	"log/slog"
	"net"
	"testing"
	"time"

	"github.com/PhilAnderson1/SentinelMilter/internal/config"
)

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
