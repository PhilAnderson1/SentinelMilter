package milter

import (
	"bufio"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/PhilAnderson1/SentinelMilter/internal/ai"
	"github.com/PhilAnderson1/SentinelMilter/internal/config"
	"github.com/PhilAnderson1/SentinelMilter/internal/message"
)

const maxFrame = 16 << 20
const analysisResponseMargin = 5 * time.Second

type Analyzer interface {
	Analyze(context.Context, string) (ai.Decision, error)
}
type Server struct {
	cfg      config.Config
	analyzer Analyzer
	log      *slog.Logger
	slots    chan struct{}
	wg       sync.WaitGroup
}

func NewServer(cfg config.Config, analyzer Analyzer, log *slog.Logger) *Server {
	return &Server{cfg: cfg, analyzer: analyzer, log: log, slots: make(chan struct{}, cfg.Milter.MaxConcurrent)}
}

func (s *Server) Serve(ctx context.Context, ln net.Listener) error {
	go func() { <-ctx.Done(); _ = ln.Close() }()
	for {
		c, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				s.wg.Wait()
				return ctx.Err()
			}
			return err
		}
		s.wg.Add(1)
		go func() { defer s.wg.Done(); defer c.Close(); s.handle(ctx, c) }()
	}
}

func (s *Server) handle(parent context.Context, c net.Conn) {
	r := bufio.NewReader(c)
	var msg = *message.New(s.cfg.Milter.MaxMessageSize)
	for {
		_ = c.SetDeadline(time.Now().Add(s.cfg.Milter.Timeout.Value()))
		frame, err := readFrame(r)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				if parent.Err() != nil {
					return
				}
				s.log.Debug("milter connection idle", "error", err)
				continue
			}
			if err != io.EOF {
				s.log.Warn("milter connection error", "error", err)
			}
			return
		}
		if len(frame) == 0 {
			return
		}
		cmd, payload := frame[0], frame[1:]
		switch cmd {
		case 'O': // option negotiation
			version := uint32(6)
			if len(payload) >= 4 {
				version = binary.BigEndian.Uint32(payload[:4])
				if version > 6 {
					version = 6
				}
			}
			out := make([]byte, 13)
			out[0] = 'O'
			binary.BigEndian.PutUint32(out[1:5], version)
			binary.BigEndian.PutUint32(out[5:9], 0)
			binary.BigEndian.PutUint32(out[9:13], 0)
			if writeFrame(c, out) != nil {
				return
			}
		case 'D': // macro definitions have no response
		case 'L':
			parts := splitNull(payload)
			if len(parts) >= 2 {
				msg.AddHeader(parts[0], parts[1])
			}
			if writeFrame(c, []byte{'c'}) != nil {
				return
			}
		case 'B':
			msg.AddBody(payload)
			if writeFrame(c, []byte{'c'}) != nil {
				return
			}
		case 'E':
			// AI analysis may legitimately take longer than the ordinary milter
			// I/O timeout. Leave a small margin to send the milter response after
			// the AI request itself reaches its deadline.
			_ = c.SetDeadline(time.Now().Add(s.analysisTimeout()))
			response := s.evaluate(parent, &msg)
			if writeFrame(c, response) != nil {
				return
			}
			msg = *message.New(s.cfg.Milter.MaxMessageSize)
		case 'A':
			msg = *message.New(s.cfg.Milter.MaxMessageSize)
			if writeFrame(c, []byte{'c'}) != nil {
				return
			}
		case 'Q':
			return
		default:
			if writeFrame(c, []byte{'c'}) != nil {
				return
			}
		}
	}
}

func (s *Server) analysisTimeout() time.Duration {
	timeout := s.cfg.AI.Timeout.Value() + analysisResponseMargin
	if milterTimeout := s.cfg.Milter.Timeout.Value(); milterTimeout > timeout {
		return milterTimeout
	}
	return timeout
}

func (s *Server) evaluate(parent context.Context, msg *message.Message) []byte {
	start := time.Now()
	ctx, cancel := context.WithTimeout(parent, s.cfg.AI.Timeout.Value())
	defer cancel()
	select {
	case s.slots <- struct{}{}:
		defer func() { <-s.slots }()
	case <-ctx.Done():
		return s.onError(msg, ctx.Err(), start)
	}
	d, err := s.analyzer.Analyze(ctx, msg.Prompt(s.cfg.AI.MaxBodyChars))
	if err != nil {
		return s.onError(msg, err, start)
	}
	proposed := "accept"
	if (d.Classification == "spam" || d.Classification == "scam") && d.Score >= s.cfg.Policy.RejectScore {
		proposed = "reject"
	}
	actual := proposed
	if s.cfg.Mode == "monitor" {
		actual = "accept"
	}
	attrs := []any{"message_id", msg.Header("Message-ID"), "mode", s.cfg.Mode, "classification", d.Classification, "score", d.Score, "reasons", d.Reasons, "proposed_action", proposed, "actual_action", actual, "model", s.cfg.AI.Model, "latency_ms", time.Since(start).Milliseconds(), "truncated", msg.Truncated}
	if s.cfg.Logging.IncludeSubject {
		attrs = append(attrs, "subject", msg.Header("Subject"))
	}
	s.log.Info("message classified", attrs...)
	if actual == "reject" {
		return replyCode("550", "5.7.1", s.cfg.Policy.RejectMessage)
	}
	return []byte{'a'}
}
func (s *Server) onError(msg *message.Message, err error, start time.Time) []byte {
	actual := "accept"
	if s.cfg.Mode == "enforce" && s.cfg.Policy.AIErrorAction == "tempfail" {
		actual = "tempfail"
	}
	s.log.Error("message analysis failed", "message_id", msg.Header("Message-ID"), "mode", s.cfg.Mode, "actual_action", actual, "error", err, "latency_ms", time.Since(start).Milliseconds())
	if actual == "tempfail" {
		return []byte{'t'}
	}
	return []byte{'a'}
}
func replyCode(code, enhanced, text string) []byte {
	clean := func(v string) string {
		v = strings.ReplaceAll(v, "\x00", "")
		v = strings.ReplaceAll(v, "\r", " ")
		return strings.ReplaceAll(v, "\n", " ")
	}
	// SMFIR_REPLYCODE is one NUL-terminated SMTP reply string: the three-byte
	// status code, a space, and the response text. Percent signs must be doubled
	// because some MTAs process the text as a printf-style format string.
	reply := clean(code) + " " + clean(enhanced) + " " + clean(text)
	reply = strings.ReplaceAll(reply, "%", "%%")
	return append([]byte{'y'}, []byte(reply+"\x00")...)
}
func splitNull(p []byte) []string {
	raw := strings.Split(string(p), "\x00")
	out := make([]string, 0, len(raw))
	for _, v := range raw {
		if v != "" {
			out = append(out, v)
		}
	}
	return out
}
func readFrame(r io.Reader) ([]byte, error) {
	var h [4]byte
	if _, err := io.ReadFull(r, h[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(h[:])
	if n == 0 || n > maxFrame {
		return nil, fmt.Errorf("invalid frame length %d", n)
	}
	b := make([]byte, n)
	_, err := io.ReadFull(r, b)
	return b, err
}
func writeFrame(w io.Writer, p []byte) error {
	var h [4]byte
	binary.BigEndian.PutUint32(h[:], uint32(len(p)))
	if _, err := w.Write(h[:]); err != nil {
		return err
	}
	_, err := w.Write(p)
	return err
}
