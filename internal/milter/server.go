package milter

import (
	"context"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/PhilAnderson1/SentinelMilter/internal/ai"
	"github.com/PhilAnderson1/SentinelMilter/internal/config"
	"github.com/PhilAnderson1/SentinelMilter/internal/message"
)

const analysisResponseMargin = 5 * time.Second

type Analyzer interface {
	Analyze(context.Context, string) (ai.Decision, error)
}

type evaluationResult struct {
	proposed       action
	selected       action
	classification string
	score          float64
	reasons        []string
	err            error
	latency        time.Duration
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
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				s.wg.Wait()
				return ctx.Err()
			}
			return err
		}
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			defer conn.Close()
			newSession(s, conn).run(ctx)
		}()
	}
}

// handle is retained as the single-connection entry point used by tests.
func (s *Server) handle(ctx context.Context, conn net.Conn) {
	newSession(s, conn).run(ctx)
}

func (s *Server) analysisTimeout() time.Duration {
	timeout := s.cfg.AI.Timeout.Value() + analysisResponseMargin
	if milterTimeout := s.cfg.Milter.Timeout.Value(); milterTimeout > timeout {
		return milterTimeout
	}
	return timeout
}

func (s *Server) evaluate(parent context.Context, msg *message.Message) evaluationResult {
	started := time.Now()
	ctx, cancel := context.WithTimeout(parent, s.cfg.AI.Timeout.Value())
	defer cancel()

	select {
	case s.slots <- struct{}{}:
		defer func() { <-s.slots }()
	case <-ctx.Done():
		return s.analysisFailure(ctx.Err(), started)
	}

	decision, err := s.analyzer.Analyze(ctx, msg.Prompt(s.cfg.AI.MaxBodyChars))
	if err != nil {
		return s.analysisFailure(err, started)
	}

	proposed, selected := s.applyPolicy(decision)
	return evaluationResult{
		proposed:       proposed,
		selected:       selected,
		classification: decision.Classification,
		score:          decision.Score,
		reasons:        decision.Reasons,
		latency:        time.Since(started),
	}
}

func (s *Server) applyPolicy(decision ai.Decision) (action, action) {
	proposed := actionAccept
	if (decision.Classification == "spam" || decision.Classification == "scam") && decision.Score >= s.cfg.Policy.RejectScore {
		proposed = actionReject
	}
	selected := proposed
	if s.cfg.Mode == "monitor" {
		selected = actionAccept
	}
	return proposed, selected
}

func (s *Server) analysisFailure(err error, started time.Time) evaluationResult {
	selected := actionAccept
	if s.cfg.Mode == "enforce" && s.cfg.Policy.AIErrorAction == "tempfail" {
		selected = actionTempfail
	}
	return evaluationResult{proposed: selected, selected: selected, err: err, latency: time.Since(started)}
}

func (s *Server) encodeAction(selected action) []byte {
	switch selected {
	case actionReject:
		return replyCode("550", "5.7.1", s.cfg.Policy.RejectMessage)
	case actionTempfail:
		return []byte{responseTempfail}
	default:
		return []byte{responseAccept}
	}
}

func (s *Server) logOutcome(ctx context.Context, msg *message.Message, result evaluationResult, sent bool, responseErr error) {
	if result.err != nil {
		attrs := []any{
			"message_id", msg.Header("Message-ID"), "mode", s.cfg.Mode,
			"actual_action", result.selected.String(), "error", result.err,
			"latency_ms", result.latency.Milliseconds(), "response_sent", sent,
		}
		if responseErr != nil {
			attrs = append(attrs, "response_error", responseErr)
		}
		s.log.Log(ctx, slog.LevelError, "message analysis failed", attrs...)
		return
	}

	attrs := []any{
		"message_id", msg.Header("Message-ID"), "mode", s.cfg.Mode,
		"classification", result.classification, "score", result.score,
		"reasons", result.reasons, "proposed_action", result.proposed.String(),
		"actual_action", result.selected.String(), "model", s.cfg.AI.Model,
		"latency_ms", result.latency.Milliseconds(), "truncated", msg.Truncated,
		"response_sent", sent,
	}
	if s.cfg.Logging.IncludeSubject {
		attrs = append(attrs, "subject", msg.Header("Subject"))
	}
	if responseErr != nil {
		attrs = append(attrs, "response_error", responseErr)
	}
	level := slog.LevelInfo
	if responseErr != nil {
		level = slog.LevelError
	}
	s.log.Log(ctx, level, "message classified", attrs...)
}
