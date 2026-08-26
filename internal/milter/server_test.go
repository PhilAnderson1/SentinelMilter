package milter

import (
	"testing"
	"time"

	"github.com/PhilAnderson1/SentinelMilter/internal/config"
)

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
