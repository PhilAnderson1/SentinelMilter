package ai

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/PhilAnderson1/SentinelMilter/internal/config"
)

func TestValidate(t *testing.T) {
	if err := validate(Decision{Classification: "scam", Score: .98, Reasons: []string{"impersonation"}}); err != nil {
		t.Fatal(err)
	}
	if err := validate(Decision{Classification: "evil", Score: .5}); err == nil {
		t.Fatal("expected invalid classification")
	}
	if err := validate(Decision{Classification: "spam", Score: 1.1}); err == nil {
		t.Fatal("expected invalid score")
	}
}

func TestDisableThinkingRequestFields(t *testing.T) {
	var body map[string]any
	transport := roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Error(err)
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     make(http.Header),
			Body:       io.NopCloser(strings.NewReader(`{"choices":[{"message":{"content":"{\"classification\":\"legitimate\",\"score\":0,\"reasons\":[]}"}}]}`)),
		}, nil
	})

	client := NewClient(config.AIConfig{
		Endpoint:        "http://llama.invalid/v1/chat/completions",
		APIKey:          "test-key",
		Model:           "qwen",
		DisableThinking: true,
		Timeout:         config.Duration(time.Second),
	}, "classify")
	client.http.Transport = transport
	if _, err := client.Analyze(context.Background(), "test message"); err != nil {
		t.Fatal(err)
	}
	if body["thinking_budget_tokens"] != float64(0) {
		t.Fatalf("thinking budget missing: %#v", body)
	}
	if _, exists := body["chat_template_kwargs"]; exists {
		t.Fatalf("legacy chat template setting must not be combined with reasoning budget: %#v", body)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}
