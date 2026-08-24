package config

import (
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

type Duration time.Duration

func (d *Duration) UnmarshalText(text []byte) error {
	v, err := time.ParseDuration(string(text))
	if err != nil {
		return err
	}
	*d = Duration(v)
	return nil
}
func (d Duration) Value() time.Duration { return time.Duration(d) }

type Config struct {
	Mode    string        `yaml:"mode"`
	Milter  MilterConfig  `yaml:"milter"`
	AI      AIConfig      `yaml:"ai"`
	Policy  PolicyConfig  `yaml:"policy"`
	Logging LoggingConfig `yaml:"logging"`
}
type MilterConfig struct {
	Socket         string   `yaml:"socket"`
	Timeout        Duration `yaml:"timeout"`
	MaxMessageSize int64    `yaml:"max_message_size"`
	MaxConcurrent  int      `yaml:"max_concurrent"`
}
type AIConfig struct {
	Endpoint        string   `yaml:"endpoint"`
	APIKey          string   `yaml:"api_key"`
	APIKeyEnv       string   `yaml:"api_key_env"`
	Model           string   `yaml:"model"`
	DisableThinking bool     `yaml:"disable_thinking"`
	PromptFile      string   `yaml:"prompt_file"`
	Timeout         Duration `yaml:"timeout"`
	MaxBodyChars    int      `yaml:"max_body_chars"`
	SiteURL         string   `yaml:"site_url"`
	AppName         string   `yaml:"app_name"`
}
type PolicyConfig struct {
	RejectScore   float64 `yaml:"reject_score"`
	AIErrorAction string  `yaml:"ai_error_action"`
	RejectMessage string  `yaml:"reject_message"`
}
type LoggingConfig struct {
	Level          string `yaml:"level"`
	IncludeSubject bool   `yaml:"include_subject"`
}

func Load(path string) (Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return Config{}, err
	}
	c := defaults()
	dec := yaml.NewDecoder(strings.NewReader(string(b)))
	dec.KnownFields(true)
	if err := dec.Decode(&c); err != nil {
		return Config{}, err
	}
	if c.AI.APIKey == "" && c.AI.APIKeyEnv != "" {
		c.AI.APIKey = os.Getenv(c.AI.APIKeyEnv)
	}
	if err := c.Validate(); err != nil {
		return Config{}, err
	}
	return c, nil
}

func defaults() Config {
	return Config{Mode: "monitor", Milter: MilterConfig{Socket: "unix:/run/sentinelmilter/sentinelmilter.sock", Timeout: Duration(30 * time.Second), MaxMessageSize: 2 << 20, MaxConcurrent: 8}, AI: AIConfig{Endpoint: "https://openrouter.ai/api/v1/chat/completions", Timeout: Duration(15 * time.Second), MaxBodyChars: 50000, AppName: "SentinelMilter"}, Policy: PolicyConfig{RejectScore: .95, AIErrorAction: "accept", RejectMessage: "Message rejected as suspected spam or fraud"}, Logging: LoggingConfig{Level: "info", IncludeSubject: true}}
}

func (c Config) Validate() error {
	if c.Mode != "monitor" && c.Mode != "enforce" {
		return fmt.Errorf("mode must be monitor or enforce")
	}
	if c.Milter.Socket == "" || (c.Milter.MaxMessageSize < 1) || c.Milter.MaxConcurrent < 1 {
		return fmt.Errorf("invalid milter settings")
	}
	if c.AI.Endpoint == "" || c.AI.Model == "" || c.AI.PromptFile == "" {
		return fmt.Errorf("ai endpoint, model, and prompt_file are required")
	}
	if c.AI.APIKey == "" {
		return fmt.Errorf("ai api_key is empty (and api_key_env is unset or empty)")
	}
	if c.AI.Timeout.Value() <= 0 || c.AI.MaxBodyChars < 1 {
		return fmt.Errorf("invalid ai timeout or max_body_chars")
	}
	if c.Policy.RejectScore < 0 || c.Policy.RejectScore > 1 {
		return fmt.Errorf("policy.reject_score must be between 0 and 1")
	}
	if c.Policy.AIErrorAction != "accept" && c.Policy.AIErrorAction != "tempfail" {
		return fmt.Errorf("policy.ai_error_action must be accept or tempfail")
	}
	return nil
}

func (c Config) LogLevel() slog.Level {
	switch strings.ToLower(c.Logging.Level) {
	case "debug":
		return slog.LevelDebug
	case "warn":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}
