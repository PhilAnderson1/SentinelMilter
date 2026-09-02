package config

import (
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

const MTAHostnameAuthservID = "$mta_hostname"

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
	Mode                   string                       `yaml:"mode"`
	Milter                 MilterConfig                 `yaml:"milter"`
	AI                     AIConfig                     `yaml:"ai"`
	Policy                 PolicyConfig                 `yaml:"policy"`
	CorrespondentAllowlist CorrespondentAllowlistConfig `yaml:"correspondent_allowlist"`
	Logging                LoggingConfig                `yaml:"logging"`
}
type MilterConfig struct {
	Socket               string   `yaml:"socket"`
	Timeout              Duration `yaml:"timeout"`
	ConnectionDNSTimeout Duration `yaml:"connection_dns_timeout"`
	MaxMessageSize       int64    `yaml:"max_message_size"`
	MaxConcurrent        int      `yaml:"max_concurrent"`
}
type AIConfig struct {
	Endpoint           string   `yaml:"endpoint"`
	APIKey             string   `yaml:"api_key"`
	APIKeyEnv          string   `yaml:"api_key_env"`
	Model              string   `yaml:"model"`
	DisableThinking    bool     `yaml:"disable_thinking"`
	PromptFile         string   `yaml:"prompt_file"`
	Timeout            Duration `yaml:"timeout"`
	MaxBodyChars       int      `yaml:"max_body_chars"`
	VisionMode         string   `yaml:"vision_mode"`
	VisionMinTextChars int      `yaml:"vision_min_text_chars"`
	MaxImages          int      `yaml:"max_images"`
	MaxImageBytes      int64    `yaml:"max_image_bytes"`
	MaxImagePixels     int64    `yaml:"max_image_pixels"`
	SiteURL            string   `yaml:"site_url"`
	AppName            string   `yaml:"app_name"`
}
type PolicyConfig struct {
	RejectScore                      float64  `yaml:"reject_score"`
	AIErrorAction                    string   `yaml:"ai_error_action"`
	RejectMessage                    string   `yaml:"reject_message"`
	ScanAuthenticated                bool     `yaml:"scan_authenticated"`
	RejectedIPBlockDuration          Duration `yaml:"rejected_ip_block_duration"`
	RejectedIPRepeatThreshold        int      `yaml:"rejected_ip_repeat_threshold"`
	RejectedIPRepeatWindow           Duration `yaml:"rejected_ip_repeat_window"`
	RejectedIPRepeatBlockDuration    Duration `yaml:"rejected_ip_repeat_block_duration"`
	RejectedIPRepeatRefreshOnAttempt bool     `yaml:"rejected_ip_repeat_refresh_on_attempt"`
	RejectedIPLegitimatePerStrike    int      `yaml:"rejected_ip_legitimate_messages_per_strike"`
	RejectedIPCacheSize              int      `yaml:"rejected_ip_cache_size"`
	RejectedIPStateFile              string   `yaml:"rejected_ip_state_file"`
	RejectedIPAllowlist              []string `yaml:"rejected_ip_allowlist"`
	RejectedIPDomainAllowlist        []string `yaml:"rejected_ip_domain_allowlist"`
}
type LoggingConfig struct {
	Level          string `yaml:"level"`
	IncludeSubject bool   `yaml:"include_subject"`
	IncludeAIInput bool   `yaml:"include_ai_input"`
}

type CorrespondentAllowlistConfig struct {
	LearnAuthenticatedRecipients bool     `yaml:"learn_authenticated_recipients"`
	LearnLegitimateSenders       bool     `yaml:"learn_legitimate_senders"`
	LegitimateSenderMinMessages  int      `yaml:"legitimate_sender_min_messages"`
	LegitimateSenderMinScore     float64  `yaml:"legitimate_sender_min_score"`
	LegitimateSenderRequireDKIM  bool     `yaml:"legitimate_sender_require_dkim"`
	UseAllowlist                 bool     `yaml:"use_allowlist"`
	Scope                        string   `yaml:"scope"`
	RecipientMatch               string   `yaml:"recipient_match"`
	BypassAI                     bool     `yaml:"bypass_ai"`
	RequireDKIMForBypass         bool     `yaml:"require_dkim_for_bypass"`
	File                         string   `yaml:"file"`
	TrustedAuthservIDs           []string `yaml:"trusted_authserv_ids"`
	MaxEntries                   int      `yaml:"max_entries"`
	StaleAfter                   Duration `yaml:"stale_after"`
	ActivityUpdateInterval       Duration `yaml:"activity_update_interval"`
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
	return Config{
		Mode: "monitor",
		Milter: MilterConfig{
			Socket: "unix:/run/sentinelmilter/sentinelmilter.sock", Timeout: Duration(30 * time.Second),
			ConnectionDNSTimeout: Duration(2 * time.Second), MaxMessageSize: 2 << 20, MaxConcurrent: 8,
		},
		AI: AIConfig{
			Endpoint: "https://openrouter.ai/api/v1/chat/completions", Timeout: Duration(15 * time.Second),
			MaxBodyChars: 50000, VisionMode: "off", VisionMinTextChars: 200,
			MaxImages: 2, MaxImageBytes: 2 << 20, MaxImagePixels: 12_000_000, AppName: "SentinelMilter",
		},
		Policy: PolicyConfig{
			RejectScore: .95, AIErrorAction: "accept", RejectMessage: "Message rejected as suspected spam or fraud",
			ScanAuthenticated: true, RejectedIPRepeatThreshold: 3,
			RejectedIPRepeatWindow: Duration(30 * 24 * time.Hour), RejectedIPRepeatBlockDuration: Duration(30 * 24 * time.Hour),
			RejectedIPRepeatRefreshOnAttempt: true, RejectedIPLegitimatePerStrike: 3,
			RejectedIPCacheSize: 10000, RejectedIPStateFile: "/var/lib/sentinelmilter/rejected-ip-state.json",
		},
		CorrespondentAllowlist: CorrespondentAllowlistConfig{
			LegitimateSenderMinMessages: 5, LegitimateSenderMinScore: .99, LegitimateSenderRequireDKIM: true,
			Scope: "per_sender", RecipientMatch: "all", File: "/var/lib/sentinelmilter/correspondent-allowlist.json",
			TrustedAuthservIDs: []string{MTAHostnameAuthservID}, MaxEntries: 10000,
			StaleAfter: Duration(365 * 24 * time.Hour), ActivityUpdateInterval: Duration(24 * time.Hour),
		},
		Logging: LoggingConfig{Level: "info", IncludeSubject: true},
	}
}

func (c Config) Validate() error {
	if c.Mode != "monitor" && c.Mode != "enforce" {
		return fmt.Errorf("mode must be monitor or enforce")
	}
	if c.Milter.Socket == "" || (c.Milter.MaxMessageSize < 1) || c.Milter.MaxConcurrent < 1 {
		return fmt.Errorf("invalid milter settings")
	}
	if c.Milter.ConnectionDNSTimeout.Value() < 0 {
		return fmt.Errorf("milter.connection_dns_timeout must not be negative")
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
	if c.AI.VisionMode != "off" && c.AI.VisionMode != "fallback" && c.AI.VisionMode != "always" {
		return fmt.Errorf("ai.vision_mode must be off, fallback, or always")
	}
	if c.AI.VisionMinTextChars < 0 || c.AI.MaxImages < 1 || c.AI.MaxImageBytes < 1 || c.AI.MaxImagePixels < 1 {
		return fmt.Errorf("invalid AI vision limits")
	}
	if c.Policy.RejectScore < 0 || c.Policy.RejectScore > 1 {
		return fmt.Errorf("policy.reject_score must be between 0 and 1")
	}
	if c.Policy.AIErrorAction != "accept" && c.Policy.AIErrorAction != "tempfail" {
		return fmt.Errorf("policy.ai_error_action must be accept or tempfail")
	}
	if c.Policy.RejectedIPBlockDuration.Value() < 0 {
		return fmt.Errorf("policy.rejected_ip_block_duration must not be negative")
	}
	if c.Policy.RejectedIPRepeatThreshold < 0 {
		return fmt.Errorf("policy.rejected_ip_repeat_threshold must not be negative")
	}
	if c.Policy.RejectedIPRepeatWindow.Value() < 0 {
		return fmt.Errorf("policy.rejected_ip_repeat_window must not be negative")
	}
	if c.Policy.RejectedIPRepeatBlockDuration.Value() < 0 {
		return fmt.Errorf("policy.rejected_ip_repeat_block_duration must not be negative")
	}
	if c.Policy.RejectedIPLegitimatePerStrike < 0 {
		return fmt.Errorf("policy.rejected_ip_legitimate_messages_per_strike must not be negative")
	}
	if c.Policy.RejectedIPRepeatThreshold > 0 && (c.Policy.RejectedIPRepeatWindow.Value() == 0 || c.Policy.RejectedIPRepeatBlockDuration.Value() == 0) {
		return fmt.Errorf("policy.rejected_ip_repeat_window and rejected_ip_repeat_block_duration must be positive when repeat escalation is enabled")
	}
	if (c.Policy.RejectedIPBlockDuration.Value() > 0 || c.Policy.RejectedIPRepeatThreshold > 0) && strings.TrimSpace(c.Policy.RejectedIPStateFile) == "" {
		return fmt.Errorf("policy.rejected_ip_state_file is required when IP blocking is enabled")
	}
	if c.Policy.RejectedIPCacheSize < 1 {
		return fmt.Errorf("policy.rejected_ip_cache_size must be positive")
	}
	for _, entry := range c.Policy.RejectedIPAllowlist {
		if _, err := netip.ParsePrefix(entry); err == nil {
			continue
		}
		if _, err := netip.ParseAddr(entry); err != nil {
			return fmt.Errorf("invalid policy.rejected_ip_allowlist entry %q", entry)
		}
	}
	for _, domain := range c.Policy.RejectedIPDomainAllowlist {
		if !validDomainName(domain) {
			return fmt.Errorf("invalid policy.rejected_ip_domain_allowlist entry %q", domain)
		}
	}
	allowlist := c.CorrespondentAllowlist
	if allowlist.Scope != "global" && allowlist.Scope != "per_sender" {
		return fmt.Errorf("correspondent_allowlist.scope must be global or per_sender")
	}
	if allowlist.RecipientMatch != "all" && allowlist.RecipientMatch != "any" {
		return fmt.Errorf("correspondent_allowlist.recipient_match must be all or any")
	}
	if allowlist.MaxEntries < 1 {
		return fmt.Errorf("correspondent_allowlist.max_entries must be positive")
	}
	if allowlist.LegitimateSenderMinMessages < 1 {
		return fmt.Errorf("correspondent_allowlist.legitimate_sender_min_messages must be positive")
	}
	if allowlist.LegitimateSenderMinScore < 0 || allowlist.LegitimateSenderMinScore > 1 {
		return fmt.Errorf("correspondent_allowlist.legitimate_sender_min_score must be between 0 and 1")
	}
	if allowlist.StaleAfter.Value() < 0 {
		return fmt.Errorf("correspondent_allowlist.stale_after must not be negative")
	}
	if allowlist.ActivityUpdateInterval.Value() < 0 {
		return fmt.Errorf("correspondent_allowlist.activity_update_interval must not be negative")
	}
	if (allowlist.LearnAuthenticatedRecipients || allowlist.UseAllowlist) && strings.TrimSpace(allowlist.File) == "" {
		return fmt.Errorf("correspondent_allowlist.file is required when the feature is enabled")
	}
	if allowlist.BypassAI && !allowlist.UseAllowlist {
		return fmt.Errorf("correspondent_allowlist.bypass_ai requires use_allowlist")
	}
	if allowlist.BypassAI && allowlist.RequireDKIMForBypass && len(allowlist.TrustedAuthservIDs) == 0 {
		return fmt.Errorf("correspondent_allowlist.require_dkim_for_bypass requires trusted_authserv_ids")
	}
	for _, authservID := range allowlist.TrustedAuthservIDs {
		if authservID != MTAHostnameAuthservID && !validDomainName(authservID) {
			return fmt.Errorf("invalid correspondent_allowlist.trusted_authserv_ids entry %q", authservID)
		}
	}
	return nil
}

func validDomainName(value string) bool {
	value = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(value)), ".")
	if value == "" || len(value) > 253 {
		return false
	}
	if _, err := netip.ParseAddr(value); err == nil {
		return false
	}
	for _, label := range strings.Split(value, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, char := range label {
			if (char < 'a' || char > 'z') && (char < '0' || char > '9') && char != '-' {
				return false
			}
		}
	}
	return true
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
