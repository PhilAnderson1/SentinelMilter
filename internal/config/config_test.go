package config

import (
	"strings"
	"testing"
	"time"
)

func validConfig() Config {
	cfg := defaults()
	cfg.AI.APIKey = "test-key"
	cfg.AI.Model = "test-model"
	cfg.AI.PromptFile = "/tmp/test-prompt"
	return cfg
}

func TestValidateRejectedIPPolicy(t *testing.T) {
	tests := []struct {
		name      string
		configure func(*Config)
		wantError string
	}{
		{
			name: "valid IP CIDR and domain allowlists",
			configure: func(cfg *Config) {
				cfg.Policy.RejectedIPBlockDuration = Duration(15 * time.Minute)
				cfg.Policy.RejectedIPAllowlist = []string{"192.0.2.1", "2001:db8::/32"}
				cfg.Policy.RejectedIPDomainAllowlist = []string{"outlook.com", "MAIL.GOOGLE.COM."}
			},
		},
		{
			name: "negative duration",
			configure: func(cfg *Config) {
				cfg.Policy.RejectedIPBlockDuration = Duration(-time.Second)
			},
			wantError: "rejected_ip_block_duration",
		},
		{
			name: "zero cache size",
			configure: func(cfg *Config) {
				cfg.Policy.RejectedIPCacheSize = 0
			},
			wantError: "rejected_ip_cache_size",
		},
		{
			name: "invalid allowlist entry",
			configure: func(cfg *Config) {
				cfg.Policy.RejectedIPAllowlist = []string{"not-an-address"}
			},
			wantError: "rejected_ip_allowlist",
		},
		{
			name: "invalid domain allowlist entry",
			configure: func(cfg *Config) {
				cfg.Policy.RejectedIPDomainAllowlist = []string{"*.outlook.com"}
			},
			wantError: "rejected_ip_domain_allowlist",
		},
		{
			name: "zero DNS timeout",
			configure: func(cfg *Config) {
				cfg.Policy.RejectedIPDNSTimeout = 0
			},
			wantError: "rejected_ip_dns_timeout",
		},
		{
			name: "invalid vision mode",
			configure: func(cfg *Config) {
				cfg.AI.VisionMode = "sometimes"
			},
			wantError: "vision_mode",
		},
		{
			name: "invalid vision limit",
			configure: func(cfg *Config) {
				cfg.AI.MaxImagePixels = 0
			},
			wantError: "vision limits",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cfg := validConfig()
			test.configure(&cfg)
			err := cfg.Validate()
			if test.wantError == "" && err != nil {
				t.Fatalf("Validate() error = %v", err)
			}
			if test.wantError != "" && (err == nil || !strings.Contains(err.Error(), test.wantError)) {
				t.Fatalf("Validate() error = %v, want error containing %q", err, test.wantError)
			}
		})
	}
}
