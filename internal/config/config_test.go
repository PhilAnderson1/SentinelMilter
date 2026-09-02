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

func TestAuthenticatedMailScanningDefaultsEnabled(t *testing.T) {
	if !defaults().Policy.ScanAuthenticated {
		t.Fatal("authenticated mail scanning must default to enabled")
	}
}

func TestMTAHostnameIsDefaultTrustedAuthenticationService(t *testing.T) {
	trusted := defaults().CorrespondentAllowlist.TrustedAuthservIDs
	if len(trusted) != 1 || trusted[0] != MTAHostnameAuthservID {
		t.Fatalf("default trusted authentication services = %q", trusted)
	}
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
			name: "negative connection DNS timeout",
			configure: func(cfg *Config) {
				cfg.Milter.ConnectionDNSTimeout = Duration(-time.Second)
			},
			wantError: "connection_dns_timeout",
		},
		{
			name: "negative duration",
			configure: func(cfg *Config) {
				cfg.Policy.RejectedIPBlockDuration = Duration(-time.Second)
			},
			wantError: "rejected_ip_block_duration",
		},
		{
			name: "negative repeat threshold",
			configure: func(cfg *Config) {
				cfg.Policy.RejectedIPRepeatThreshold = -1
			},
			wantError: "rejected_ip_repeat_threshold",
		},
		{
			name: "negative legitimate messages per strike",
			configure: func(cfg *Config) {
				cfg.Policy.RejectedIPLegitimatePerStrike = -1
			},
			wantError: "rejected_ip_legitimate_messages_per_strike",
		},
		{
			name: "zero repeat window when escalation enabled",
			configure: func(cfg *Config) {
				cfg.Policy.RejectedIPRepeatWindow = 0
			},
			wantError: "rejected_ip_repeat_window",
		},
		{
			name: "missing state file when blocking enabled",
			configure: func(cfg *Config) {
				cfg.Policy.RejectedIPStateFile = ""
			},
			wantError: "rejected_ip_state_file",
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
			name: "invalid vision mode",
			configure: func(cfg *Config) {
				cfg.AI.VisionMode = "sometimes"
			},
			wantError: "vision_mode",
		},
		{
			name: "invalid correspondent scope",
			configure: func(cfg *Config) {
				cfg.CorrespondentAllowlist.Scope = "user"
			},
			wantError: "correspondent_allowlist.scope",
		},
		{
			name: "invalid correspondent recipient matching policy",
			configure: func(cfg *Config) {
				cfg.CorrespondentAllowlist.RecipientMatch = "some"
			},
			wantError: "correspondent_allowlist.recipient_match",
		},
		{
			name: "negative correspondent stale duration",
			configure: func(cfg *Config) {
				cfg.CorrespondentAllowlist.StaleAfter = Duration(-time.Second)
			},
			wantError: "correspondent_allowlist.stale_after",
		},
		{
			name: "negative correspondent activity update interval",
			configure: func(cfg *Config) {
				cfg.CorrespondentAllowlist.ActivityUpdateInterval = Duration(-time.Second)
			},
			wantError: "correspondent_allowlist.activity_update_interval",
		},
		{
			name: "zero legitimate sender message threshold",
			configure: func(cfg *Config) {
				cfg.CorrespondentAllowlist.LegitimateSenderMinMessages = 0
			},
			wantError: "legitimate_sender_min_messages",
		},
		{
			name: "invalid legitimate sender score threshold",
			configure: func(cfg *Config) {
				cfg.CorrespondentAllowlist.LegitimateSenderMinScore = 1.01
			},
			wantError: "legitimate_sender_min_score",
		},
		{
			name: "correspondent bypass without use",
			configure: func(cfg *Config) {
				cfg.CorrespondentAllowlist.BypassAI = true
				cfg.CorrespondentAllowlist.TrustedAuthservIDs = []string{"mx.example.com"}
			},
			wantError: "bypass_ai requires use_allowlist",
		},
		{
			name: "correspondent bypass without trusted authentication service",
			configure: func(cfg *Config) {
				cfg.CorrespondentAllowlist.UseAllowlist = true
				cfg.CorrespondentAllowlist.BypassAI = true
				cfg.CorrespondentAllowlist.RequireDKIMForBypass = true
				cfg.CorrespondentAllowlist.TrustedAuthservIDs = nil
			},
			wantError: "requires trusted_authserv_ids",
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
