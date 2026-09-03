package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestLoadAcceptsNewSectionsAndRejectsLegacySections(t *testing.T) {
	writeConfig := func(t *testing.T, content string) string {
		t.Helper()
		path := filepath.Join(t.TempDir(), "sentinelmilter.yaml")
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}

	valid := `
ai:
  api_key: test-key
  model: test-model
  prompt_file: /tmp/test-prompt
  max_concurrent: 3
filtering:
  reject_score: 0.8
attachments:
  block: false
correspondents:
  scope: global
ip_reputation:
  max_entries: 42
logging:
  level: warn
`
	cfg, err := Load(writeConfig(t, valid))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.AI.MaxConcurrent != 3 || cfg.Filtering.RejectScore != 0.8 || cfg.Correspondents.Scope != "global" || cfg.IPReputation.MaxEntries != 42 {
		t.Fatalf("new configuration sections not loaded: %#v", cfg)
	}

	legacy := valid + "\npolicy:\n  reject_score: 0.9\n"
	if _, err := Load(writeConfig(t, legacy)); err == nil || !strings.Contains(err.Error(), "field policy not found") {
		t.Fatalf("legacy policy section error = %v", err)
	}
}

func validConfig() Config {
	cfg := defaults()
	cfg.AI.APIKey = "test-key"
	cfg.AI.Model = "test-model"
	cfg.AI.PromptFile = "/tmp/test-prompt"
	return cfg
}

func TestAuthenticatedMailScanningDefaultsEnabled(t *testing.T) {
	if !defaults().Filtering.ScanAuthenticated {
		t.Fatal("authenticated mail scanning must default to enabled")
	}
}

func TestValidateSenderDomainAllowlist(t *testing.T) {
	tests := []struct {
		name      string
		configure func(*Config)
		wantError string
	}{
		{
			name: "valid sender domains",
			configure: func(cfg *Config) {
				cfg.Filtering.SenderDomainAllowlist = []string{"amazon.com", "MAIL.EXAMPLE.ORG."}
				cfg.Filtering.SenderDomainAllowlistRequireDKIM = true
			},
		},
		{
			name: "wildcards are rejected",
			configure: func(cfg *Config) {
				cfg.Filtering.SenderDomainAllowlist = []string{"*.amazon.com"}
			},
			wantError: "invalid filtering.sender_domain_allowlist",
		},
		{
			name: "DKIM requirement needs trusted authentication service",
			configure: func(cfg *Config) {
				cfg.Filtering.SenderDomainAllowlist = []string{"amazon.com"}
				cfg.Filtering.SenderDomainAllowlistRequireDKIM = true
				cfg.Correspondents.TrustedAuthservIDs = nil
			},
			wantError: "requires correspondents.trusted_authserv_ids",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cfg := validConfig()
			test.configure(&cfg)
			err := cfg.Validate()
			if test.wantError == "" && err != nil {
				t.Fatal(err)
			}
			if test.wantError != "" && (err == nil || !strings.Contains(err.Error(), test.wantError)) {
				t.Fatalf("validation error = %v, want %q", err, test.wantError)
			}
		})
	}
}

func TestAttachmentBlockingDefaultsDisabled(t *testing.T) {
	if defaults().Attachments.Block {
		t.Fatal("attachment blocking must default to disabled for existing configurations")
	}
}

func TestMTAHostnameIsDefaultTrustedAuthenticationService(t *testing.T) {
	trusted := defaults().Correspondents.TrustedAuthservIDs
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
				cfg.IPReputation.BlockDuration = Duration(15 * time.Minute)
				cfg.IPReputation.IPAllowlist = []string{"192.0.2.1", "2001:db8::/32"}
				cfg.IPReputation.DomainAllowlist = []string{"outlook.com", "MAIL.GOOGLE.COM."}
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
				cfg.IPReputation.BlockDuration = Duration(-time.Second)
			},
			wantError: "ip_reputation.block_duration",
		},
		{
			name: "negative repeat threshold",
			configure: func(cfg *Config) {
				cfg.IPReputation.RepeatThreshold = -1
			},
			wantError: "ip_reputation.repeat_threshold",
		},
		{
			name: "negative legitimate messages per strike",
			configure: func(cfg *Config) {
				cfg.IPReputation.LegitimatePerStrike = -1
			},
			wantError: "ip_reputation.legitimate_messages_per_strike",
		},
		{
			name: "zero repeat window when escalation enabled",
			configure: func(cfg *Config) {
				cfg.IPReputation.RepeatWindow = 0
			},
			wantError: "ip_reputation.repeat_window",
		},
		{
			name: "missing state file when blocking enabled",
			configure: func(cfg *Config) {
				cfg.IPReputation.StateFile = ""
			},
			wantError: "ip_reputation.state_file",
		},
		{
			name: "zero cache size",
			configure: func(cfg *Config) {
				cfg.IPReputation.MaxEntries = 0
			},
			wantError: "ip_reputation.max_entries",
		},
		{
			name: "invalid allowlist entry",
			configure: func(cfg *Config) {
				cfg.IPReputation.IPAllowlist = []string{"not-an-address"}
			},
			wantError: "ip_reputation.ip_allowlist",
		},
		{
			name: "invalid domain allowlist entry",
			configure: func(cfg *Config) {
				cfg.IPReputation.DomainAllowlist = []string{"*.outlook.com"}
			},
			wantError: "ip_reputation.domain_allowlist",
		},
		{
			name: "invalid vision mode",
			configure: func(cfg *Config) {
				cfg.AI.VisionMode = "sometimes"
			},
			wantError: "vision_mode",
		},
		{
			name: "enabled attachment policy without detection",
			configure: func(cfg *Config) {
				cfg.Attachments.Block = true
				cfg.Attachments.BlockedExtensions = nil
				cfg.Attachments.InspectSignatures = false
			},
			wantError: "requires blocked_extensions",
		},
		{
			name: "invalid blocked attachment extension",
			configure: func(cfg *Config) {
				cfg.Attachments.BlockedExtensions = []string{"tar.gz"}
			},
			wantError: "blocked_extensions",
		},
		{
			name: "invalid attachment limit",
			configure: func(cfg *Config) {
				cfg.Attachments.MaxArchiveFiles = 0
			},
			wantError: "attachments limits",
		},
		{
			name: "invalid encrypted archive action",
			configure: func(cfg *Config) {
				cfg.Attachments.EncryptedArchiveAction = "allow"
			},
			wantError: "encrypted_archive_action",
		},
		{
			name: "invalid unscannable action",
			configure: func(cfg *Config) {
				cfg.Attachments.UnscannableAction = "defer"
			},
			wantError: "unscannable_action",
		},
		{
			name: "invalid correspondent scope",
			configure: func(cfg *Config) {
				cfg.Correspondents.Scope = "user"
			},
			wantError: "correspondents.scope",
		},
		{
			name: "invalid correspondent recipient matching policy",
			configure: func(cfg *Config) {
				cfg.Correspondents.RecipientMatch = "some"
			},
			wantError: "correspondents.recipient_match",
		},
		{
			name: "negative correspondent stale duration",
			configure: func(cfg *Config) {
				cfg.Correspondents.StaleAfter = Duration(-time.Second)
			},
			wantError: "correspondents.stale_after",
		},
		{
			name: "negative correspondent activity update interval",
			configure: func(cfg *Config) {
				cfg.Correspondents.ActivityUpdateInterval = Duration(-time.Second)
			},
			wantError: "correspondents.activity_update_interval",
		},
		{
			name: "zero legitimate sender message threshold",
			configure: func(cfg *Config) {
				cfg.Correspondents.LegitimateSenderMinMessages = 0
			},
			wantError: "legitimate_sender_min_messages",
		},
		{
			name: "invalid legitimate sender score threshold",
			configure: func(cfg *Config) {
				cfg.Correspondents.LegitimateSenderMinScore = 1.01
			},
			wantError: "legitimate_sender_min_score",
		},
		{
			name: "correspondent bypass without use",
			configure: func(cfg *Config) {
				cfg.Correspondents.BypassAI = true
				cfg.Correspondents.TrustedAuthservIDs = []string{"mx.example.com"}
			},
			wantError: "bypass_ai requires use_allowlist",
		},
		{
			name: "correspondent bypass without trusted authentication service",
			configure: func(cfg *Config) {
				cfg.Correspondents.UseAllowlist = true
				cfg.Correspondents.BypassAI = true
				cfg.Correspondents.RequireDKIMForBypass = true
				cfg.Correspondents.TrustedAuthservIDs = nil
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
