package milter

import (
	"bytes"
	"context"
	"log/slog"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/PhilAnderson1/SentinelMilter/internal/config"
)

type fakeDNSResolver struct {
	ptr     map[string][]string
	forward map[string][]net.IPAddr
}

func (r fakeDNSResolver) LookupAddr(_ context.Context, address string) ([]string, error) {
	return r.ptr[address], nil
}

func (r fakeDNSResolver) LookupIPAddr(_ context.Context, hostname string) ([]net.IPAddr, error) {
	return r.forward[hostname], nil
}

type blockingDNSResolver struct{}

func (blockingDNSResolver) LookupAddr(ctx context.Context, _ string) ([]string, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

func (blockingDNSResolver) LookupIPAddr(ctx context.Context, _ string) ([]net.IPAddr, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

func TestRejectedIPCacheExpiresEntries(t *testing.T) {
	now := time.Date(2026, 8, 31, 12, 0, 0, 0, time.UTC)
	cache := newRejectedIPCache(config.PolicyConfig{
		RejectedIPBlockDuration: config.Duration(10 * time.Minute),
		RejectedIPCacheSize:     10,
	}, nil)
	cache.now = func() time.Time { return now }
	addr := netip.MustParseAddr("192.0.2.10")
	if !cache.add(context.Background(), addr, "scam", 1) {
		t.Fatal("IP was not added")
	}
	if _, ok := cache.lookup(addr); !ok {
		t.Fatal("IP was not found before expiry")
	}
	now = now.Add(10 * time.Minute)
	if _, ok := cache.lookup(addr); ok {
		t.Fatal("IP remained cached at its expiry time")
	}
}

func TestRejectedIPCacheHonorsAllowlist(t *testing.T) {
	var output bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&output, &slog.HandlerOptions{Level: slog.LevelDebug}))
	cache := newRejectedIPCache(config.PolicyConfig{
		RejectedIPBlockDuration: config.Duration(time.Hour),
		RejectedIPCacheSize:     10,
		RejectedIPAllowlist:     []string{"192.0.2.0/24", "2001:db8::1"},
	}, logger)
	for _, value := range []string{"192.0.2.25", "2001:db8::1"} {
		if cache.add(context.Background(), netip.MustParseAddr(value), "spam", 1) {
			t.Errorf("allowlisted address %s was added", value)
		}
	}
	if !cache.add(context.Background(), netip.MustParseAddr("198.51.100.25"), "spam", 1) {
		t.Fatal("non-allowlisted address was not added")
	}
	logOutput := output.String()
	for _, wanted := range []string{
		`"msg":"sending IP excluded from rejection cache","remote_ip":"192.0.2.25","matched_prefix":"192.0.2.0/24","reason":"ip_allowlist","cache_size":0`,
		`"msg":"sending IP excluded from rejection cache","remote_ip":"2001:db8::1","matched_prefix":"2001:db8::1/128","reason":"ip_allowlist","cache_size":0`,
	} {
		if !strings.Contains(logOutput, wanted) {
			t.Errorf("debug log does not contain %s: %s", wanted, logOutput)
		}
	}
}

func TestRejectedIPCacheEvictsEarliestExpiry(t *testing.T) {
	now := time.Date(2026, 8, 31, 12, 0, 0, 0, time.UTC)
	cache := newRejectedIPCache(config.PolicyConfig{
		RejectedIPBlockDuration: config.Duration(10 * time.Minute),
		RejectedIPCacheSize:     2,
	}, nil)
	cache.now = func() time.Time { return now }
	first := netip.MustParseAddr("192.0.2.1")
	second := netip.MustParseAddr("192.0.2.2")
	third := netip.MustParseAddr("192.0.2.3")
	cache.add(context.Background(), first, "spam", 1)
	now = now.Add(time.Minute)
	cache.add(context.Background(), second, "spam", 1)
	now = now.Add(time.Minute)
	cache.add(context.Background(), third, "spam", 1)
	if _, ok := cache.lookup(first); ok {
		t.Fatal("earliest-expiring entry was not evicted")
	}
	for _, addr := range []netip.Addr{second, third} {
		if _, ok := cache.lookup(addr); !ok {
			t.Errorf("expected %s to remain cached", addr)
		}
	}
}

func TestRejectedIPCacheCanRefreshExpiryOnAttempt(t *testing.T) {
	now := time.Date(2026, 8, 31, 12, 0, 0, 0, time.UTC)
	cache := newRejectedIPCache(config.PolicyConfig{
		RejectedIPBlockDuration:    config.Duration(time.Minute),
		RejectedIPCacheSize:        10,
		RejectedIPRefreshOnAttempt: true,
	}, nil)
	cache.now = func() time.Time { return now }
	addr := netip.MustParseAddr("192.0.2.10")
	cache.add(context.Background(), addr, "scam", 1)

	now = now.Add(45 * time.Second)
	entry, ok := cache.lookup(addr)
	if !ok {
		t.Fatal("IP was not found before its original expiry")
	}
	wantExpiry := now.Add(time.Minute)
	if !entry.expires.Equal(wantExpiry) {
		t.Fatalf("refreshed expiry = %v, want %v", entry.expires, wantExpiry)
	}

	now = now.Add(30 * time.Second)
	if _, ok := cache.lookup(addr); !ok {
		t.Fatal("IP expired at its original expiry despite refresh")
	}
}

func TestRejectedIPCacheLogsSizeOnAddAndRemove(t *testing.T) {
	var output bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&output, &slog.HandlerOptions{Level: slog.LevelDebug}))
	now := time.Date(2026, 8, 31, 12, 0, 0, 0, time.UTC)
	cache := newRejectedIPCache(config.PolicyConfig{
		RejectedIPBlockDuration: config.Duration(time.Minute),
		RejectedIPCacheSize:     1,
	}, logger)
	cache.now = func() time.Time { return now }
	first := netip.MustParseAddr("192.0.2.1")
	second := netip.MustParseAddr("192.0.2.2")
	cache.add(context.Background(), first, "scam", 1)
	cache.add(context.Background(), second, "spam", 0.95)
	now = now.Add(time.Minute)
	cache.lookup(second)

	logOutput := output.String()
	for _, wanted := range []string{
		`"msg":"sending IP added to rejection cache","remote_ip":"192.0.2.1"`,
		`"remote_ip":"192.0.2.1","reason":"capacity","cache_size":0`,
		`"msg":"sending IP added to rejection cache","remote_ip":"192.0.2.2"`,
		`"remote_ip":"192.0.2.2","reason":"expired","cache_size":0`,
	} {
		if !strings.Contains(logOutput, wanted) {
			t.Errorf("debug log does not contain %s: %s", wanted, logOutput)
		}
	}
}

func TestRejectedIPCacheHonorsForwardConfirmedDomainAllowlist(t *testing.T) {
	addr := netip.MustParseAddr("192.0.2.25")
	cache := newRejectedIPCache(config.PolicyConfig{
		RejectedIPBlockDuration:   config.Duration(time.Hour),
		RejectedIPCacheSize:       10,
		RejectedIPDomainAllowlist: []string{"outlook.com"},
		RejectedIPDNSTimeout:      config.Duration(time.Second),
	}, nil)
	cache.resolver = fakeDNSResolver{
		ptr: map[string][]string{
			addr.String(): {"mail.outbound.protection.outlook.com."},
		},
		forward: map[string][]net.IPAddr{
			"mail.outbound.protection.outlook.com": {{IP: net.ParseIP(addr.String())}},
		},
	}
	if cache.add(context.Background(), addr, "scam", 1) {
		t.Fatal("forward-confirmed outlook.com subdomain was blacklisted")
	}
	if _, found := cache.lookup(addr); found {
		t.Fatal("domain-allowlisted address was present in cache")
	}
}

func TestRejectedIPDomainAllowlistRequiresLabelBoundaryAndForwardConfirmation(t *testing.T) {
	tests := []struct {
		name      string
		hostname  string
		forwardIP string
	}{
		{name: "suffix without label boundary", hostname: "eviloutlook.com", forwardIP: "192.0.2.25"},
		{name: "unconfirmed matching PTR", hostname: "outbound.protection.outlook.com", forwardIP: "198.51.100.10"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			addr := netip.MustParseAddr("192.0.2.25")
			cache := newRejectedIPCache(config.PolicyConfig{
				RejectedIPBlockDuration:   config.Duration(time.Hour),
				RejectedIPCacheSize:       10,
				RejectedIPDomainAllowlist: []string{"outlook.com"},
				RejectedIPDNSTimeout:      config.Duration(time.Second),
			}, nil)
			cache.resolver = fakeDNSResolver{
				ptr: map[string][]string{addr.String(): {test.hostname}},
				forward: map[string][]net.IPAddr{
					test.hostname: {{IP: net.ParseIP(test.forwardIP)}},
				},
			}
			if !cache.add(context.Background(), addr, "scam", 1) {
				t.Fatal("untrusted reverse DNS prevented blacklisting")
			}
		})
	}
}

func TestRejectedIPDomainLookupRespectsTimeout(t *testing.T) {
	cache := newRejectedIPCache(config.PolicyConfig{
		RejectedIPBlockDuration:   config.Duration(time.Hour),
		RejectedIPCacheSize:       10,
		RejectedIPDomainAllowlist: []string{"outlook.com"},
		RejectedIPDNSTimeout:      config.Duration(10 * time.Millisecond),
	}, nil)
	cache.resolver = blockingDNSResolver{}
	started := time.Now()
	if !cache.add(context.Background(), netip.MustParseAddr("192.0.2.25"), "scam", 1) {
		t.Fatal("DNS timeout prevented fail-closed blacklisting")
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("DNS lookup exceeded timeout: %v", elapsed)
	}
}
