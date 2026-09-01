package milter

import (
	"context"
	"log/slog"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/PhilAnderson1/SentinelMilter/internal/config"
)

type blockedIP struct {
	expires        time.Time
	classification string
	score          float64
}

type dnsResolver interface {
	LookupAddr(context.Context, string) ([]string, error)
	LookupIPAddr(context.Context, string) ([]net.IPAddr, error)
}

type rejectedIPCache struct {
	mu               sync.Mutex
	entries          map[netip.Addr]blockedIP
	duration         time.Duration
	maxSize          int
	refreshOnAttempt bool
	allowlist        []netip.Prefix
	domainAllowlist  []string
	dnsTimeout       time.Duration
	resolver         dnsResolver
	now              func() time.Time
	log              *slog.Logger
}

func newRejectedIPCache(policy config.PolicyConfig, log *slog.Logger) *rejectedIPCache {
	cache := &rejectedIPCache{
		entries:          make(map[netip.Addr]blockedIP),
		duration:         policy.RejectedIPBlockDuration.Value(),
		maxSize:          policy.RejectedIPCacheSize,
		refreshOnAttempt: policy.RejectedIPRefreshOnAttempt,
		dnsTimeout:       policy.RejectedIPDNSTimeout.Value(),
		resolver:         net.DefaultResolver,
		now:              time.Now,
		log:              log,
	}
	for _, entry := range policy.RejectedIPAllowlist {
		if prefix, err := netip.ParsePrefix(entry); err == nil {
			cache.allowlist = append(cache.allowlist, prefix)
			continue
		}
		if addr, err := netip.ParseAddr(entry); err == nil {
			bits := 128
			if addr.Is4() || addr.Is4In6() {
				bits = 32
			}
			cache.allowlist = append(cache.allowlist, netip.PrefixFrom(addr.Unmap(), bits))
		}
	}
	for _, domain := range policy.RejectedIPDomainAllowlist {
		cache.domainAllowlist = append(cache.domainAllowlist, normalizeDomain(domain))
	}
	return cache
}

func (c *rejectedIPCache) enabled() bool {
	return c != nil && c.duration > 0 && c.maxSize > 0
}

func (c *rejectedIPCache) allowed(addr netip.Addr) (netip.Prefix, bool) {
	if !addr.IsValid() {
		return netip.Prefix{}, true
	}
	addr = addr.Unmap()
	for _, prefix := range c.allowlist {
		if prefix.Contains(addr) {
			return prefix, true
		}
	}
	return netip.Prefix{}, false
}

func (c *rejectedIPCache) add(ctx context.Context, addr netip.Addr, classification string, score float64) bool {
	if !c.enabled() || !addr.IsValid() {
		return false
	}
	addr = addr.Unmap()
	if prefix, ok := c.allowed(addr); ok {
		c.debug("sending IP excluded from rejection cache",
			"remote_ip", addr.String(),
			"matched_prefix", prefix.String(),
			"reason", "ip_allowlist",
			"cache_size", c.size())
		return false
	}
	if hostname, domain, ok := c.domainAllowed(ctx, addr); ok {
		c.debug("sending IP excluded from rejection cache",
			"remote_ip", addr.String(),
			"reverse_dns", hostname,
			"matched_domain", domain,
			"reason", "domain_allowlist",
			"cache_size", c.size())
		return false
	}
	now := c.now()
	c.mu.Lock()
	defer c.mu.Unlock()
	c.removeExpired(now)
	_, existed := c.entries[addr]
	if !existed && len(c.entries) >= c.maxSize {
		c.evictEarliest()
	}
	entry := blockedIP{expires: now.Add(c.duration), classification: classification, score: score}
	c.entries[addr] = entry
	message := "sending IP added to rejection cache"
	if existed {
		message = "sending IP rejection cache entry refreshed"
	}
	c.debug(message,
		"remote_ip", addr.String(),
		"classification", classification,
		"score", score,
		"block_expires_at", entry.expires,
		"cache_size", len(c.entries))
	return true
}

func (c *rejectedIPCache) domainAllowed(parent context.Context, addr netip.Addr) (string, string, bool) {
	if len(c.domainAllowlist) == 0 || c.resolver == nil || c.dnsTimeout <= 0 {
		return "", "", false
	}
	ctx, cancel := context.WithTimeout(parent, c.dnsTimeout)
	defer cancel()
	hostnames, err := c.resolver.LookupAddr(ctx, addr.String())
	if err != nil {
		c.debug("reverse DNS domain allowlist lookup failed", "remote_ip", addr.String(), "error", err)
		return "", "", false
	}
	for _, hostname := range hostnames {
		hostname = normalizeDomain(hostname)
		for _, domain := range c.domainAllowlist {
			if !domainMatches(hostname, domain) {
				continue
			}
			forwardAddresses, err := c.resolver.LookupIPAddr(ctx, hostname)
			if err != nil {
				c.debug("forward DNS confirmation failed",
					"remote_ip", addr.String(), "reverse_dns", hostname, "matched_domain", domain, "error", err)
				continue
			}
			for _, forward := range forwardAddresses {
				confirmed, ok := netip.AddrFromSlice(forward.IP)
				if ok && confirmed.Unmap() == addr {
					return hostname, domain, true
				}
			}
			c.debug("reverse DNS domain match was not forward-confirmed",
				"remote_ip", addr.String(), "reverse_dns", hostname, "matched_domain", domain)
		}
	}
	return "", "", false
}

func normalizeDomain(value string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(value)), ".")
}

func domainMatches(hostname, domain string) bool {
	return hostname == domain || strings.HasSuffix(hostname, "."+domain)
}

func (c *rejectedIPCache) lookup(addr netip.Addr) (blockedIP, bool) {
	if !c.enabled() || !addr.IsValid() {
		return blockedIP{}, false
	}
	if _, allowed := c.allowed(addr); allowed {
		return blockedIP{}, false
	}
	addr = addr.Unmap()
	now := c.now()
	c.mu.Lock()
	defer c.mu.Unlock()
	entry, ok := c.entries[addr]
	if !ok {
		return blockedIP{}, false
	}
	if !entry.expires.After(now) {
		delete(c.entries, addr)
		c.debug("sending IP removed from rejection cache",
			"remote_ip", addr.String(),
			"reason", "expired",
			"cache_size", len(c.entries))
		return blockedIP{}, false
	}
	if c.refreshOnAttempt {
		entry.expires = now.Add(c.duration)
		c.entries[addr] = entry
		c.debug("sending IP rejection cache expiry refreshed",
			"remote_ip", addr.String(),
			"block_expires_at", entry.expires,
			"cache_size", len(c.entries))
	}
	return entry, true
}

func (c *rejectedIPCache) removeExpired(now time.Time) {
	for addr, entry := range c.entries {
		if !entry.expires.After(now) {
			delete(c.entries, addr)
			c.debug("sending IP removed from rejection cache",
				"remote_ip", addr.String(),
				"reason", "expired",
				"cache_size", len(c.entries))
		}
	}
}

func (c *rejectedIPCache) evictEarliest() {
	var earliestAddr netip.Addr
	var earliestTime time.Time
	for addr, entry := range c.entries {
		if !earliestAddr.IsValid() || entry.expires.Before(earliestTime) {
			earliestAddr = addr
			earliestTime = entry.expires
		}
	}
	if earliestAddr.IsValid() {
		delete(c.entries, earliestAddr)
		c.debug("sending IP removed from rejection cache",
			"remote_ip", earliestAddr.String(),
			"reason", "capacity",
			"cache_size", len(c.entries))
	}
}

func (c *rejectedIPCache) debug(message string, attrs ...any) {
	if c.log != nil {
		c.log.Debug(message, attrs...)
	}
}

func (c *rejectedIPCache) size() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.entries)
}
