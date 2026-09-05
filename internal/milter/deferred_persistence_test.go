package milter

import (
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/PhilAnderson1/MilterGuard/internal/config"
)

func TestIPReputationDeferredPersistence(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ip.json")
	cfg := config.IPReputationConfig{
		BlockDuration: config.Duration(time.Hour), RepeatThreshold: 3,
		RepeatWindow: config.Duration(24 * time.Hour), RepeatBlockDuration: config.Duration(24 * time.Hour),
		MaxEntries: 10, StateFile: path,
	}
	store := newIPReputationStore(cfg, nil)
	store.enableDeferredPersistence()
	store.add(netip.MustParseAddr("192.0.2.1"), "unwanted", 1, connectionDNSResult{})
	assertNotPersisted(t, path)
	if err := store.flush(); err != nil {
		t.Fatal(err)
	}
	if _, blocked := newIPReputationStore(cfg, nil).lookup(netip.MustParseAddr("192.0.2.1")); !blocked {
		t.Fatal("flushed IP reputation was not reloadable")
	}
}

func TestCorrespondentDeferredPersistence(t *testing.T) {
	path := filepath.Join(t.TempDir(), "correspondents.json")
	cfg := config.CorrespondentsConfig{
		LearnAuthenticatedRecipients: true, UseAllowlist: true, Scope: "per_sender",
		RecipientMatch: "all", File: path, MaxEntries: 10,
	}
	store := newCorrespondentStore(cfg, nil)
	store.enableDeferredPersistence()
	if err := store.learn("local@example.com", []string{"friend@example.net"}); err != nil {
		t.Fatal(err)
	}
	assertNotPersisted(t, path)
	if err := store.flush(); err != nil {
		t.Fatal(err)
	}
	if match := newCorrespondentStore(cfg, nil).match("friend@example.net", []string{"local@example.com"}); !match.Known {
		t.Fatal("flushed correspondent was not reloadable")
	}
}

func TestRejectionHistoryDeferredPersistence(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rejections.json")
	cfg := config.RejectionHistoryConfig{File: path, Expiry: config.Duration(24 * time.Hour), MaxEntries: 10}
	store := newRejectionHistoryStore(cfg, nil)
	store.enableDeferredPersistence()
	if err := store.add("sender@example.net", "", []string{"local@example.com"}, []string{"Unwanted message"}); err != nil {
		t.Fatal(err)
	}
	assertNotPersisted(t, path)
	if err := store.flush(); err != nil {
		t.Fatal(err)
	}
	if entries := newRejectionHistoryStore(cfg, nil).list("local@example.com"); len(entries) != 1 || entries[0].Reason != "Unwanted message" {
		t.Fatalf("flushed rejection history = %#v", entries)
	}
}

func assertNotPersisted(t *testing.T, path string) {
	t.Helper()
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("deferred state was written before flush: %v", err)
	}
}
