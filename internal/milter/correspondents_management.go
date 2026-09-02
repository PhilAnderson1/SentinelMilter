package milter

import (
	"fmt"
	"os"
	"time"

	"github.com/PhilAnderson1/SentinelMilter/internal/config"
)

// AddManualCorrespondent adds an immediately qualified relationship. The
// caller must ensure the running daemon is stopped while editing its database.
func AddManualCorrespondent(cfg config.CorrespondentAllowlistConfig, sender, recipient string) (bool, error) {
	store, err := openCorrespondentStoreForManagement(cfg)
	if err != nil {
		return false, err
	}
	sender = normalizeEmailAddress(sender)
	recipient = normalizeEmailAddress(recipient)
	if sender == "" || recipient == "" {
		return false, fmt.Errorf("sender and recipient must be valid email addresses")
	}
	now := store.now().UTC()
	store.mu.Lock()
	defer store.mu.Unlock()
	store.removeStaleLocked(now)
	key := store.key(recipient, sender)
	entry, existed := store.entries[key]
	if !existed {
		for len(store.entries) >= store.cfg.MaxEntries {
			store.evictOldestLocked()
		}
		entry = correspondentEntry{LocalAddress: recipient, Correspondent: sender, LearnedAt: now}
	}
	entry.LastActivityAt = now
	entry.WhitelistType = whitelistManual
	entry.LegitimateEmailCount = 0
	store.entries[key] = entry
	if err := store.saveLocked(); err != nil {
		return false, err
	}
	return !existed, nil
}

// DeleteCorrespondents deletes an exact relationship, or every relationship
// for sender when recipient is "*". Explicit deletion applies to all types.
func DeleteCorrespondents(cfg config.CorrespondentAllowlistConfig, sender, recipient string) (int, error) {
	store, err := openCorrespondentStoreForManagement(cfg)
	if err != nil {
		return 0, err
	}
	sender = normalizeEmailAddress(sender)
	if sender == "" {
		return 0, fmt.Errorf("sender must be a valid email address")
	}
	allRecipients := recipient == "*"
	if !allRecipients {
		recipient = normalizeEmailAddress(recipient)
		if recipient == "" {
			return 0, fmt.Errorf("recipient must be a valid email address or *")
		}
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	staleRemoved := store.removeStaleLocked(store.now().UTC())
	removed := 0
	for key, entry := range store.entries {
		if entry.Correspondent == sender && (allRecipients || entry.LocalAddress == recipient) {
			delete(store.entries, key)
			removed++
		}
	}
	if removed > 0 || staleRemoved > 0 {
		if err := store.saveLocked(); err != nil {
			return 0, err
		}
	}
	return removed, nil
}

func openCorrespondentStoreForManagement(cfg config.CorrespondentAllowlistConfig) (*correspondentStore, error) {
	store := &correspondentStore{cfg: cfg, entries: make(map[string]correspondentEntry), now: time.Now}
	if err := store.load(); err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	return store, nil
}
