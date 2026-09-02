package milter

import (
	"fmt"
	"sort"

	"github.com/PhilAnderson1/SentinelMilter/internal/jsonfile"
)

func (s *correspondentStore) load() error {
	var data correspondentFile
	if err := jsonfile.Read(s.cfg.File, maxCorrespondentFileSize, &data); err != nil {
		return err
	}
	if data.Version != legacyCorrespondentFileVersion && data.Version != correspondentFileVersion {
		return fmt.Errorf("unsupported correspondent allowlist version %d", data.Version)
	}
	changed := data.Version != correspondentFileVersion
	for _, entry := range data.Entries {
		entry.Correspondent = normalizeEmailAddress(entry.Correspondent)
		entry.LocalAddress = normalizeEmailAddress(entry.LocalAddress)
		if entry.Correspondent == "" || entry.LocalAddress == "" {
			changed = true
			continue
		}
		if entry.LastActivityAt.IsZero() {
			entry.LastActivityAt = entry.LearnedAt
			changed = true
		}
		if entry.WhitelistType == "" {
			entry.WhitelistType = whitelistAuthenticatedOutbound
			changed = true
		}
		if entry.WhitelistType != whitelistAuthenticatedOutbound && entry.WhitelistType != whitelistRepeatedLegitimate && entry.WhitelistType != whitelistManual {
			changed = true
			continue
		}
		if (entry.WhitelistType == whitelistAuthenticatedOutbound || entry.WhitelistType == whitelistManual) && entry.LegitimateEmailCount != 0 {
			entry.LegitimateEmailCount = 0
			changed = true
		}
		entry.PersistedActivityAt = entry.LastActivityAt
		s.entries[s.key(entry.LocalAddress, entry.Correspondent)] = entry
	}
	if s.removeStaleLocked(s.now().UTC()) > 0 {
		changed = true
	}
	for len(s.entries) > s.cfg.MaxEntries {
		s.evictOldestLocked()
		changed = true
	}
	if changed {
		return s.saveLocked()
	}
	return nil
}

func (s *correspondentStore) saveLocked() error {
	entries := make([]correspondentEntry, 0, len(s.entries))
	for _, entry := range s.entries {
		entries = append(entries, entry)
	}
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].LocalAddress != entries[j].LocalAddress {
			return entries[i].LocalAddress < entries[j].LocalAddress
		}
		return entries[i].Correspondent < entries[j].Correspondent
	})
	if err := jsonfile.Write(s.cfg.File, correspondentFile{Version: correspondentFileVersion, Entries: entries}, 0750, 0640); err != nil {
		return err
	}
	for key, entry := range s.entries {
		entry.PersistedActivityAt = entry.LastActivityAt
		s.entries[key] = entry
	}
	return nil
}
