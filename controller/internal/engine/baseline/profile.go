package baseline

import (
	"context"
	"fmt"
	"log"
	"sort"
	"sync"
	"time"

	"github.com/littlewolf9527/xsight/controller/internal/store"
	"github.com/littlewolf9527/xsight/controller/internal/store/ring"
)

// SlotIndex maps a UTC time to a weekly slot index (0-167).
// Monday 00:00 = 0, Monday 01:00 = 1, ..., Sunday 23:00 = 167.
func SlotIndex(t time.Time) int {
	utc := t.UTC()
	weekday := int(utc.Weekday())
	if weekday == 0 {
		weekday = 6
	} else {
		weekday--
	}
	return weekday*24 + utc.Hour()
}

// SlotLabel returns a human-readable label for a slot index.
func SlotLabel(slot int) string {
	days := []string{"Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"}
	day := slot / 24
	hour := slot % 24
	if day < 0 || day >= 7 {
		return fmt.Sprintf("slot_%d", slot)
	}
	return fmt.Sprintf("%s %02d:00 UTC", days[day], hour)
}

// profileKey builds "nodeID:prefix" key.
func profileKey(nodeID, prefix string) string { return nodeID + ":" + prefix }

// ProfileStatus is returned by the status API for one prefix.
type ProfileStatus struct {
	Prefix      string `json:"prefix"`
	NodeID      string `json:"node_id"`
	SlotIndex   int    `json:"slot_index"`
	ExpectedPPS int64  `json:"expected_pps"`
	ExpectedBPS int64  `json:"expected_bps"`
	SampleWeeks int    `json:"sample_weeks"`
	Status      string `json:"status"` // "learning" | "active"
}

// ProfileEngine manages dynamic detection profiles.
type ProfileEngine struct {
	mu        sync.RWMutex
	rings     *ring.RingStore
	statsRepo store.StatsRepo
	repo      store.DynDetectRepo
	config    store.DynDetectConfig
	profiles  map[string]*store.PrefixProfile // "nodeID:prefix:slotIndex" → profile
}

func profileMapKey(nodeID, prefix string, slot int) string {
	return fmt.Sprintf("%s:%s:%d", nodeID, prefix, slot)
}

// NewProfileEngine creates a new profile engine.
func NewProfileEngine(rings *ring.RingStore, repo store.DynDetectRepo, statsRepo store.StatsRepo) *ProfileEngine {
	return &ProfileEngine{
		rings:     rings,
		statsRepo: statsRepo,
		repo:      repo,
		profiles:  make(map[string]*store.PrefixProfile),
	}
}

// LoadFromDB loads config and all profiles from the database on startup.
func (e *ProfileEngine) LoadFromDB(ctx context.Context) error {
	// Load config
	cfg, err := e.repo.GetConfig(ctx)
	if err != nil {
		return fmt.Errorf("load dyn detect config: %w", err)
	}

	e.mu.Lock()
	e.config = *cfg
	e.mu.Unlock()

	// Load all 168 slots
	for slot := 0; slot < 168; slot++ {
		profiles, err := e.repo.ListProfiles(ctx, slot)
		if err != nil {
			return fmt.Errorf("load profiles slot %d: %w", slot, err)
		}
		e.mu.Lock()
		for i := range profiles {
			p := profiles[i]
			key := profileMapKey(p.NodeID, p.Prefix, p.SlotIndex)
			e.profiles[key] = &p
		}
		e.mu.Unlock()
	}

	e.mu.RLock()
	count := len(e.profiles)
	e.mu.RUnlock()
	log.Printf("profile engine: loaded %d profiles, enabled=%v", count, cfg.Enabled)
	return nil
}

// RefreshConfig reloads config from the database.
func (e *ProfileEngine) RefreshConfig(ctx context.Context) {
	cfg, err := e.repo.GetConfig(ctx)
	if err != nil {
		log.Printf("profile engine refresh config: %v", err)
		return
	}
	e.mu.Lock()
	e.config = *cfg
	e.mu.Unlock()
}

// IsExceeded checks if the current traffic exceeds the dynamic profile threshold.
func (e *ProfileEngine) IsExceeded(nodeID, prefix string, currentPPS, currentBPS int64) (exceeded bool, reason string) {
	e.mu.RLock()
	cfg := e.config
	if !cfg.Enabled {
		e.mu.RUnlock()
		return false, ""
	}

	slot := SlotIndex(time.Now())
	key := profileMapKey(nodeID, prefix, slot)
	p := e.profiles[key]
	e.mu.RUnlock()

	if p == nil {
		return false, ""
	}

	// Learning phase: not enough samples
	if p.SampleWeeks < 1 {
		return false, ""
	}

	// Below minimum thresholds — ignore small traffic
	if currentPPS < cfg.MinPPS && currentBPS < cfg.MinBPS {
		return false, ""
	}

	// Progressive deviation: narrows from deviation_max to deviation_min as sample_weeks grows
	progress := float64(p.SampleWeeks)
	if progress > float64(cfg.StableWeeks) {
		progress = float64(cfg.StableWeeks)
	}
	progress = progress / float64(cfg.StableWeeks)
	deviation := float64(cfg.DeviationMax) - progress*(float64(cfg.DeviationMax)-float64(cfg.DeviationMin))

	threshPPS := p.ExpectedPPS * (100 + int64(deviation)) / 100
	threshBPS := p.ExpectedBPS * (100 + int64(deviation)) / 100

	if currentPPS > threshPPS {
		return true, fmt.Sprintf("dynamic_pps_exceeded(expected=%d thresh=%d actual=%d dev=%.0f%%)",
			p.ExpectedPPS, threshPPS, currentPPS, deviation)
	}
	if currentBPS > threshBPS {
		return true, fmt.Sprintf("dynamic_bps_exceeded(expected=%d thresh=%d actual=%d dev=%.0f%%)",
			p.ExpectedBPS, threshBPS, currentBPS, deviation)
	}
	return false, ""
}

// UpdateHourly updates prefix profiles from ring buffer data.
// Should be called once per hour at the hour boundary.
func (e *ProfileEngine) UpdateHourly() {
	// Wait for DBWriter to flush the last seconds of the previous hour.
	// DBWriter flushes every dbFlushInterval (default 5s).
	// Delay = 2 × flush interval to ensure the closed hour is fully persisted.
	const dbFlushInterval = 5 * time.Second
	time.Sleep(2 * dbFlushInterval)

	e.mu.RLock()
	cfg := e.config
	e.mu.RUnlock()

	if !cfg.Enabled {
		return
	}

	now := time.Now().UTC()
	sampleHour := now.Truncate(time.Hour).Add(-time.Hour) // the hour that just ended
	slot := SlotIndex(sampleHour)
	isoYear, isoWeek := sampleHour.ISOWeek()
	yearWeek := isoYear*100 + isoWeek

	// Query P95 from ts_stats for the closed hour that just ended
	hourEnd := now.Truncate(time.Hour)        // e.g. 14:00 UTC
	hourStart := hourEnd.Add(-time.Hour)      // e.g. 13:00 UTC

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	p95Results, err := e.statsRepo.QueryHourP95(ctx, hourStart, hourEnd, 30)
	if err != nil {
		log.Printf("profile engine: QueryHourP95 failed: %v", err)
		return
	}

	var updated []store.PrefixProfile

	for _, r := range p95Results {
		key := profileMapKey(r.NodeID, r.Prefix, slot)

		e.mu.Lock()
		existing := e.profiles[key]
		var profile store.PrefixProfile
		if existing != nil {
			profile = *existing
		} else {
			profile = store.PrefixProfile{
				NodeID:    r.NodeID,
				Prefix:    r.Prefix,
				SlotIndex: slot,
			}
		}

		// Skip if already updated this week
		if profile.LastSampleYW == yearWeek {
			e.mu.Unlock()
			continue
		}

		// EWMA update
		alpha := cfg.EWMAAlpha
		if profile.SampleWeeks == 0 {
			profile.ExpectedPPS = r.P95PPS
			profile.ExpectedBPS = r.P95BPS
		} else {
			profile.ExpectedPPS = int64(float32(r.P95PPS)*alpha + float32(profile.ExpectedPPS)*(1-alpha))
			profile.ExpectedBPS = int64(float32(r.P95BPS)*alpha + float32(profile.ExpectedBPS)*(1-alpha))
		}
		profile.SampleWeeks++
		profile.LastSampleYW = yearWeek

		e.profiles[key] = &profile
		e.mu.Unlock()

		updated = append(updated, profile)
	}

	if len(updated) > 0 {
		if err := e.repo.BulkUpsertProfiles(ctx, updated); err != nil {
			log.Printf("profile engine: bulk upsert failed: %v", err)
		} else {
			log.Printf("profile engine: updated %d profiles for slot %d (%s)", len(updated), slot, SlotLabel(slot))
		}
	}
}

// StatusForSlot returns profile status for a given slot index.
func (e *ProfileEngine) StatusForSlot(slotIndex int) []ProfileStatus {
	e.mu.RLock()
	defer e.mu.RUnlock()

	var result []ProfileStatus
	for _, p := range e.profiles {
		if p.SlotIndex != slotIndex {
			continue
		}
		status := "learning"
		if p.SampleWeeks >= 1 {
			status = "active"
		}
		result = append(result, ProfileStatus{
			Prefix:      p.Prefix,
			NodeID:      p.NodeID,
			SlotIndex:   p.SlotIndex,
			ExpectedPPS: p.ExpectedPPS,
			ExpectedBPS: p.ExpectedBPS,
			SampleWeeks: p.SampleWeeks,
			Status:      status,
		})
	}

	// Sort by prefix for stable output
	sort.Slice(result, func(i, j int) bool {
		if result[i].Prefix != result[j].Prefix {
			return result[i].Prefix < result[j].Prefix
		}
		return result[i].NodeID < result[j].NodeID
	})

	return result
}

// Config returns a copy of the current config.
func (e *ProfileEngine) Config() store.DynDetectConfig {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.config
}

// Rings returns the underlying ring store (used by the status API to read current traffic).
func (e *ProfileEngine) Rings() *ring.RingStore {
	return e.rings
}

// ComputeThreshold calculates the dynamic threshold for a given expected value and config.
func (e *ProfileEngine) ComputeThreshold(expected int64, sampleWeeks int) int64 {
	e.mu.RLock()
	cfg := e.config
	e.mu.RUnlock()

	if sampleWeeks < 1 {
		return 0
	}
	progress := float64(sampleWeeks)
	if progress > float64(cfg.StableWeeks) {
		progress = float64(cfg.StableWeeks)
	}
	progress = progress / float64(cfg.StableWeeks)
	deviation := float64(cfg.DeviationMax) - progress*(float64(cfg.DeviationMax)-float64(cfg.DeviationMin))
	return expected * (100 + int64(deviation)) / 100
}
