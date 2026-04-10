// Package baseline implements dynamic threshold calculation via P95 baselines.
package baseline

import (
	"context"
	"log"
	"sync"
	"time"

	"github.com/littlewolf9527/xsight/controller/internal/store"
)

// Config holds baseline calculation parameters.
type Config struct {
	WindowDuration time.Duration // 1h / 1d / 1w (default 1d = 86400s)
	Multiplier     float64       // trigger multiplier (default 3.0)
	MinDataPoints  int           // minimum points before baseline activates
}

func DefaultConfig() Config {
	return Config{
		WindowDuration: 1 * time.Hour, // initial default, subject to tuning
		Multiplier:     3.0,
		MinDataPoints:  60, // minimum 60 data points from ts_stats
	}
}

// Baseline holds the computed baseline and dynamic threshold for one entity.
type Baseline struct {
	P95PPS     int64
	P95BPS     int64
	ThreshPPS  int64 // = P95PPS × Multiplier
	ThreshBPS  int64
	DataPoints int
	Active     bool // false during cold start
	ComputedAt time.Time
}

// Calculator manages per-(nodeID, prefix) dynamic baselines.
type Calculator struct {
	mu        sync.RWMutex
	statsRepo store.StatsRepo
	cfg       Config
	baselines map[string]*Baseline // "nodeID:prefix" → baseline
}

func NewCalculator(statsRepo store.StatsRepo, cfg Config) *Calculator {
	return &Calculator{
		statsRepo: statsRepo,
		cfg:       cfg,
		baselines: make(map[string]*Baseline),
	}
}

// baselineKey builds "nodeID:prefix" key.
func baselineKey(nodeID, prefix string) string { return nodeID + ":" + prefix }

// Recompute recalculates baselines for all tracked (nodeID, prefix) pairs.
// Called every 1 minute from a background goroutine.
// Reads P95 from ts_stats (not ring buffer) for accurate long-window statistics.
func (c *Calculator) Recompute() {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	now := time.Now().UTC()
	results, err := c.statsRepo.QueryWindowP95(ctx, now, c.cfg.WindowDuration, c.cfg.MinDataPoints)
	if err != nil {
		log.Printf("baseline: QueryWindowP95 failed: %v", err)
		return
	}

	// Build fresh map from current query results — stale entries are automatically dropped
	fresh := make(map[string]*Baseline, len(results))

	for _, r := range results {
		key := baselineKey(r.NodeID, r.Prefix)
		bl := &Baseline{
			DataPoints: r.DataPoints,
			ComputedAt: now,
		}

		// Cold start: not enough data
		if r.DataPoints < c.cfg.MinDataPoints {
			bl.Active = false
			fresh[key] = bl
			continue
		}

		bl.P95PPS = r.P95PPS
		bl.P95BPS = r.P95BPS
		bl.ThreshPPS = int64(float64(bl.P95PPS) * c.cfg.Multiplier)
		bl.ThreshBPS = int64(float64(bl.P95BPS) * c.cfg.Multiplier)
		bl.Active = true

		fresh[key] = bl
	}

	c.mu.Lock()
	c.baselines = fresh
	c.mu.Unlock()

	activeCount := 0
	for _, bl := range fresh {
		if bl.Active {
			activeCount++
		}
	}
	if activeCount > 0 {
		log.Printf("baseline: recomputed %d (node,prefix) pairs from ts_stats, %d active baselines", len(results), activeCount)
	}
}

// Get returns the baseline for a specific (nodeID, prefix) pair (nil if not computed).
func (c *Calculator) Get(nodeID, prefix string) *Baseline {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.baselines[baselineKey(nodeID, prefix)]
}

// GetForPrefix returns the best baseline across all nodes for a given prefix.
// Used by the recommendation API which is prefix-oriented (not node-specific).
// Picks the active baseline with the most data points; falls back to any baseline.
func (c *Calculator) GetForPrefix(prefix string) *Baseline {
	c.mu.RLock()
	defer c.mu.RUnlock()
	var best *Baseline
	for key, bl := range c.baselines {
		// key = "nodeID:prefix", check suffix
		if len(key) > len(prefix) && key[len(key)-len(prefix):] == prefix && key[len(key)-len(prefix)-1] == ':' {
			if best == nil || (bl.Active && !best.Active) || (bl.Active == best.Active && bl.DataPoints > best.DataPoints) {
				best = bl
			}
		}
	}
	return best
}

// IsExceeded checks if the current value exceeds the dynamic threshold for a (nodeID, prefix).
// Returns false during cold start (not active).
func (c *Calculator) IsExceeded(nodeID, prefix string, currentPPS, currentBPS int64) (exceeded bool, reason string) {
	c.mu.RLock()
	bl := c.baselines[baselineKey(nodeID, prefix)]
	c.mu.RUnlock()

	if bl == nil || !bl.Active {
		return false, ""
	}

	if currentPPS > bl.ThreshPPS {
		return true, "dynamic_pps_exceeded"
	}
	if currentBPS > bl.ThreshBPS {
		return true, "dynamic_bps_exceeded"
	}
	return false, ""
}


