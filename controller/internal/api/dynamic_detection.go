package api

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/littlewolf9527/xsight/controller/internal/engine/baseline"
	"github.com/littlewolf9527/xsight/controller/internal/store"
)

// timeNow is a package-level var for testing.
var timeNow = time.Now

// getDynDetectConfig returns the dynamic detection configuration.
func getDynDetectConfig(deps Dependencies) gin.HandlerFunc {
	return func(c *gin.Context) {
		cfg, err := deps.Store.DynDetect().GetConfig(c)
		if err != nil {
			errResponse(c, http.StatusInternalServerError, err.Error())
			return
		}
		ok(c, cfg)
	}
}

// updateDynDetectConfig updates the dynamic detection configuration.
func updateDynDetectConfig(deps Dependencies) gin.HandlerFunc {
	return func(c *gin.Context) {
		var cfg store.DynDetectConfig
		if err := c.ShouldBindJSON(&cfg); err != nil {
			errResponse(c, http.StatusBadRequest, err.Error())
			return
		}

		// Validate
		if cfg.DeviationMin < 0 || cfg.DeviationMax < 0 {
			errResponse(c, http.StatusBadRequest, "deviation values must be non-negative")
			return
		}
		if cfg.DeviationMin > cfg.DeviationMax {
			errResponse(c, http.StatusBadRequest, "deviation_min must be <= deviation_max")
			return
		}
		if cfg.StableWeeks < 1 {
			errResponse(c, http.StatusBadRequest, "stable_weeks must be >= 1")
			return
		}
		if cfg.EWMAAlpha <= 0 || cfg.EWMAAlpha >= 1 {
			errResponse(c, http.StatusBadRequest, "ewma_alpha must be between 0 and 1 (exclusive)")
			return
		}
		if cfg.MinPPS < 0 {
			errResponse(c, http.StatusBadRequest, "min_pps must be >= 0")
			return
		}
		if cfg.MinBPS < 0 {
			errResponse(c, http.StatusBadRequest, "min_bps must be >= 0")
			return
		}

		if err := deps.Store.DynDetect().UpdateConfig(c, &cfg); err != nil {
			errResponse(c, http.StatusInternalServerError, err.Error())
			return
		}

		// Refresh in-memory config in the profile engine
		if deps.ProfileEngine != nil {
			deps.ProfileEngine.RefreshConfig(c)
		}

		ok(c, cfg)
	}
}

// getDynDetectStatus returns the current dynamic detection status.
func getDynDetectStatus(deps Dependencies) gin.HandlerFunc {
	return func(c *gin.Context) {
		if deps.ProfileEngine == nil {
			errResponse(c, http.StatusServiceUnavailable, "profile engine not available")
			return
		}

		cfg := deps.ProfileEngine.Config()
		slot := baseline.SlotIndex(timeNow())
		label := baseline.SlotLabel(slot)

		statuses := deps.ProfileEngine.StatusForSlot(slot)

		// If current slot has no data, search backwards for the nearest slot with data (up to 168)
		if len(statuses) == 0 {
			for i := 1; i < 168; i++ {
				trySlot := (slot - i + 168) % 168
				statuses = deps.ProfileEngine.StatusForSlot(trySlot)
				if len(statuses) > 0 {
					label = baseline.SlotLabel(trySlot) + " (latest)"
					break
				}
			}
		}

		// Multi-node aggregation: group by prefix
		type prefixAgg struct {
			Prefix      string `json:"prefix"`
			ExpectedPPS int64  `json:"expected_pps"`
			ExpectedBPS int64  `json:"expected_bps"`
			CurrentPPS  int64  `json:"current_pps"`
			CurrentBPS  int64  `json:"current_bps"`
			ThreshPPS   int64  `json:"thresh_pps"`
			ThreshBPS   int64  `json:"thresh_bps"`
			SampleWeeks int    `json:"sample_weeks"`
			Status      string `json:"status"`
			NodeCount   int    `json:"node_count"`
		}

		// Read current traffic from ring buffer
		rings := deps.ProfileEngine.Rings()

		aggMap := make(map[string]*prefixAgg)
		for _, s := range statuses {
			// Get current PPS/BPS from ring buffer
			var curPPS, curBPS int64
			if rings != nil {
				if pr := rings.GetPrefixRing(s.NodeID, s.Prefix); pr != nil {
					if dp, ok := pr.LatestOne(10 * time.Second); ok {
						curPPS = dp.PPS
						curBPS = dp.BPS
					}
				}
			}

			// Compute thresholds using progressive deviation
			threshPPS := deps.ProfileEngine.ComputeThreshold(s.ExpectedPPS, s.SampleWeeks)
			threshBPS := deps.ProfileEngine.ComputeThreshold(s.ExpectedBPS, s.SampleWeeks)

			agg, exists := aggMap[s.Prefix]
			if !exists {
				agg = &prefixAgg{
					Prefix:      s.Prefix,
					ExpectedPPS: s.ExpectedPPS,
					ExpectedBPS: s.ExpectedBPS,
					CurrentPPS:  curPPS,
					CurrentBPS:  curBPS,
					ThreshPPS:   threshPPS,
					ThreshBPS:   threshBPS,
					SampleWeeks: s.SampleWeeks,
				}
				aggMap[s.Prefix] = agg
			} else {
				// Take max expected for thresholds
				if s.ExpectedPPS > agg.ExpectedPPS {
					agg.ExpectedPPS = s.ExpectedPPS
				}
				if s.ExpectedBPS > agg.ExpectedBPS {
					agg.ExpectedBPS = s.ExpectedBPS
				}
				// Sum current traffic across nodes
				agg.CurrentPPS += curPPS
				agg.CurrentBPS += curBPS
				// Take max threshold
				if threshPPS > agg.ThreshPPS {
					agg.ThreshPPS = threshPPS
				}
				if threshBPS > agg.ThreshBPS {
					agg.ThreshBPS = threshBPS
				}
				// Take min sample_weeks for status (most conservative)
				if s.SampleWeeks < agg.SampleWeeks {
					agg.SampleWeeks = s.SampleWeeks
				}
			}
			agg.NodeCount++
		}

		// Compute status dynamically for each prefix
		var prefixes []prefixAgg
		for _, agg := range aggMap {
			if agg.SampleWeeks < 1 {
				agg.Status = "learning"
			} else if agg.CurrentPPS > agg.ThreshPPS || agg.CurrentBPS > agg.ThreshBPS {
				agg.Status = "exceeded"
			} else {
				agg.Status = "normal"
			}
			prefixes = append(prefixes, *agg)
		}

		activatedCount := 0
		learningCount := 0
		for _, p := range prefixes {
			if p.Status != "learning" {
				activatedCount++
			} else {
				learningCount++
			}
		}

		ok(c, gin.H{
			"enabled":          cfg.Enabled,
			"current_slot":     slot,
			"current_slot_label": label,
			"total_prefixes":   len(prefixes),
			"activated_count":  activatedCount,
			"learning_count":   learningCount,
			"prefixes":         prefixes,
		})
	}
}
