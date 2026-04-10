package api

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// listBaselines returns baseline P95 + recommended thresholds for all monitored prefixes.
func listBaselines(deps Dependencies) gin.HandlerFunc {
	return func(c *gin.Context) {
		if deps.BaselineCalc == nil {
			errResponse(c, http.StatusServiceUnavailable, "baseline calculator not available")
			return
		}

		prefixes, err := deps.Store.Prefixes().List(c)
		if err != nil {
			errResponse(c, http.StatusInternalServerError, err.Error())
			return
		}

		type baselineInfo struct {
			Prefix         string `json:"prefix"`
			P95PPS         int64  `json:"p95_pps"`
			P95BPS         int64  `json:"p95_bps"`
			RecommendPPS   int64  `json:"recommend_pps"`   // P95 × 2 — conservative manual threshold suggestion
			RecommendBPS   int64  `json:"recommend_bps"`   // P95 × 2
			DetectThreshPPS int64 `json:"detect_thresh_pps"` // P95 × 3 — runtime dynamic detection trigger
			DetectThreshBPS int64 `json:"detect_thresh_bps"` // P95 × 3
			DataPoints     int    `json:"data_points"`
			Active         bool   `json:"active"` // false = cold start
			Source         string `json:"source"` // "best_node" = node with most data points
		}

		var result []baselineInfo
		for _, p := range prefixes {
			if !p.Enabled {
				continue
			}
			bl := deps.BaselineCalc.GetForPrefix(p.Prefix)
			if bl == nil {
				result = append(result, baselineInfo{
					Prefix: p.Prefix,
					Active: false,
					Source: "best_node",
				})
				continue
			}
			result = append(result, baselineInfo{
				Prefix:          p.Prefix,
				P95PPS:          bl.P95PPS,
				P95BPS:          bl.P95BPS,
				RecommendPPS:    bl.P95PPS * 2,
				RecommendBPS:    bl.P95BPS * 2,
				DetectThreshPPS: bl.ThreshPPS, // P95 × Multiplier (default 3.0)
				DetectThreshBPS: bl.ThreshBPS,
				DataPoints:      bl.DataPoints,
				Active:          bl.Active,
				Source:          "best_node",
			})
		}

		ok(c, result)
	}
}
