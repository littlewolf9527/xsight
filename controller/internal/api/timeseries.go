package api

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/littlewolf9527/xsight/controller/internal/store"
)

func queryTimeseries(deps Dependencies) gin.HandlerFunc {
	return func(c *gin.Context) {
		resolution := c.DefaultQuery("resolution", "5min")
		// Dynamic limit based on resolution to avoid truncation
		limit := 1000
		switch resolution {
		case "5s":
			limit = 7200 // up to 10h of 5s data
		case "5min":
			limit = 2000 // up to ~7 days of 5min data
		case "1h":
			limit = 1000 // up to ~41 days of 1h data
		}
		dir := c.Query("direction")
		if dir != "" && dir != "receives" && dir != "sends" && dir != "both" {
			errResponse(c, http.StatusBadRequest, "direction must be 'receives', 'sends', or 'both'")
			return
		}
		filter := store.TimeseriesFilter{
			Prefix:     c.Query("prefix"),
			NodeID:     c.Query("node_id"),
			Resolution: resolution,
			Direction:  dir,
			Limit:      limit,
		}
		if from := c.Query("from"); from != "" {
			if t, err := time.Parse(time.RFC3339, from); err == nil {
				filter.From = t
			}
		}
		if to := c.Query("to"); to != "" {
			if t, err := time.Parse(time.RFC3339, to); err == nil {
				filter.To = t
			}
		}
		// Default: last 1 hour
		if filter.From.IsZero() {
			filter.From = time.Now().Add(-1 * time.Hour)
		}

		points, err := deps.Store.Stats().QueryTimeseries(c, filter)
		if err != nil {
			errResponse(c, http.StatusInternalServerError, err.Error())
			return
		}
		ok(c, points)
	}
}
