package api

import (
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/littlewolf9527/xsight/controller/internal/store"
)

func listAttacks(deps Dependencies) gin.HandlerFunc {
	return func(c *gin.Context) {
		filter := store.AttackFilter{
			Limit:  50,
			Offset: 0,
		}
		if s := c.Query("status"); s != "" {
			filter.Status = s
		}
		if d := c.Query("direction"); d != "" {
			if d != "receives" && d != "sends" {
				errResponse(c, http.StatusBadRequest, "direction must be 'receives' or 'sends'")
				return
			}
			filter.Direction = d
		}
		if pid := c.Query("prefix_id"); pid != "" {
			id, _ := strconv.Atoi(pid)
			filter.PrefixID = &id
		}
		if from := c.Query("from"); from != "" {
			if t, err := time.Parse(time.RFC3339, from); err == nil {
				filter.TimeFrom = &t
			}
		}
		if to := c.Query("to"); to != "" {
			if t, err := time.Parse(time.RFC3339, to); err == nil {
				filter.TimeTo = &t
			}
		}
		if lim := c.Query("limit"); lim != "" {
			filter.Limit, _ = strconv.Atoi(lim)
		}
		if off := c.Query("offset"); off != "" {
			filter.Offset, _ = strconv.Atoi(off)
		}
		// Hard cap to prevent oversized responses
		if filter.Limit > 200 {
			filter.Limit = 200
		}

		attacks, err := deps.Store.Attacks().List(c, filter)
		if err != nil {
			errResponse(c, http.StatusInternalServerError, err.Error())
			return
		}
		total, _ := deps.Store.Attacks().Count(c, filter)
		ok(c, gin.H{
			"attacks": attacks,
			"total":   total,
		})
	}
}

func listActiveAttacks(deps Dependencies) gin.HandlerFunc {
	return func(c *gin.Context) {
		limit := 100
		if l := c.Query("limit"); l != "" {
			limit, _ = strconv.Atoi(l)
		}
		attacks, err := deps.Store.Attacks().ListActive(c, limit)
		if err != nil {
			errResponse(c, http.StatusInternalServerError, err.Error())
			return
		}
		activeCount, _ := deps.Store.Attacks().CountActive(c)
		ok(c, gin.H{
			"attacks":       attacks,
			"active_count":  activeCount,
			"returned":      len(attacks),
			"tracker_count": deps.Tracker.ActiveCount(),
		})
	}
}

func getAttackActionLog(deps Dependencies) gin.HandlerFunc {
	return func(c *gin.Context) {
		id, err := strconv.Atoi(c.Param("id"))
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid attack id"})
			return
		}
		logs, err := deps.Store.ActionExecLog().ListByAttack(c, id)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		if logs == nil {
			logs = []store.ActionExecutionLog{}
		}
		c.JSON(http.StatusOK, logs)
	}
}

func statsSummary(deps Dependencies) gin.HandlerFunc {
	return func(c *gin.Context) {
		activeCount, _ := deps.Store.Attacks().CountActive(c)

		// Count-oriented: don't pull full lists just to len()
		nodes, _ := deps.Store.Nodes().List(c) // small table, OK
		onlineCount := 0
		for _, n := range nodes {
			if deps.NodeState.IsOnline(n.ID) {
				onlineCount++
			}
		}

		prefixCount, _ := deps.Store.Prefixes().Count(c)
		thresholdCount, _ := deps.Store.Thresholds().Count(c)

		ok(c, gin.H{
			"active_attacks":      activeCount,
			"total_nodes":         len(nodes),
			"online_nodes":        onlineCount,
			"total_prefixes":      prefixCount,
			"total_thresholds":    thresholdCount,
			"tracker_count":       deps.Tracker.ActiveCount(),
			"attacks_created":     deps.Tracker.CreatedTotal.Load(),
			"attacks_suppressed":  deps.Tracker.SuppressedTotal.Load(),
			"attacks_evicted":     deps.Tracker.EvictedTotal.Load(),
		})
	}
}

func getAttack(deps Dependencies) gin.HandlerFunc {
	return func(c *gin.Context) {
		id, _ := strconv.Atoi(c.Param("id"))
		attack, err := deps.Store.Attacks().Get(c, id)
		if err != nil {
			errResponse(c, http.StatusNotFound, "attack not found")
			return
		}
		// Include action execution logs (Response System v2)
		logs, err := deps.Store.ActionExecLog().ListByAttack(c, id)
		if err != nil {
			errResponse(c, http.StatusInternalServerError, "failed to load action logs: "+err.Error())
			return
		}
		ok(c, gin.H{"attack": attack, "actions_log": logs})
	}
}

func expireAttack(deps Dependencies) gin.HandlerFunc {
	return func(c *gin.Context) {
		id, err := strconv.Atoi(c.Param("id"))
		if err != nil {
			errResponse(c, http.StatusBadRequest, "invalid attack id")
			return
		}
		attack, err := deps.Store.Attacks().Get(c, id)
		if err != nil {
			errResponse(c, http.StatusNotFound, "attack not found")
			return
		}
		if attack.EndedAt != nil {
			errResponse(c, http.StatusConflict, "attack already expired")
			return
		}
		// Try tracker first (in-memory active attack)
		if deps.Tracker.ForceExpire(id) {
			ok(c, gin.H{"ok": true, "method": "tracker"})
			return
		}
		// Fallback: attack not in tracker memory (degraded recovery / stale DB row).
		// Update DB + notify action engine for on_expired cleanup (unblock etc.)
		now := time.Now()
		attack.EndedAt = &now
		if err := deps.Store.Attacks().Update(c, attack); err != nil {
			errResponse(c, http.StatusInternalServerError, err.Error())
			return
		}
		deps.Tracker.NotifyExpired(attack)
		ok(c, gin.H{"ok": true, "method": "db"})
	}
}

func getAttackSensorLogs(deps Dependencies) gin.HandlerFunc {
	return func(c *gin.Context) {
		id, err := strconv.Atoi(c.Param("id"))
		if err != nil {
			errResponse(c, http.StatusBadRequest, "invalid attack id")
			return
		}

		attack, err := deps.Store.Attacks().Get(c, id)
		if err != nil {
			errResponse(c, http.StatusNotFound, "attack not found")
			return
		}

		// Global attacks (0.0.0.0/0) have no per-flow detail
		if attack.DstIP == "0.0.0.0/0" {
			ok(c, gin.H{"flows": []store.FlowLog{}, "total": 0, "expired": false})
			return
		}

		// Time window: attack start → end (or now if still active)
		// For active attacks, cap query window to last 1 hour to avoid timeout on long-running attacks
		to := time.Now()
		from := attack.StartedAt
		window := "full"
		if attack.EndedAt != nil {
			to = *attack.EndedAt
		} else {
			// Active attack: only query last 1 hour
			oneHourAgo := to.Add(-1 * time.Hour)
			if from.Before(oneHourAgo) {
				from = oneHourAgo
				window = "last_1h"
			}
		}

		limit := 1000
		if l := c.Query("limit"); l != "" {
			limit, _ = strconv.Atoi(l)
		}
		if limit > 10000 {
			limit = 10000
		}

		filter := store.FlowLogFilter{
			DstIP: attack.DstIP,
			From:  from,
			To:    to,
			Limit: limit,
		}

		// Outbound attacks: query by src_ip instead of dst_ip
		var flows []store.FlowLog
		if attack.Direction == "sends" {
			flows, err = deps.Store.FlowLogs().QueryBySrcIP(c, filter)
		} else {
			flows, err = deps.Store.FlowLogs().QueryByDstIP(c, filter)
		}
		if err != nil {
			errResponse(c, http.StatusInternalServerError, err.Error())
			return
		}
		if flows == nil {
			flows = []store.FlowLog{}
		}

		// Determine if flow data is expired (attack started before retention cutoff)
		expired := false
		if len(flows) == 0 && attack.EndedAt != nil && deps.FlowLogsDays > 0 {
			cutoff := time.Now().AddDate(0, 0, -deps.FlowLogsDays)
			if attack.StartedAt.Before(cutoff) {
				expired = true
			}
		}

		ok(c, gin.H{
			"flows":   flows,
			"total":   len(flows),
			"expired": expired,
			"window":  window,
		})
	}
}

func listAuditLog(deps Dependencies) gin.HandlerFunc {
	return func(c *gin.Context) {
		filter := store.AuditFilter{
			Limit:  50,
			Offset: 0,
		}
		if et := c.Query("entity_type"); et != "" {
			filter.EntityType = et
		}
		if uid := c.Query("user_id"); uid != "" {
			id, _ := strconv.Atoi(uid)
			filter.UserID = &id
		}
		if lim := c.Query("limit"); lim != "" {
			filter.Limit, _ = strconv.Atoi(lim)
		}
		if off := c.Query("offset"); off != "" {
			filter.Offset, _ = strconv.Atoi(off)
		}

		logs, err := deps.Store.AuditLog().List(c, filter)
		if err != nil {
			errResponse(c, http.StatusInternalServerError, err.Error())
			return
		}
		ok(c, logs)
	}
}
