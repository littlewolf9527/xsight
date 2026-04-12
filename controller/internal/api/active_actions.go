package api

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/littlewolf9527/xsight/controller/internal/store"
)

// ActiveResponseAction is the aggregated view of an active xDrop rule or BGP route.
type ActiveResponseAction struct {
	AttackID       int        `json:"attack_id"`
	AttackDstIP    string     `json:"attack_dst_ip"`
	ActionID       int        `json:"action_id"`
	ActionType     string     `json:"action_type"` // "xdrop" | "bgp"
	ConnectorName  string     `json:"connector_name"`
	ConnectorID    int        `json:"connector_id"`
	ExternalRuleID string     `json:"external_rule_id"`
	CreatedAt      time.Time  `json:"created_at"`
	Status         string     `json:"status"` // active | delayed | pending | failed
	ScheduledFor   *time.Time `json:"scheduled_for,omitempty"`
	// xDrop-specific (parsed from request_body)
	DstIP    string `json:"dst_ip,omitempty"`
	Protocol string `json:"protocol,omitempty"`
	TcpFlags string `json:"tcp_flags,omitempty"`
	Action   string `json:"action,omitempty"` // drop | rate_limit
	// BGP-specific (parsed from external_rule_id)
	Prefix   string `json:"prefix,omitempty"`
	RouteMap string `json:"route_map,omitempty"`
}

func listActiveBGPRoutes(deps Dependencies) gin.HandlerFunc {
	return func(c *gin.Context) {
		actions, err := buildActiveActions(c, deps.Store, "bgp")
		if err != nil {
			errResponse(c, http.StatusInternalServerError, err.Error())
			return
		}
		ok(c, actions)
	}
}

func listActiveXDropRules(deps Dependencies) gin.HandlerFunc {
	return func(c *gin.Context) {
		actions, err := buildActiveActions(c, deps.Store, "xdrop")
		if err != nil {
			errResponse(c, http.StatusInternalServerError, err.Error())
			return
		}
		ok(c, actions)
	}
}

// buildActiveActions queries action_execution_log and derives status for active xDrop/BGP artifacts.
func buildActiveActions(ctx *gin.Context, s store.Store, actionType string) ([]ActiveResponseAction, error) {
	// Get all active attacks + recently expired (last 24h) to show delayed items
	activeAttacks, err := s.Attacks().ListActive(ctx, 1000)
	if err != nil {
		return nil, err
	}
	recentFilter := store.AttackFilter{
		Status: "expired",
		Limit:  500,
	}
	recentFrom := time.Now().Add(-24 * time.Hour)
	recentFilter.TimeFrom = &recentFrom
	recentAttacks, _ := s.Attacks().List(ctx, recentFilter)

	allAttacks := append(activeAttacks, recentAttacks...)

	var result []ActiveResponseAction
	now := time.Now()

	for _, atk := range allAttacks {
		logs, err := s.ActionExecLog().ListByAttack(ctx, atk.ID)
		if err != nil {
			continue
		}

		// Find on_detected success logs for this action type
		for _, log := range logs {
			if log.ActionType != actionType || log.TriggerPhase != "on_detected" || log.Status != "success" || log.ExternalRuleID == "" {
				continue
			}

			connID := 0
			if log.ConnectorID != nil {
				connID = *log.ConnectorID
			}

			// Check if already withdrawn/unblocked
			withdrawn := false
			var scheduledFor *time.Time
			for _, l2 := range logs {
				if l2.ActionType != actionType && l2.ActionType != "manual_override" {
					continue
				}
				c2 := 0
				if l2.ConnectorID != nil {
					c2 = *l2.ConnectorID
				}
				if l2.ExternalRuleID == log.ExternalRuleID && c2 == connID {
					if (l2.TriggerPhase == "on_expired" || l2.TriggerPhase == "manual_override") && l2.Status == "success" {
						withdrawn = true
						break
					}
					if l2.Status == "scheduled" && l2.ScheduledFor != nil {
						scheduledFor = l2.ScheduledFor
					}
				}
			}
			if withdrawn {
				continue
			}

			// Derive status
			status := "active"
			if atk.EndedAt != nil {
				if scheduledFor != nil && scheduledFor.After(now) {
					status = "delayed"
				} else {
					status = "pending"
				}
			}

			// Check for failed on_expired
			for _, l2 := range logs {
				if l2.ActionType == actionType && l2.TriggerPhase == "on_expired" && l2.Status == "failed" {
					c2 := 0
					if l2.ConnectorID != nil {
						c2 = *l2.ConnectorID
					}
					if l2.ExternalRuleID == log.ExternalRuleID && c2 == connID {
						status = "failed"
					}
				}
			}

			item := ActiveResponseAction{
				AttackID:       atk.ID,
				AttackDstIP:    atk.DstIP,
				ActionID:       log.ActionID,
				ActionType:     actionType,
				ConnectorName:  log.ConnectorName,
				ConnectorID:    connID,
				ExternalRuleID: log.ExternalRuleID,
				CreatedAt:      log.ExecutedAt,
				Status:         status,
				ScheduledFor:   scheduledFor,
			}

			// Parse type-specific fields
			if actionType == "bgp" {
				// Split on "|" (v1.1.1+); fallback to last ":" for backward compat
				prefix, routeMap := splitBGPRuleID(log.ExternalRuleID)
				item.Prefix = prefix
				item.RouteMap = routeMap
			} else if actionType == "xdrop" {
				item.DstIP = atk.DstIP
				// Parse action/protocol from request_body if available
				if log.RequestBody != "" {
					parseXDropRequestBody(log.RequestBody, &item)
				}
			}

			result = append(result, item)
		}
	}

	return result, nil
}

func splitN(s, sep string, n int) []string {
	result := make([]string, 0, n)
	for i := 0; i < n-1; i++ {
		idx := -1
		for j := 0; j < len(s); j++ {
			if string(s[j]) == sep {
				idx = j
				break
			}
		}
		if idx < 0 {
			break
		}
		result = append(result, s[:idx])
		s = s[idx+1:]
	}
	result = append(result, s)
	return result
}

// splitBGPRuleID splits "{prefix}|{route_map}" or legacy "{prefix}:{route_map}".
// Uses "|" first (v1.1.1+); falls back to last ":" for backward compat with IPv4 records.
func splitBGPRuleID(ruleID string) (prefix, routeMap string) {
	if idx := strings.LastIndex(ruleID, "|"); idx >= 0 {
		return ruleID[:idx], ruleID[idx+1:]
	}
	// Backward compat: old records used ":" separator.
	// Use LastIndex to handle IPv6 like "2001:db8::1/128:RTBH".
	if idx := strings.LastIndex(ruleID, ":"); idx >= 0 {
		return ruleID[:idx], ruleID[idx+1:]
	}
	return ruleID, ""
}

func parseXDropRequestBody(body string, item *ActiveResponseAction) {
	// Simple JSON field extraction without full unmarshal
	var m map[string]any
	if err := json.Unmarshal([]byte(body), &m); err != nil {
		return
	}
	if v, ok := m["action"].(string); ok {
		item.Action = v
	}
	if v, ok := m["protocol"].(string); ok {
		item.Protocol = v
	}
	if v, ok := m["tcp_flags"].(string); ok {
		item.TcpFlags = v
	}
	if v, ok := m["dst_ip"].(string); ok {
		item.DstIP = v
	}
}

func forceRemoveAction(deps Dependencies) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req struct {
			AttackID       int    `json:"attack_id" binding:"required"`
			ActionID       int    `json:"action_id" binding:"required"`
			ConnectorID    int    `json:"connector_id" binding:"required"`
			ExternalRuleID string `json:"external_rule_id" binding:"required"`
		}
		if err := c.ShouldBindJSON(&req); err != nil {
			errResponse(c, http.StatusBadRequest, err.Error())
			return
		}

		// Cancel pending delay for this specific artifact (full business key)
		if deps.ActionEngine != nil {
			deps.ActionEngine.CancelDelay(req.AttackID, req.ActionID, req.ConnectorID, req.ExternalRuleID)
		}

		// Execute the removal first, then write log with actual result
		removeErr := deps.ActionEngine.ForceRemove(c, req.AttackID, req.ActionID, req.ConnectorID, req.ExternalRuleID)

		overrideLog := &store.ActionExecutionLog{
			AttackID:       req.AttackID,
			ActionID:       req.ActionID,
			ActionType:     "manual_override",
			TriggerPhase:   "manual_override",
			ConnectorID:    &req.ConnectorID,
			ExternalRuleID: req.ExternalRuleID,
			ExecutedAt:     time.Now(),
		}
		if removeErr != nil {
			overrideLog.Status = "failed"
			overrideLog.ErrorMessage = removeErr.Error()
			overrideLog.ResponseBody = "force remove failed"
		} else {
			overrideLog.Status = "success"
			overrideLog.ResponseBody = "force removed by user"
		}
		if _, err := deps.Store.ActionExecLog().Create(c, overrideLog); err != nil {
			// External removal already executed — log write failed but artifact is gone
			log.Printf("action: force-remove audit log write failed (artifact already removed externally): %v", err)
			ok(c, gin.H{
				"ok":      true,
				"warning": "force remove succeeded but audit log write failed — artifact was removed externally",
			})
			return
		}

		// Write audit log
		auditDiff, _ := json.Marshal(map[string]any{
			"user":             c.GetString("username"),
			"attack_id":        req.AttackID,
			"action_id":        req.ActionID,
			"connector_id":     req.ConnectorID,
			"external_rule_id": req.ExternalRuleID,
			"result":           overrideLog.Status,
		})
		publishAfterChange(c, deps, "active_action", fmt.Sprintf("attack:%d:rule:%s", req.AttackID, req.ExternalRuleID),
			"force_remove", json.RawMessage(auditDiff))

		if removeErr != nil {
			errResponse(c, http.StatusInternalServerError, fmt.Sprintf("force remove failed: %v", removeErr))
			return
		}

		ok(c, gin.H{
			"ok":      true,
			"message": fmt.Sprintf("force removed %s (attack #%d)", req.ExternalRuleID, req.AttackID),
		})
	}
}

// getArtifactTimeline returns the full execution log timeline for a single mitigation artifact.
func getArtifactTimeline(deps Dependencies) gin.HandlerFunc {
	return func(c *gin.Context) {
		attackID, _ := strconv.Atoi(c.Query("attack_id"))
		connectorID, _ := strconv.Atoi(c.Query("connector_id"))
		externalRuleID := c.Query("external_rule_id")
		if attackID == 0 || externalRuleID == "" {
			errResponse(c, http.StatusBadRequest, "attack_id and external_rule_id are required")
			return
		}

		logs, err := deps.Store.ActionExecLog().ListByAttack(c, attackID)
		if err != nil {
			errResponse(c, http.StatusInternalServerError, err.Error())
			return
		}

		// Filter logs matching this artifact's business key
		var timeline []store.ActionExecutionLog
		for _, l := range logs {
			if l.ExternalRuleID != externalRuleID {
				continue
			}
			cid := 0
			if l.ConnectorID != nil {
				cid = *l.ConnectorID
			}
			if connectorID > 0 && cid > 0 && cid != connectorID {
				continue
			}
			timeline = append(timeline, l)
		}

		// Reverse to chronological order (ListByAttack returns DESC)
		for i, j := 0, len(timeline)-1; i < j; i, j = i+1, j-1 {
			timeline[i], timeline[j] = timeline[j], timeline[i]
		}

		atk, _ := deps.Store.Attacks().Get(c, attackID)

		ok(c, gin.H{
			"attack": atk,
			"logs":   timeline,
		})
	}
}

