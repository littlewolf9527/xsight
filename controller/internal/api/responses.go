package api

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/littlewolf9527/xsight/controller/internal/store"
)

// --- Responses ---

func listResponses(deps Dependencies) gin.HandlerFunc {
	return func(c *gin.Context) {
		responses, err := deps.Store.Responses().List(c)
		if err != nil {
			errResponse(c, http.StatusInternalServerError, err.Error())
			return
		}
		ok(c, responses)
	}
}

func createResponse(deps Dependencies) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req struct {
			Name        string `json:"name" binding:"required"`
			Description string `json:"description"`
			Enabled     *bool  `json:"enabled"`
		}
		if err := c.ShouldBindJSON(&req); err != nil {
			errResponse(c, http.StatusBadRequest, err.Error())
			return
		}
		enabled := true
		if req.Enabled != nil {
			enabled = *req.Enabled
		}
		id, err := deps.Store.Responses().Create(c, &store.Response{
			Name: req.Name, Description: req.Description, Enabled: enabled,
		})
		if err != nil {
			errResponse(c, http.StatusInternalServerError, err.Error())
			return
		}
		publishAfterChange(c, deps, "response", strconv.Itoa(id), "create", makeDiff(nil, store.Response{ID: id, Name: req.Name, Description: req.Description}))
		created(c, gin.H{"id": id})
	}
}

// actionView is the enriched read DTO for actions (includes connector_name, target_node_ids).
type actionView struct {
	store.ResponseAction
	ConnectorName  string   `json:"connector_name"`
	ConnectorID    *int     `json:"connector_id"`      // generic ID for UI
	TargetNodeIDs  []int    `json:"target_node_ids"`   // xDrop targets
	XDropFields    []string `json:"xdrop_fields"`      // derived from xdrop_custom_payload for UI
	XDropRateLimit *int     `json:"xdrop_rate_limit"`  // derived from xdrop_custom_payload for UI
}

func getResponse(deps Dependencies) gin.HandlerFunc {
	return func(c *gin.Context) {
		id, _ := strconv.Atoi(c.Param("id"))
		r, err := deps.Store.Responses().Get(c, id)
		if err != nil {
			errResponse(c, http.StatusNotFound, "response not found")
			return
		}
		// Include enriched actions
		actions, _ := deps.Store.Responses().ListActions(c, id)
		views := make([]actionView, len(actions))
		for i, act := range actions {
			v := actionView{ResponseAction: act}
			// Resolve connector name + generic ID
			switch act.ActionType {
			case "webhook":
				if act.WebhookConnectorID != nil {
					v.ConnectorID = act.WebhookConnectorID
					if wc, err := deps.Store.WebhookConnectors().Get(c, *act.WebhookConnectorID); err == nil {
						v.ConnectorName = wc.Name
					}
				}
			case "shell":
				if act.ShellConnectorID != nil {
					v.ConnectorID = act.ShellConnectorID
					if sc, err := deps.Store.ShellConnectors().Get(c, *act.ShellConnectorID); err == nil {
						v.ConnectorName = sc.Name
					}
				}
			case "xdrop":
				targets, _ := deps.Store.XDropTargets().List(c, act.ID)
				ids := make([]int, len(targets))
				for j, t := range targets {
					ids[j] = t.ID
				}
				v.TargetNodeIDs = ids
				if len(targets) > 0 {
					v.ConnectorName = targets[0].Name
					if len(targets) > 1 {
						v.ConnectorName += fmt.Sprintf(" (+%d)", len(targets)-1)
					}
				} else {
					v.ConnectorName = "(all)"
				}
				// Derive xdrop_fields and xdrop_rate_limit from xdrop_custom_payload for UI
				v.XDropFields, v.XDropRateLimit = parseXDropPayloadFields(act.XDropCustomPayload)
			case "bgp":
				if act.BGPConnectorID != nil {
					v.ConnectorID = act.BGPConnectorID
					if bc, err := deps.Store.BGPConnectors().Get(c, *act.BGPConnectorID); err == nil {
						v.ConnectorName = bc.Name
					}
				}
			}
			views[i] = v
		}
		ok(c, gin.H{"response": r, "actions": views})
	}
}

func updateResponse(deps Dependencies) gin.HandlerFunc {
	return func(c *gin.Context) {
		id, _ := strconv.Atoi(c.Param("id"))
		old, err := deps.Store.Responses().Get(c, id)
		if err != nil {
			errResponse(c, http.StatusNotFound, "response not found")
			return
		}
		var req struct {
			Name        string `json:"name"`
			Description string `json:"description"`
			Enabled     *bool  `json:"enabled"`
		}
		if err := c.ShouldBindJSON(&req); err != nil {
			errResponse(c, http.StatusBadRequest, err.Error())
			return
		}
		enabled := old.Enabled
		if req.Enabled != nil {
			enabled = *req.Enabled
		}
		if err := deps.Store.Responses().Update(c, &store.Response{
			ID: id, Name: req.Name, Description: req.Description, Enabled: enabled,
		}); err != nil {
			errResponse(c, http.StatusInternalServerError, err.Error())
			return
		}
		publishAfterChange(c, deps, "response", strconv.Itoa(id), "update", makeDiff(old, store.Response{ID: id, Name: req.Name, Description: req.Description}))
		ok(c, gin.H{"ok": true})
	}
}

func deleteResponse(deps Dependencies) gin.HandlerFunc {
	return func(c *gin.Context) {
		id, _ := strconv.Atoi(c.Param("id"))
		// Check if any template is using this response (fail closed on error)
		templates, err := deps.Store.ThresholdTemplates().List(c)
		if err != nil {
			errResponse(c, http.StatusInternalServerError, "failed to check response usage: "+err.Error())
			return
		}
		for _, t := range templates {
			if t.ResponseID != nil && *t.ResponseID == id {
				errResponse(c, http.StatusConflict,
					fmt.Sprintf("response in use by template %q (id=%d)", t.Name, t.ID))
				return
			}
		}
		// Check if any threshold rule is using this response
		thresholds, err := deps.Store.Thresholds().List(c)
		if err != nil {
			errResponse(c, http.StatusInternalServerError, "failed to check response usage: "+err.Error())
			return
		}
		for _, t := range thresholds {
			if t.ResponseID != nil && *t.ResponseID == id {
				errResponse(c, http.StatusConflict,
					fmt.Sprintf("response in use by threshold rule id=%d", t.ID))
				return
			}
		}
		old, _ := deps.Store.Responses().Get(c, id)
		if err := deps.Store.Responses().Delete(c, id); err != nil {
			errResponse(c, http.StatusInternalServerError, err.Error())
			return
		}
		publishAfterChange(c, deps, "response", strconv.Itoa(id), "delete", makeDiff(old, nil))
		ok(c, gin.H{"ok": true})
	}
}

// Note: response/action create/update also go through audit via publishAfterChange
// Response changes affect action execution but don't need Node config push

// --- Response Actions ---

func listActions(deps Dependencies) gin.HandlerFunc {
	return func(c *gin.Context) {
		respID, _ := strconv.Atoi(c.Param("id"))
		actions, err := deps.Store.Responses().ListActions(c, respID)
		if err != nil {
			errResponse(c, http.StatusInternalServerError, err.Error())
			return
		}
		ok(c, actions)
	}
}

// actionDTO is the API request/response shape for actions.
// Maps generic UI fields to typed backend fields.
type actionDTO struct {
	ActionType      string          `json:"action_type"`
	TriggerPhase    string          `json:"trigger_phase"`
	RunMode         string          `json:"run_mode"`
	PeriodSeconds   int             `json:"period_seconds"`
	Execution       string          `json:"execution"`
	Priority        int             `json:"priority"`
	Enabled         *bool           `json:"enabled"`
	ConnectorID     *int            `json:"connector_id"`      // generic: UI sends this
	TargetNodeIDs   []int           `json:"target_node_ids"`   // xDrop targets from UI
	XDropAction         string          `json:"xdrop_action"`
	XDropPayload        json.RawMessage `json:"xdrop_custom_payload"`
	ShellExtraArgs      string          `json:"shell_extra_args"`
	UnblockDelayMinutes int             `json:"unblock_delay_minutes"`
	BGPRouteMap         string          `json:"bgp_route_map"`
}

func dtoToAction(dto actionDTO, respID int) store.ResponseAction {
	enabled := true
	if dto.Enabled != nil {
		enabled = *dto.Enabled
	}
	act := store.ResponseAction{
		ResponseID:         respID,
		ActionType:         dto.ActionType,
		TriggerPhase:       dto.TriggerPhase,
		RunMode:            dto.RunMode,
		PeriodSeconds:      dto.PeriodSeconds,
		Execution:          dto.Execution,
		Priority:           dto.Priority,
		Enabled:            enabled,
		Config:             json.RawMessage(`{}`), // default empty JSON for legacy compat
		XDropAction:        dto.XDropAction,
		XDropCustomPayload: dto.XDropPayload,
		ShellExtraArgs:      dto.ShellExtraArgs,
		UnblockDelayMinutes: dto.UnblockDelayMinutes,
		BGPRouteMap:         dto.BGPRouteMap,
	}
	// Map generic connector_id to typed FK based on action_type
	if dto.ConnectorID != nil {
		switch dto.ActionType {
		case "webhook":
			act.WebhookConnectorID = dto.ConnectorID
		case "shell":
			act.ShellConnectorID = dto.ConnectorID
		case "bgp":
			act.BGPConnectorID = dto.ConnectorID
		}
	}
	// Map legacy execution_policy from new fields for backward compat
	switch {
	case dto.TriggerPhase == "on_detected" && dto.RunMode == "once":
		act.ExecutionPolicy = "once_on_enter"
	case dto.TriggerPhase == "on_expired" && dto.RunMode == "once":
		act.ExecutionPolicy = "once_on_exit"
	case dto.RunMode == "periodic":
		act.ExecutionPolicy = "periodic"
	case dto.RunMode == "retry_until_success":
		act.ExecutionPolicy = "retry_until_success"
	default:
		act.ExecutionPolicy = "once_on_enter"
	}
	return act
}

func createAction(deps Dependencies) gin.HandlerFunc {
	return func(c *gin.Context) {
		respID, _ := strconv.Atoi(c.Param("id"))
		var dto actionDTO
		if err := c.ShouldBindJSON(&dto); err != nil {
			errResponse(c, http.StatusBadRequest, err.Error())
			return
		}
		// Validate: on_expired only supports run_mode=once
		if dto.TriggerPhase == "on_expired" && dto.RunMode != "" && dto.RunMode != "once" {
			errResponse(c, http.StatusBadRequest, "on_expired only supports run_mode=once")
			return
		}
		// Validate: webhook/shell/bgp require connector_id
		if (dto.ActionType == "webhook" || dto.ActionType == "shell" || dto.ActionType == "bgp") && dto.ConnectorID == nil {
			errResponse(c, http.StatusBadRequest, dto.ActionType+" action requires connector_id")
			return
		}
		// Validate: BGP on_detected requires route_map
		if dto.ActionType == "bgp" && dto.TriggerPhase == "on_detected" && dto.BGPRouteMap == "" {
			errResponse(c, http.StatusBadRequest, "bgp action (on_detected) requires bgp_route_map")
			return
		}
		// Validate: xDrop action semantics
		if msg := validateXDropAction(dto); msg != "" {
			errResponse(c, http.StatusBadRequest, msg)
			return
		}
		// Global prefix guard: reject xDrop/BGP if this response is used by 0.0.0.0/0
		if dto.ActionType == "xdrop" || dto.ActionType == "bgp" {
			referenced, err := isResponseReferencedByGlobalPrefix(c, deps.Store, respID)
			if err != nil {
				errResponse(c, http.StatusInternalServerError, "failed to check global prefix references: "+err.Error())
				return
			}
			if referenced {
				errResponse(c, http.StatusBadRequest,
					"This response is referenced by global prefix (0.0.0.0/0) rules — cannot add xDrop/BGP action")
				return
			}
		}
		act := dtoToAction(dto, respID)
		id, err := deps.Store.Responses().CreateAction(c, &act)
		if err != nil {
			errResponse(c, http.StatusInternalServerError, err.Error())
			return
		}
		// Save xDrop targets if provided
		if act.ActionType == "xdrop" && len(dto.TargetNodeIDs) > 0 {
			if err := deps.Store.XDropTargets().Set(c, id, dto.TargetNodeIDs); err != nil {
				log.Printf("action: set xdrop targets for action %d: %v", id, err)
			}
		}
		act.ID = id
		publishAfterChange(c, deps, "response_action", strconv.Itoa(id), "create", makeDiff(nil, act))
		created(c, gin.H{"id": id})
	}
}

func updateAction(deps Dependencies) gin.HandlerFunc {
	return func(c *gin.Context) {
		id, _ := strconv.Atoi(c.Param("id"))
		old, _ := deps.Store.Responses().GetAction(c, id)
		var dto actionDTO
		if err := c.ShouldBindJSON(&dto); err != nil {
			errResponse(c, http.StatusBadRequest, err.Error())
			return
		}
		// Validate: on_expired only supports run_mode=once
		if dto.TriggerPhase == "on_expired" && dto.RunMode != "" && dto.RunMode != "once" {
			errResponse(c, http.StatusBadRequest, "on_expired only supports run_mode=once")
			return
		}
		// Validate: webhook/shell/bgp require connector_id
		if (dto.ActionType == "webhook" || dto.ActionType == "shell" || dto.ActionType == "bgp") && dto.ConnectorID == nil {
			errResponse(c, http.StatusBadRequest, dto.ActionType+" action requires connector_id")
			return
		}
		// Validate: BGP on_detected requires route_map
		if dto.ActionType == "bgp" && dto.TriggerPhase == "on_detected" && dto.BGPRouteMap == "" {
			errResponse(c, http.StatusBadRequest, "bgp action (on_detected) requires bgp_route_map")
			return
		}
		// Validate: xDrop action semantics
		if msg := validateXDropAction(dto); msg != "" {
			errResponse(c, http.StatusBadRequest, msg)
			return
		}
		// Global prefix guard: reject xDrop/BGP if this response is used by 0.0.0.0/0
		if (dto.ActionType == "xdrop" || dto.ActionType == "bgp") && old != nil {
			referenced, err := isResponseReferencedByGlobalPrefix(c, deps.Store, old.ResponseID)
			if err != nil {
				errResponse(c, http.StatusInternalServerError, "failed to check global prefix references: "+err.Error())
				return
			}
			if referenced {
				errResponse(c, http.StatusBadRequest,
					"This response is referenced by global prefix (0.0.0.0/0) rules — cannot add xDrop/BGP action")
				return
			}
		}
		act := dtoToAction(dto, 0)
		act.ID = id
		if old != nil {
			act.ResponseID = old.ResponseID
		}
		if err := deps.Store.Responses().UpdateAction(c, &act); err != nil {
			errResponse(c, http.StatusInternalServerError, err.Error())
			return
		}
		// Update xDrop targets; clear if action type changed away from xdrop
		if act.ActionType == "xdrop" {
			if err := deps.Store.XDropTargets().Set(c, id, dto.TargetNodeIDs); err != nil {
				log.Printf("action: set xdrop targets for action %d: %v", id, err)
			}
		} else {
			// Clear stale targets if action was previously xdrop
			_ = deps.Store.XDropTargets().Set(c, id, nil)
		}
		publishAfterChange(c, deps, "response_action", strconv.Itoa(id), "update", makeDiff(old, act))
		ok(c, gin.H{"ok": true})
	}
}

func deleteAction(deps Dependencies) gin.HandlerFunc {
	return func(c *gin.Context) {
		id, _ := strconv.Atoi(c.Param("id"))
		old, _ := deps.Store.Responses().GetAction(c, id)
		if err := deps.Store.Responses().DeleteAction(c, id); err != nil {
			errResponse(c, http.StatusInternalServerError, err.Error())
			return
		}
		publishAfterChange(c, deps, "response_action", strconv.Itoa(id), "delete", makeDiff(old, nil))
		ok(c, gin.H{"ok": true})
	}
}

func listPreconditions(deps Dependencies) gin.HandlerFunc {
	return func(c *gin.Context) {
		id, err := strconv.Atoi(c.Param("id"))
		if err != nil {
			errResponse(c, http.StatusBadRequest, "invalid action id")
			return
		}
		list, err := deps.Store.Preconditions().List(c, id)
		if err != nil {
			errResponse(c, http.StatusInternalServerError, err.Error())
			return
		}
		if list == nil {
			list = []store.ActionPrecondition{}
		}
		ok(c, list)
	}
}

func replacePreconditions(deps Dependencies) gin.HandlerFunc {
	return func(c *gin.Context) {
		id, err := strconv.Atoi(c.Param("id"))
		if err != nil {
			errResponse(c, http.StatusBadRequest, "invalid action id")
			return
		}
		var req struct {
			Preconditions []store.ActionPrecondition `json:"preconditions"`
		}
		if err := c.ShouldBindJSON(&req); err != nil {
			errResponse(c, http.StatusBadRequest, err.Error())
			return
		}
		// Validate preconditions
		validAttrs := map[string]bool{
			"cidr": true, "decoder": true, "attack_type": true, "severity": true,
			"pps": true, "bps": true, "peak_pps": true, "peak_bps": true,
			"node": true, "domain": true,
			"dominant_src_port": true, "dominant_src_port_pct": true,
			"dominant_dst_port": true, "dominant_dst_port_pct": true,
			"unique_src_ips": true,
		}
		validOps := map[string]bool{
			"eq": true, "neq": true, "gt": true, "gte": true, "lt": true, "lte": true, "in": true, "not_in": true,
		}
		for _, p := range req.Preconditions {
			if !validAttrs[p.Attribute] {
				errResponse(c, http.StatusBadRequest, fmt.Sprintf("unsupported precondition attribute: %s", p.Attribute))
				return
			}
			if !validOps[p.Operator] {
				errResponse(c, http.StatusBadRequest, fmt.Sprintf("unsupported precondition operator: %s", p.Operator))
				return
			}
			if p.Value == "" {
				errResponse(c, http.StatusBadRequest, "precondition value cannot be empty")
				return
			}
		}
		if err := deps.Store.Preconditions().ReplaceAll(c, id, req.Preconditions); err != nil {
			errResponse(c, http.StatusInternalServerError, err.Error())
			return
		}
		publishAfterChange(c, deps, "action_precondition", strconv.Itoa(id), "update", makeDiff(nil, req.Preconditions))
		ok(c, gin.H{"ok": true})
	}
}

func getXDropTargets(deps Dependencies) gin.HandlerFunc {
	return func(c *gin.Context) {
		id, err := strconv.Atoi(c.Param("id"))
		if err != nil {
			errResponse(c, http.StatusBadRequest, "invalid action id")
			return
		}
		targets, err := deps.Store.XDropTargets().List(c, id)
		if err != nil {
			errResponse(c, http.StatusInternalServerError, err.Error())
			return
		}
		ids := make([]int, len(targets))
		for i, t := range targets {
			ids[i] = t.ID
		}
		ok(c, ids)
	}
}

func setXDropTargets(deps Dependencies) gin.HandlerFunc {
	return func(c *gin.Context) {
		id, err := strconv.Atoi(c.Param("id"))
		if err != nil {
			errResponse(c, http.StatusBadRequest, "invalid action id")
			return
		}
		var req struct {
			ConnectorIDs []int `json:"connector_ids"`
		}
		if err := c.ShouldBindJSON(&req); err != nil {
			errResponse(c, http.StatusBadRequest, err.Error())
			return
		}
		if err := deps.Store.XDropTargets().Set(c, id, req.ConnectorIDs); err != nil {
			errResponse(c, http.StatusInternalServerError, err.Error())
			return
		}
		ok(c, gin.H{"ok": true})
	}
}

// validateXDropAction checks xdrop-specific action semantics.
// Returns an error message if invalid, or empty string if OK.
func validateXDropAction(dto actionDTO) string {
	if dto.ActionType != "xdrop" {
		return ""
	}
	// Validate xdrop_action enum
	switch dto.XDropAction {
	case "filter_l4", "rate_limit", "unblock":
		// ok
	case "":
		return "xdrop_action is required"
	default:
		return "xdrop_action must be one of: filter_l4, rate_limit, unblock"
	}
	// filter_l4 and rate_limit require at least one match field in the payload
	if dto.XDropAction == "filter_l4" || dto.XDropAction == "rate_limit" {
		fields, rl := parseXDropPayloadFields(dto.XDropPayload)
		if len(fields) == 0 {
			return "xDrop filter/rate_limit action requires at least one match field (dst_ip, src_ip, dst_port, src_port, or protocol)"
		}
		if dto.XDropAction == "rate_limit" && (rl == nil || *rl <= 0) {
			return "xDrop rate_limit action requires a positive rate_limit value"
		}
	}
	// Unblock delay: must be 0-1440 minutes, only valid on on_detected filter_l4/rate_limit
	if dto.UnblockDelayMinutes != 0 {
		if dto.UnblockDelayMinutes < 0 || dto.UnblockDelayMinutes > 1440 {
			return "unblock_delay_minutes must be between 0 and 1440"
		}
		if dto.TriggerPhase != "on_detected" {
			return "unblock_delay_minutes is only valid for on_detected actions"
		}
		if dto.XDropAction != "filter_l4" && dto.XDropAction != "rate_limit" {
			return "unblock_delay_minutes is only valid for filter_l4 or rate_limit actions"
		}
	}
	return ""
}

// parseXDropPayloadFields extracts the checked filter fields and rate_limit
// from xdrop_custom_payload JSON, so the frontend can reconstruct checkbox state.
func parseXDropPayloadFields(payload json.RawMessage) (fields []string, rateLimit *int) {
	if len(payload) == 0 || string(payload) == "null" {
		return nil, nil
	}
	var m map[string]any
	if err := json.Unmarshal(payload, &m); err != nil {
		return nil, nil
	}
	fiveTuple := []string{"dst_ip", "src_ip", "dst_port", "src_port", "protocol"}
	for _, f := range fiveTuple {
		if _, ok := m[f]; ok {
			fields = append(fields, f)
		}
	}
	if rl, ok := m["rate_limit"]; ok {
		switch v := rl.(type) {
		case float64:
			n := int(v)
			rateLimit = &n
		}
	}
	return fields, rateLimit
}

// --- Webhooks ---

func listWebhooks(deps Dependencies) gin.HandlerFunc {
	return func(c *gin.Context) {
		webhooks, err := deps.Store.Webhooks().List(c)
		if err != nil {
			errResponse(c, http.StatusInternalServerError, err.Error())
			return
		}
		ok(c, webhooks)
	}
}

func createWebhook(deps Dependencies) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req store.Webhook
		if err := c.ShouldBindJSON(&req); err != nil {
			errResponse(c, http.StatusBadRequest, err.Error())
			return
		}
		req.Enabled = true
		id, err := deps.Store.Webhooks().Create(c, &req)
		if err != nil {
			errResponse(c, http.StatusInternalServerError, err.Error())
			return
		}
		req.ID = id
		publishAfterChange(c, deps, "webhook", strconv.Itoa(id), "create", makeDiff(nil, req))
		created(c, gin.H{"id": id})
	}
}

func updateWebhook(deps Dependencies) gin.HandlerFunc {
	return func(c *gin.Context) {
		id, _ := strconv.Atoi(c.Param("id"))
		old, _ := deps.Store.Webhooks().Get(c, id)
		var req store.Webhook
		if err := c.ShouldBindJSON(&req); err != nil {
			errResponse(c, http.StatusBadRequest, err.Error())
			return
		}
		req.ID = id
		if err := deps.Store.Webhooks().Update(c, &req); err != nil {
			errResponse(c, http.StatusInternalServerError, err.Error())
			return
		}
		publishAfterChange(c, deps, "webhook", strconv.Itoa(id), "update", makeDiff(old, req))
		ok(c, gin.H{"ok": true})
	}
}

func deleteWebhook(deps Dependencies) gin.HandlerFunc {
	return func(c *gin.Context) {
		id, _ := strconv.Atoi(c.Param("id"))
		old, _ := deps.Store.Webhooks().Get(c, id)
		if err := deps.Store.Webhooks().Delete(c, id); err != nil {
			errResponse(c, http.StatusInternalServerError, err.Error())
			return
		}
		publishAfterChange(c, deps, "webhook", strconv.Itoa(id), "delete", makeDiff(old, nil))
		ok(c, gin.H{"ok": true})
	}
}
