// Package action implements the Action Engine that executes responses
// when attacks are detected.
package action

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"strconv"
	"strings"
	"time"

	"github.com/littlewolf9527/xsight/controller/internal/store"
	"github.com/littlewolf9527/xsight/controller/internal/tracker"
)

// Engine evaluates and executes response actions when attacks change state.
type Engine struct {
	store store.Store
	mode  string // "observe" | "auto"
}

func NewEngine(s store.Store, mode string) *Engine {
	return &Engine{store: s, mode: mode}
}

// HandleEvent is the callback wired to AttackTracker.
// It evaluates preconditions and executes matching actions.
func (e *Engine) HandleEvent(event tracker.AttackEvent) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	attack := event.Attack
	if attack == nil || event.DBID == 0 {
		return
	}

	// Find the response associated with this attack
	// Priority: rule-level response_id → template-level response_id
	var responseID int
	if attack.ResponseID != nil {
		responseID = *attack.ResponseID
	}
	if responseID == 0 && attack.PrefixID != nil && attack.Direction != "sends" {
		// Fallback: check template-level response binding
		// v2.11: sends attacks do NOT fallback to template default response (Decision 7)
		// because the default response may contain xDrop/BGP actions intended for inbound only.
		if p, err := e.store.Prefixes().Get(ctx, *attack.PrefixID); err == nil && p.ThresholdTemplateID != nil {
			if tmpl, err := e.store.ThresholdTemplates().Get(ctx, *p.ThresholdTemplateID); err == nil && tmpl.ResponseID != nil {
				responseID = *tmpl.ResponseID
			}
		}
	}
	if responseID == 0 {
		// No response configured — still send to global webhooks
		e.fireGlobalWebhooks(ctx, event)
		return
	}

	// Check if response is enabled — disabled response = record attack but skip all actions
	resp, err := e.store.Responses().Get(ctx, responseID)
	if err != nil || !resp.Enabled {
		e.fireGlobalWebhooks(ctx, event)
		return
	}

	// Load response actions
	actions, err := e.store.Responses().ListActions(ctx, responseID)
	if err != nil {
		log.Printf("action: list actions for response %d: %v", responseID, err)
		return
	}

	// Resolve owning prefix for precondition checks and dynamic params
	prefixStr := attack.DstIP
	if attack.PrefixID != nil {
		if p, err := e.store.Prefixes().Get(ctx, *attack.PrefixID); err == nil {
			prefixStr = p.Prefix
		}
	}

	// Lazy-load FlowAnalysis: computed once on first need, shared across all actions.
	var fa *FlowAnalysis
	var faLoaded bool
	getFA := func() *FlowAnalysis {
		if !faLoaded {
			faLoaded = true
			fa = analyzeFlows(ctx, e.store, attack)
		}
		return fa
	}

	// First-match tracking: for non-webhook action types (xdrop, bgp, shell),
	// only the first matching action per type is executed (ACL-style).
	// Webhook actions always all execute (multi-channel notification).
	// Actions are already sorted by (trigger_phase, priority) from DB query.
	firstMatchTypes := map[string]bool{} // tracks which types already matched

	for _, act := range actions {
		if !act.Enabled {
			continue
		}

		// First-match: skip if this non-webhook type already matched
		if act.ActionType != "webhook" && firstMatchTypes[act.ActionType] {
			continue
		}

		// v2 lifecycle: use trigger_phase + run_mode if set; else fallback to legacy ExecutionPolicy
		if act.TriggerPhase != "" {
			// New model: trigger_phase decides when, run_mode decides how
			// Constraint: on_expired only supports run_mode=once (tracker doesn't emit periodic events post-expiry)
			if act.TriggerPhase == "on_expired" && act.RunMode != "once" && act.RunMode != "" {
				continue
			}
			if !phaseMatchesEvent(act.TriggerPhase, event.Type) {
				continue
			}
			// run_mode gating for "updated" events (periodic ticks)
			if event.Type == "updated" && act.RunMode == "once" {
				continue
			}
			if event.Type == "updated" && act.RunMode == "retry_until_success" {
				if alreadyExecutedV2(ctx, e.store, event.DBID, act.ID, act.TriggerPhase) {
					continue
				}
			}
			// Preconditions: lazy-load FlowAnalysis if any flow-dependent attribute exists
			if !e.checkAllPreconditions(ctx, act, attack, prefixStr, getFA) {
				continue
			}
			if act.RunMode == "once" {
				if alreadyExecutedV2(ctx, e.store, event.DBID, act.ID, act.TriggerPhase) {
					continue
				}
			}
		} else {
			// Legacy model
			if !policyMatchesEvent(act.ExecutionPolicy, event.Type) {
				continue
			}
			if !e.checkAllPreconditions(ctx, act, attack, prefixStr, getFA) {
				continue
			}
			if shouldSkip(ctx, e.store, event.DBID, act.ID, act.ExecutionPolicy) {
				continue
			}
		}

		// Mode check: xdrop/xdrop_api only runs in auto mode
		if (act.ActionType == "xdrop_api" || act.ActionType == "xdrop") && e.mode != "auto" {
			continue
		}
		// Manual actions need explicit UI trigger (not implemented yet)
		if act.Execution == "manual" {
			continue
		}

		// Mark this type as matched (first-match for non-webhook types)
		if act.ActionType != "webhook" {
			firstMatchTypes[act.ActionType] = true
		}

		// Only query flow_logs if the action actually uses flow-derived data.
		// If getFA() was already called (e.g. by precondition evaluation), reuse cached result.
		var flowData *FlowAnalysis
		if faLoaded {
			flowData = fa // already computed, free to pass
		} else if actionNeedsFlowData(act) {
			flowData = getFA()
		}
		actCtx, actCancel := context.WithTimeout(context.Background(), 30*time.Second)
		go func(a store.ResponseAction, fd *FlowAnalysis) {
			defer actCancel()
			e.executeAction(actCtx, event, a, fd)
		}(act, flowData)
	}

	// Always fire global webhooks regardless of response actions
	e.fireGlobalWebhooks(ctx, event)
}

// phaseMatchesEvent checks if a v2 trigger_phase + run_mode matches the tracker event type.
func phaseMatchesEvent(phase, eventType string) bool {
	switch phase {
	case "on_detected":
		// confirmed/type_upgrade = attack just started → once/periodic/retry all fire
		// updated = periodic 5min tick → only periodic/retry fire (handled by run_mode check in caller)
		return eventType == "confirmed" || eventType == "type_upgrade" || eventType == "updated"
	case "on_expired":
		return eventType == "expired" || eventType == "evicted"
	}
	return false
}

// alreadyExecutedV2 checks action_execution_log for v2 idempotency.
func alreadyExecutedV2(ctx context.Context, s store.Store, attackID, actionID int, triggerPhase string) bool {
	execLog, err := s.ActionExecLog().FindByAttackAndAction(ctx, attackID, actionID, triggerPhase)
	if err == nil && execLog != nil && execLog.Status == "success" {
		return true
	}
	return false
}

func policyMatchesEvent(policy, eventType string) bool {
	switch policy {
	case "once_on_enter":
		return eventType == "confirmed" || eventType == "type_upgrade"
	case "periodic":
		return eventType == "confirmed" || eventType == "updated" || eventType == "type_upgrade"
	case "retry_until_success":
		return eventType == "confirmed" || eventType == "type_upgrade"
	case "once_on_exit":
		return eventType == "expired" || eventType == "evicted"
	}
	return false
}

// checkAllPreconditions checks preconditions against the attack context.
// If structured preconditions exist in DB, they are authoritative and legacy JSONB is ignored.
// If no structured preconditions exist, falls back to legacy JSONB evaluation.
// getFA is a lazy loader for FlowAnalysis — only called if a flow-dependent attribute is encountered.
func (e *Engine) checkAllPreconditions(ctx context.Context, act store.ResponseAction, attack *store.Attack, prefixStr string, getFA func() *FlowAnalysis) bool {
	// Try structured preconditions from DB
	structured, err := e.store.Preconditions().List(ctx, act.ID)
	if err == nil && len(structured) > 0 {
		// Structured preconditions exist — they are the single source of truth
		for _, p := range structured {
			if !evaluateStructuredPrecondition(p, attack, prefixStr, getFA) {
				return false
			}
		}
		return true // all structured conditions passed, ignore legacy JSONB
	}

	// No structured preconditions — fall back to legacy JSONB
	return evaluatePreconditions(act.Preconditions, attack, prefixStr)
}

// evaluateStructuredPrecondition checks one structured precondition row.
// getFA is a lazy loader — only called for flow-dependent attributes. If it returns nil, flow attributes fail closed.
func evaluateStructuredPrecondition(p store.ActionPrecondition, attack *store.Attack, prefixStr string, getFA func() *FlowAnalysis) bool {
	switch p.Attribute {
	case "cidr":
		// Extract prefix length from attack's DstIP (not owning prefix).
		// For subnet attacks: DstIP = "10.0.0.0/24" → 24
		// For internal_ip attacks: DstIP = "10.0.0.1" (no /) → 32
		prefixLen := int64(32)
		if idx := strings.IndexByte(attack.DstIP, '/'); idx >= 0 {
			if pl, err := strconv.ParseInt(attack.DstIP[idx+1:], 10, 64); err == nil {
				prefixLen = pl
			}
		}
		return compareIntOp(p.Operator, p.Value, prefixLen)
	case "decoder":
		return matchStringOp(p.Operator, p.Value, attack.DecoderFamily)
	case "attack_type":
		return matchStringOp(p.Operator, p.Value, attack.AttackType)
	case "severity":
		return matchStringOp(p.Operator, p.Value, attack.Severity)
	case "pps", "peak_pps":
		return compareIntOp(p.Operator, p.Value, attack.PeakPPS)
	case "bps", "peak_bps":
		return compareIntOp(p.Operator, p.Value, attack.PeakBPS)
	case "node":
		return matchStringInSlice(p.Operator, p.Value, attack.NodeSources)
	case "domain":
		domain := "internal_ip"
		if strings.Contains(attack.DstIP, "/") {
			domain = "subnet"
		}
		return matchStringOp(p.Operator, p.Value, domain)
	case "dominant_src_port":
		fa := getFA()
		if fa == nil {
			log.Printf("action: precondition %q: no flow data available, blocking", p.Attribute)
			return false
		}
		return compareIntOp(p.Operator, p.Value, int64(fa.DominantSrcPort))
	case "dominant_src_port_pct":
		fa := getFA()
		if fa == nil {
			log.Printf("action: precondition %q: no flow data available, blocking", p.Attribute)
			return false
		}
		return compareIntOp(p.Operator, p.Value, int64(fa.DominantSrcPortPct))
	case "dominant_dst_port":
		fa := getFA()
		if fa == nil {
			log.Printf("action: precondition %q: no flow data available, blocking", p.Attribute)
			return false
		}
		return compareIntOp(p.Operator, p.Value, int64(fa.DominantDstPort))
	case "dominant_dst_port_pct":
		fa := getFA()
		if fa == nil {
			log.Printf("action: precondition %q: no flow data available, blocking", p.Attribute)
			return false
		}
		return compareIntOp(p.Operator, p.Value, int64(fa.DominantDstPortPct))
	case "unique_src_ips":
		fa := getFA()
		if fa == nil {
			log.Printf("action: precondition %q: no flow data available, blocking", p.Attribute)
			return false
		}
		return compareIntOp(p.Operator, p.Value, int64(fa.UniqueSrcIPs))
	default:
		log.Printf("action: unknown precondition attribute %q, blocking (fail closed)", p.Attribute)
		return false
	}
}

// matchStringOp handles eq/neq/in/not_in operators for string values.
func matchStringOp(op, expected, actual string) bool {
	switch op {
	case "eq":
		return actual == expected
	case "neq":
		return actual != expected
	case "in", "not_in":
		found := false
		for _, v := range strings.Split(expected, ",") {
			if strings.TrimSpace(v) == actual {
				found = true
				break
			}
		}
		if op == "in" {
			return found
		}
		return !found
	}
	return false
}

// matchStringInSlice checks if any element in the slice matches.
func matchStringInSlice(op, expected string, actual []string) bool {
	switch op {
	case "eq", "in":
		targets := strings.Split(expected, ",")
		for _, a := range actual {
			for _, t := range targets {
				if strings.TrimSpace(t) == a {
					return true
				}
			}
		}
		return false
	}
	return false
}

// compareIntOp handles gt/lt/gte/lte/eq/in operators for int64 values.
func compareIntOp(op, valStr string, actual int64) bool {
	if op == "in" || op == "not_in" {
		found := false
		for _, s := range strings.Split(valStr, ",") {
			v, err := strconv.ParseInt(strings.TrimSpace(s), 10, 64)
			if err == nil && v == actual {
				found = true
				break
			}
		}
		if op == "in" {
			return found
		}
		return !found
	}
	val, err := strconv.ParseInt(strings.TrimSpace(valStr), 10, 64)
	if err != nil {
		return false
	}
	switch op {
	case "gt":
		return actual > val
	case "gte":
		return actual >= val
	case "lt":
		return actual < val
	case "lte":
		return actual <= val
	case "eq":
		return actual == val
	case "neq":
		return actual != val
	}
	return false
}

// evaluatePreconditions checks AND-logic preconditions against attack context (legacy JSONB).
func evaluatePreconditions(raw json.RawMessage, attack *store.Attack, prefixStr string) bool {
	if len(raw) == 0 || string(raw) == "null" {
		return true // no preconditions = always match
	}

	var conds map[string]string
	if err := json.Unmarshal(raw, &conds); err != nil {
		log.Printf("action: invalid precondition JSON, blocking action (fail closed): %v", err)
		return false // fail closed: invalid preconditions = block
	}

	for field, expr := range conds {
		if !checkCondition(field, expr, attack, prefixStr) {
			return false
		}
	}
	return true
}

func checkCondition(field, expr string, attack *store.Attack, prefixStr string) bool {
	switch field {
	case "peak_pps":
		return compareInt(expr, attack.PeakPPS)
	case "peak_bps":
		return compareInt(expr, attack.PeakBPS)
	case "severity":
		return attack.Severity == expr
	case "attack_type":
		return attack.AttackType == expr
	case "domain":
		// domain = internal_ip | subnet (not direction)
		// Infer from attack: if dst_ip contains "/", it's subnet-level (carpet bomb)
		if strings.Contains(attack.DstIP, "/") {
			return expr == "subnet"
		}
		return expr == "internal_ip"
	case "prefix_len":
		return comparePrefixLen(expr, prefixStr)
	case "duration":
		if attack.StartedAt.IsZero() {
			return false
		}
		dur := int64(time.Since(attack.StartedAt).Seconds())
		return compareInt(expr, dur)
	default:
		log.Printf("action: unknown precondition field %q, blocking (fail closed)", field)
		return false // fail closed: unknown field = block
	}
}

func compareInt(expr string, actual int64) bool {
	expr = strings.TrimSpace(expr)
	if len(expr) < 2 {
		return false // fail closed
	}
	var op string
	var valStr string
	// Parse operator: >=, <=, >, <
	if len(expr) >= 2 && (expr[:2] == ">=" || expr[:2] == "<=") {
		op = expr[:2]
		valStr = expr[2:]
	} else {
		op = string(expr[0])
		valStr = expr[1:]
	}
	val, err := strconv.ParseInt(strings.TrimSpace(valStr), 10, 64)
	if err != nil {
		return false // fail closed
	}
	switch op {
	case ">":
		return actual > val
	case ">=":
		return actual >= val
	case "<":
		return actual < val
	case "<=":
		return actual <= val
	}
	return false // unknown operator = fail closed
}

func extractPrefixLen(dstIP string) string {
	if idx := strings.IndexByte(dstIP, '/'); idx >= 0 {
		return dstIP[idx+1:]
	}
	return "32"
}

func comparePrefixLen(expr, dstIP string) bool {
	// Extract prefix length from CIDR notation (e.g. "10.2.0.0/24" → 24)
	// If dstIP is a plain IP (no /), treat as /32
	prefixLen := int64(32)
	if idx := strings.IndexByte(dstIP, '/'); idx >= 0 {
		if pl, err := strconv.ParseInt(dstIP[idx+1:], 10, 64); err == nil {
			prefixLen = pl
		}
	}
	return compareInt(expr, prefixLen)
}

// shouldSkip checks ActionsLog and ActionExecLog for idempotency.
func shouldSkip(ctx context.Context, s store.Store, attackID, actionID int, policy string) bool {
	// Check legacy ActionsLog
	existing, err := s.ActionsLog().FindByAttackAndAction(ctx, attackID, actionID)
	if err == nil && existing != nil {
		switch policy {
		case "once_on_enter", "once_on_exit":
			if existing.Status == "success" {
				return true
			}
		case "retry_until_success":
			if existing.Status == "success" {
				return true
			}
		}
	}

	// Check new ActionExecLog (v2)
	triggerPhase := ""
	switch policy {
	case "once_on_enter":
		triggerPhase = "on_detected"
	case "once_on_exit":
		triggerPhase = "on_expired"
	}
	if triggerPhase != "" {
		execLog, err := s.ActionExecLog().FindByAttackAndAction(ctx, attackID, actionID, triggerPhase)
		if err == nil && execLog != nil && execLog.Status == "success" {
			return true
		}
	}

	return false
}

// executeAction dispatches to the appropriate action handler.
// fa is pre-computed FlowAnalysis (may be nil if no flow data available).
func (e *Engine) executeAction(ctx context.Context, event tracker.AttackEvent, act store.ResponseAction, fa *FlowAnalysis) {
	attack := event.Attack

	// Resolve owning prefix for dynamic parameters
	prefixStr := attack.DstIP
	if attack.PrefixID != nil {
		if p, err := e.store.Prefixes().Get(ctx, *attack.PrefixID); err == nil {
			prefixStr = p.Prefix
		}
	}

	// Resolve response name for logging
	responseName := ""
	if resp, err := e.store.Responses().Get(ctx, act.ResponseID); err == nil {
		responseName = resp.Name
	}

	// Expand dynamic parameters in action config (includes flow-derived variables)
	configStr := expandParams(string(act.Config), attack, event.Type, prefixStr, fa)

	// Determine trigger phase
	triggerPhase := act.TriggerPhase
	if triggerPhase == "" {
		triggerPhase = event.Type
	}

	switch act.ActionType {
	case "webhook":
		execLog := &store.ActionExecutionLog{
			AttackID:      event.DBID,
			ActionID:      act.ID,
			ResponseName:  responseName,
			ActionType:    "webhook",
			TriggerPhase:  triggerPhase,
			ExecutedAt:    time.Now(),
		}

		// If webhook_connector_id is set, use the connector; otherwise fall back to old config-based webhook
		if act.WebhookConnectorID != nil {
			wc, err := e.store.WebhookConnectors().Get(ctx, *act.WebhookConnectorID)
			if err != nil {
				execLog.Status = "failed"
				execLog.ErrorMessage = fmt.Sprintf("get webhook connector %d: %v", *act.WebhookConnectorID, err)
				log.Printf("action: %s", execLog.ErrorMessage)
			} else {
				execLog.ConnectorName = wc.Name
				start := time.Now()
				result, err := postWebhookWithFA(ctx, wc.URL, wc.Headers, attack, event.Type, fa)
				execLog.DurationMs = int(time.Since(start).Milliseconds())
				if err != nil {
					execLog.Status = "failed"
					execLog.ErrorMessage = err.Error()
					log.Printf("action: webhook connector %d failed for attack %d: %v", wc.ID, event.DBID, err)
				} else {
					execLog.Status = "success"
					execLog.ResponseBody = result
				}
			}
		} else {
			// Legacy: config-based webhook
			start := time.Now()
			result, err := executeWebhook(ctx, []byte(configStr), attack, event.Type)
			execLog.DurationMs = int(time.Since(start).Milliseconds())
			execLog.ConnectorName = "legacy-config"
			if err != nil {
				execLog.Status = "failed"
				execLog.ErrorMessage = err.Error()
				log.Printf("action: webhook failed for attack %d: %v", event.DBID, err)
			} else {
				execLog.Status = "success"
				execLog.ResponseBody = result
			}
		}

		if _, err := e.store.ActionExecLog().Create(ctx, execLog); err != nil {
			log.Printf("action: create action_execution_log: %v", err)
		}

	case "xdrop":
		// Defense-in-depth: skip xDrop for global attacks (no concrete IP to block)
		if attack.DstIP == "0.0.0.0/0" {
			log.Printf("action: xdrop skipped for global attack %d (0.0.0.0/0 has no concrete target)", event.DBID)
			skipLog := &store.ActionExecutionLog{
				AttackID:      event.DBID,
				ActionID:      act.ID,
				ActionType:    "xdrop",
				TriggerPhase:  triggerPhase,
				ResponseName:  responseName,
				Status:        "skipped",
				ErrorMessage:  "global attack (0.0.0.0/0) has no concrete IP target for xDrop",
			}
			if _, err := e.store.ActionExecLog().Create(ctx, skipLog); err != nil {
				log.Printf("action: create skip log: %v", err)
			}
			break
		}
		execLog, err := executeXDrop(ctx, e.store, act, attack, event.Type, prefixStr, responseName, triggerPhase, event.DBID, fa)
		if err != nil {
			log.Printf("action: xdrop failed for attack %d: %v", event.DBID, err)
		}
		if execLog != nil {
			if _, err := e.store.ActionExecLog().Create(ctx, execLog); err != nil {
				log.Printf("action: create action_execution_log: %v", err)
			}
		}

	case "shell":
		execLog, err := executeShell(ctx, e.store, act, attack, event.Type, prefixStr, responseName, triggerPhase, event.DBID, fa)
		if err != nil {
			log.Printf("action: shell failed for attack %d: %v", event.DBID, err)
		}
		if execLog != nil {
			if _, err := e.store.ActionExecLog().Create(ctx, execLog); err != nil {
				log.Printf("action: create action_execution_log: %v", err)
			}
		}

	case "bgp":
		// Defense-in-depth: skip BGP for global attacks (no concrete target)
		if attack.DstIP == "0.0.0.0/0" {
			log.Printf("action: bgp skipped for global attack %d (0.0.0.0/0 has no concrete target)", event.DBID)
			skipLog := &store.ActionExecutionLog{
				AttackID:     event.DBID,
				ActionID:     act.ID,
				ActionType:   "bgp",
				TriggerPhase: triggerPhase,
				ResponseName: responseName,
				Status:       "skipped",
				ErrorMessage: "global attack (0.0.0.0/0) has no concrete target for BGP",
			}
			if _, err := e.store.ActionExecLog().Create(ctx, skipLog); err != nil {
				log.Printf("action: create skip log: %v", err)
			}
			break
		}
		if act.BGPConnectorID == nil {
			log.Printf("action: bgp action %d has no connector_id, skipping", act.ID)
			break
		}
		execLog, err := executeBGP(ctx, e.store, act, attack, event.Type, prefixStr, responseName, triggerPhase, event.DBID, nil)
		if err != nil {
			log.Printf("action: bgp failed for attack %d: %v", event.DBID, err)
		}
		if execLog != nil {
			if _, err := e.store.ActionExecLog().Create(ctx, execLog); err != nil {
				log.Printf("action: create action_execution_log: %v", err)
			}
		}

	case "xdrop_api":
		// Legacy placeholder — log as skipped
		execLog := &store.ActionExecutionLog{
			AttackID:     event.DBID,
			ActionID:     act.ID,
			ResponseName: responseName,
			ActionType:   "xdrop_api",
			TriggerPhase: triggerPhase,
			Status:       "skipped",
			ErrorMessage: "xdrop_api deprecated, use action_type=xdrop",
			ExecutedAt:   time.Now(),
		}
		if _, err := e.store.ActionExecLog().Create(ctx, execLog); err != nil {
			log.Printf("action: create action_execution_log: %v", err)
		}

	default:
		execLog := &store.ActionExecutionLog{
			AttackID:     event.DBID,
			ActionID:     act.ID,
			ResponseName: responseName,
			ActionType:   act.ActionType,
			TriggerPhase: triggerPhase,
			Status:       "skipped",
			ErrorMessage: fmt.Sprintf("unknown action type: %s", act.ActionType),
			ExecutedAt:   time.Now(),
		}
		if _, err := e.store.ActionExecLog().Create(ctx, execLog); err != nil {
			log.Printf("action: create action_execution_log: %v", err)
		}
	}
}

// fireGlobalWebhooks sends notifications to all enabled global webhook connectors.
func (e *Engine) fireGlobalWebhooks(ctx context.Context, event tracker.AttackEvent) {
	eventName := eventToWebhookEvent(event.Type)
	if eventName == "" {
		return
	}

	connectors, err := e.store.WebhookConnectors().ListGlobal(ctx)
	if err != nil {
		log.Printf("action: list global webhook connectors: %v", err)
		return
	}

	for _, wc := range connectors {
		if !wc.Enabled {
			continue
		}

		result, err := postWebhook(ctx, wc.URL, wc.Headers, event.Attack, eventName)
		if err != nil {
			log.Printf("action: global webhook connector %d (%s) failed: %v", wc.ID, wc.URL, err)
		} else {
			log.Printf("action: global webhook connector %d (%s) sent: %s event=%s attack=%d",
				wc.ID, wc.URL, result, eventName, event.DBID)
		}
	}
}

func eventToWebhookEvent(eventType string) string {
	switch eventType {
	case "confirmed":
		return "attack_start"
	case "expired", "evicted":
		return "attack_end"
	case "type_upgrade":
		return "attack_update"
	}
	return ""
}

func containsEvent(events []string, target string) bool {
	for _, e := range events {
		if e == target {
			return true
		}
	}
	return false
}

// expandParams replaces {ip} {prefix} {attack_type} {top_src_ips} etc. in a template string.
func expandParams(template string, attack *store.Attack, eventType string, prefixStr string, fa *FlowAnalysis) string {
	duration := "0"
	if !attack.StartedAt.IsZero() {
		duration = strconv.FormatInt(int64(time.Since(attack.StartedAt).Seconds()), 10)
	}
	nodeSources := strings.Join(attack.NodeSources, ",")
	reasonCodes := strings.Join(attack.ReasonCodes, ",")

	pairs := []string{
		"{ip}", attack.DstIP,
		"{dst_ip}", attack.DstIP,
		"{prefix}", prefixStr,
		"{prefix_len}", extractPrefixLen(prefixStr),
		"{attack_type}", attack.AttackType,
		"{decoder}", attack.DecoderFamily,
		"{severity}", attack.Severity,
		"{peak_pps}", strconv.FormatInt(attack.PeakPPS, 10),
		"{peak_bps}", strconv.FormatInt(attack.PeakBPS, 10),
		"{event}", eventType,
		"{attack_id}", strconv.Itoa(attack.ID),
		"{started_at}", attack.StartedAt.Format(time.RFC3339),
		"{duration}", duration,
		"{node_sources}", nodeSources,
		"{reason_codes}", reasonCodes,
	}
	// Append flow analysis replacements (Phase 4)
	pairs = append(pairs, flowAnalysisReplacements(fa)...)

	return strings.NewReplacer(pairs...).Replace(template)
}
