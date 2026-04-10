package action

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/littlewolf9527/xsight/controller/internal/store"
)

// xdropRuleRequest is the default request body sent to xDrop API.
// Matches xDrop's RuleRequest format — any field left empty/zero is treated as wildcard.
type xdropRuleRequest struct {
	DstIP     string  `json:"dst_ip,omitempty"`
	SrcIP     string  `json:"src_ip,omitempty"`
	DstPort   int     `json:"dst_port,omitempty"`
	SrcPort   int     `json:"src_port,omitempty"`
	Protocol  string  `json:"protocol,omitempty"`
	TcpFlags  *string `json:"tcp_flags,omitempty"` // e.g. "SYN,!ACK"; requires protocol=tcp
	Action    string  `json:"action"`              // "drop" or "rate_limit"
	RateLimit int     `json:"rate_limit,omitempty"` // PPS, required if action=rate_limit
	Source    string  `json:"source"`               // "xsight"
	Comment   string  `json:"comment,omitempty"`
}

// executeXDrop executes an xDrop action by calling the xDrop Controller API.
func executeXDrop(
	ctx context.Context,
	s store.Store,
	action store.ResponseAction,
	attack *store.Attack,
	eventType string,
	prefixStr string,
	responseName string,
	triggerPhase string,
	attackDBID int,
	fa *FlowAnalysis,
) (*store.ActionExecutionLog, error) {
	xdropAction := action.XDropAction
	if xdropAction == "" {
		return nil, fmt.Errorf("xdrop action type is empty")
	}

	// Resolve target connectors: action-specific targets first, fall back to all enabled
	connectors, err := s.XDropTargets().List(ctx, action.ID)
	if err != nil {
		return nil, fmt.Errorf("list xdrop targets for action %d: %w", action.ID, err)
	}
	if len(connectors) == 0 {
		connectors, err = s.XDropConnectors().ListEnabled(ctx)
		if err != nil {
			return nil, fmt.Errorf("list enabled xdrop connectors: %w", err)
		}
	}
	if len(connectors) == 0 {
		execLog := &store.ActionExecutionLog{
			AttackID:     attackDBID,
			ActionID:     action.ID,
			ResponseName: responseName,
			ActionType:   "xdrop",
			TriggerPhase: triggerPhase,
			Status:       "skipped",
			ErrorMessage: "no xdrop connectors available",
			ExecutedAt:   time.Now(),
		}
		return execLog, fmt.Errorf("no xdrop connectors available")
	}

	// Build request body
	var body []byte
	if len(action.XDropCustomPayload) > 0 && string(action.XDropCustomPayload) != "null" {
		// Use custom payload with {var} expansion
		expanded := expandParams(string(action.XDropCustomPayload), attack, eventType, prefixStr, fa)
		// Fix JSON types: port and rate_limit fields must be integers, not strings.
		// expandParams does string replacement, so "src_port": "{dominant_src_port}" becomes "src_port": "53".
		// We parse and re-marshal to fix types.
		body, err = fixPayloadTypes([]byte(expanded))
		if err != nil {
			body = []byte(expanded) // fallback to raw string if fixup fails
		}
		// Auto-inject tcp_flags for tcp_syn attacks if not already specified
		body = injectTcpFlags(body, attack)
	} else {
		// Default payload: dst_ip drop/rate_limit based on xdrop_action
		actionStr := "drop"
		if xdropAction == "rate_limit" {
			actionStr = "rate_limit"
		}
		payload := xdropRuleRequest{
			DstIP:   attack.DstIP,
			Action:  actionStr,
			Source:  "xsight",
			Comment: fmt.Sprintf("attack #%d %s", attack.ID, attack.AttackType),
		}
		// Auto-inject tcp_flags for decoder-specific attacks
		if attack.DecoderFamily == "tcp_syn" {
			payload.Protocol = "tcp"
			synFlags := "SYN,!ACK"
			payload.TcpFlags = &synFlags
		}
		body, err = json.Marshal(payload)
		if err != nil {
			return nil, fmt.Errorf("marshal xdrop payload: %w", err)
		}
	}

	// Runtime sanity: rate_limit action must have a positive rate_limit in the payload.
	// API validation should prevent this, but guard against malformed DB rows.
	if xdropAction == "rate_limit" {
		var check map[string]any
		if json.Unmarshal(body, &check) == nil {
			rl, _ := check["rate_limit"].(float64)
			if rl <= 0 {
				return nil, fmt.Errorf("xdrop rate_limit action has no valid rate_limit value in payload")
			}
		}
	}

	// For "unblock" action, we need the external rule ID from a previous execution
	httpMethod := "POST"
	if xdropAction == "unblock" {
		httpMethod = "DELETE"
	}

	// Execute against each connector; return log for the last one (or first failure)
	var lastLog *store.ActionExecutionLog
	for _, conn := range connectors {
		connID := conn.ID // capture for pointer
		execLog := &store.ActionExecutionLog{
			AttackID:      attackDBID,
			ActionID:      action.ID,
			ResponseName:  responseName,
			ActionType:    "xdrop",
			ConnectorName: conn.Name,
			ConnectorID:   &connID,
			TriggerPhase:  triggerPhase,
			RequestBody:   truncateStr(string(body), 1024),
			ExecutedAt:    time.Now(),
		}

		apiURL := strings.TrimRight(conn.APIURL, "/") + "/rules"

		// Create HTTP client with connector timeout
		timeout := 10 * time.Second
		if conn.TimeoutMs > 0 {
			timeout = time.Duration(conn.TimeoutMs) * time.Millisecond
		}
		client := &http.Client{Timeout: timeout}

		// For unblock, look up ALL external rule IDs from prior xdrop actions on this attack.
		// Each rule may have a different unblock_delay_minutes from its originating on_detected action.
		// Rules with delay=0 are deleted immediately; rules with delay>0 are scheduled for later deletion.
		// NOTE: delayed deletions are best-effort in-process timers — lost on controller restart.
		if xdropAction == "unblock" {
			allRules, err := s.ActionExecLog().FindExternalRulesWithActions(ctx, attackDBID)
			if err != nil || len(allRules) == 0 {
				execLog.Status = "failed"
				execLog.ErrorMessage = "no external_rule_ids found for unblock"
				lastLog = execLog
				if _, err := s.ActionExecLog().Create(ctx, execLog); err != nil {
					log.Printf("action: create action_execution_log: %v", err)
				}
				continue
			}

			// Filter: only delete rules that were created on THIS connector.
			// Prevents cross-connector deletion when multiple xDrop connectors are used.
			// ConnectorID=0 means legacy record without connector tracking — allow on any connector (backward compat).
			var rulesWithActions []store.RuleWithAction
			for _, ra := range allRules {
				if ra.ConnectorID == 0 || ra.ConnectorID == conn.ID {
					rulesWithActions = append(rulesWithActions, ra)
				}
			}
			if len(rulesWithActions) == 0 {
				continue // no rules for this connector
			}

			// Build action ID → delay map by looking up the originating actions
			actionDelays := make(map[int]int) // action_id → unblock_delay_minutes
			for _, ra := range rulesWithActions {
				if _, seen := actionDelays[ra.ActionID]; !seen {
					if act, err := s.Responses().GetAction(ctx, ra.ActionID); err == nil {
						actionDelays[ra.ActionID] = act.UnblockDelayMinutes
					}
				}
			}

			// Group rules by delay
			immediateRules := []string{}
			type delayedRule struct {
				ruleID string
				delay  time.Duration
			}
			var delayedRules []delayedRule
			for _, ra := range rulesWithActions {
				delay := actionDelays[ra.ActionID]
				if delay <= 0 {
					immediateRules = append(immediateRules, ra.RuleID)
				} else {
					delayedRules = append(delayedRules, delayedRule{ra.RuleID, time.Duration(delay) * time.Minute})
				}
			}

			// Delete immediate rules now
			deleted := 0
			var lastErr string
			for _, ruleID := range immediateRules {
				delURL := apiURL + "/" + ruleID
				req, err := http.NewRequestWithContext(ctx, "DELETE", delURL, nil)
				if err != nil {
					lastErr = fmt.Sprintf("create request: %v", err)
					continue
				}
				req.Header.Set("Content-Type", "application/json")
				req.Header.Set("User-Agent", "xsight-controller/1.0")
				if conn.APIKey != "" {
					req.Header.Set("X-API-Key", conn.APIKey)
				}
				resp, err := client.Do(req)
				if err != nil {
					lastErr = fmt.Sprintf("DELETE %s: %v", delURL, err)
					continue
				}
				resp.Body.Close()
				if resp.StatusCode < 400 {
					deleted++
				} else {
					lastErr = fmt.Sprintf("DELETE %s: HTTP %d", delURL, resp.StatusCode)
				}
			}

			// Schedule delayed rule deletions
			for _, dr := range delayedRules {
				log.Printf("action: scheduling delayed unblock rule %s in %v (attack=%d connector=%d)",
					dr.ruleID, dr.delay, attackDBID, conn.ID)
				go func(ruleID string, d time.Duration, connCopy store.XDropConnector) {
					time.Sleep(d)
					delCtx, delCancel := context.WithTimeout(context.Background(), 30*time.Second)
					defer delCancel()
					delURL := connCopy.APIURL + "/rules/" + ruleID
					req, err := http.NewRequestWithContext(delCtx, "DELETE", delURL, nil)
					if err != nil {
						log.Printf("action: delayed unblock rule %s failed: %v", ruleID, err)
						return
					}
					req.Header.Set("Content-Type", "application/json")
					req.Header.Set("User-Agent", "xsight-controller/1.0")
					if connCopy.APIKey != "" {
						req.Header.Set("X-API-Key", connCopy.APIKey)
					}
					cl := &http.Client{Timeout: 30 * time.Second}
					resp, err := cl.Do(req)
					if err != nil {
						log.Printf("action: delayed unblock rule %s failed: %v", ruleID, err)
						return
					}
					resp.Body.Close()
					log.Printf("action: delayed unblock rule %s completed (HTTP %d, attack=%d)", ruleID, resp.StatusCode, attackDBID)
				}(dr.ruleID, dr.delay, conn)
			}

			totalRules := len(immediateRules) + len(delayedRules)
			execLog.DurationMs = int(time.Since(execLog.ExecutedAt).Milliseconds())
			if deleted == len(immediateRules) {
				execLog.Status = "success"
			} else if deleted > 0 {
				execLog.Status = "success"
				execLog.ErrorMessage = fmt.Sprintf("deleted %d/%d immediate rules, last error: %s", deleted, len(immediateRules), lastErr)
			} else if len(delayedRules) > 0 {
				execLog.Status = "success"
				execLog.ErrorMessage = fmt.Sprintf("0 immediate, %d delayed rules scheduled", len(delayedRules))
			} else {
				execLog.Status = "failed"
				execLog.ErrorMessage = fmt.Sprintf("deleted 0/%d rules: %s", totalRules, lastErr)
			}
			sc := 200
			execLog.StatusCode = &sc
			lastLog = execLog
			if _, err := s.ActionExecLog().Create(ctx, execLog); err != nil {
				log.Printf("action: create action_execution_log: %v", err)
			}
			log.Printf("action: xdrop unblock connector %d (%s) immediate=%d/%d delayed=%d attack=%d",
				conn.ID, conn.Name, deleted, len(immediateRules), len(delayedRules), attackDBID)
			continue // skip the normal single-request path below
		}

		req, err := http.NewRequestWithContext(ctx, httpMethod, apiURL, bytes.NewReader(body))
		if err != nil {
			execLog.Status = "failed"
			execLog.ErrorMessage = fmt.Sprintf("create request: %v", err)
			lastLog = execLog
			if _, err := s.ActionExecLog().Create(ctx, execLog); err != nil {
				log.Printf("action: create action_execution_log: %v", err)
			}
			continue
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("User-Agent", "xsight-controller/1.0")
		if conn.APIKey != "" {
			req.Header.Set("X-API-Key", conn.APIKey)
		}

		start := time.Now()
		resp, err := client.Do(req)
		execLog.DurationMs = int(time.Since(start).Milliseconds())

		if err != nil {
			execLog.Status = "failed"
			execLog.ErrorMessage = fmt.Sprintf("HTTP %s %s: %v", httpMethod, apiURL, err)
			lastLog = execLog
			if _, err := s.ActionExecLog().Create(ctx, execLog); err != nil {
				log.Printf("action: create action_execution_log: %v", err)
			}
			continue
		}

		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		resp.Body.Close()

		statusCode := resp.StatusCode
		execLog.StatusCode = &statusCode
		execLog.ResponseBody = truncateStr(string(respBody), 1024)

		if statusCode >= 400 {
			execLog.Status = "failed"
			execLog.ErrorMessage = fmt.Sprintf("HTTP %d: %s", statusCode, string(respBody))
		} else {
			execLog.Status = "success"
			// Try to extract external_rule_id from response
			var respJSON map[string]any
			if err := json.Unmarshal(respBody, &respJSON); err == nil {
				if ruleID, ok := respJSON["id"]; ok {
					execLog.ExternalRuleID = fmt.Sprintf("%v", ruleID)
				} else if ruleObj, ok := respJSON["rule"].(map[string]any); ok {
					if ruleID, ok := ruleObj["id"]; ok {
						execLog.ExternalRuleID = fmt.Sprintf("%v", ruleID)
					}
				} else if ruleID, ok := respJSON["rule_id"]; ok {
					execLog.ExternalRuleID = fmt.Sprintf("%v", ruleID)
				}
			}
		}

		lastLog = execLog
		if _, err := s.ActionExecLog().Create(ctx, execLog); err != nil {
			log.Printf("action: create action_execution_log: %v", err)
		}

		log.Printf("action: xdrop %s connector %d (%s) %s attack=%d",
			xdropAction, conn.ID, conn.Name, execLog.Status, attackDBID)
	}

	// Return nil for the log since we already persisted per-connector logs
	if lastLog != nil && lastLog.Status == "failed" {
		return nil, fmt.Errorf("xdrop action failed: %s", lastLog.ErrorMessage)
	}
	return nil, nil
}

// fixPayloadTypes converts string values to proper JSON types for xDrop RuleRequest.
// After expandParams, numeric fields like src_port/dst_port/rate_limit are strings ("53").
// xDrop expects them as integers. This function parses the JSON, converts known numeric
// fields from string to int, and removes fields with empty string values (wildcard).
func fixPayloadTypes(raw []byte) ([]byte, error) {
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, err
	}

	intFields := []string{"src_port", "dst_port", "rate_limit"}
	for _, f := range intFields {
		v, ok := m[f]
		if !ok {
			continue
		}
		switch val := v.(type) {
		case string:
			if val == "" || val == "0" {
				delete(m, f) // empty/zero = wildcard, remove from payload
			} else {
				n, err := strconv.Atoi(val)
				if err != nil {
					delete(m, f) // unparseable, remove
				} else {
					m[f] = n
				}
			}
		}
	}

	return json.Marshal(m)
}

// decoderToXDropProtocol maps xSight decoder families to xDrop protocol values.
func decoderToXDropProtocol(decoder string) string {
	switch decoder {
	case "tcp", "tcp_syn":
		return "tcp"
	case "udp":
		return "udp"
	case "icmp":
		return "icmp"
	default:
		return ""
	}
}

// injectTcpFlags auto-injects tcp_flags and normalizes protocol for tcp_syn attacks.
// Rules:
//   - tcp_syn attack without tcp_flags → inject tcp_flags=SYN,!ACK + protocol=tcp
//   - tcp_syn attack with tcp_flags already set → keep user's flags, still ensure protocol=tcp
//   - tcp_syn attack with protocol=tcp_syn (from {decoder} expansion) → fix to tcp
//   - non-tcp_syn attack → no changes
func injectTcpFlags(body []byte, attack *store.Attack) []byte {
	if attack.DecoderFamily != "tcp_syn" {
		return body
	}
	var m map[string]any
	if json.Unmarshal(body, &m) != nil {
		return body
	}
	// Inject tcp_flags if not already set
	if _, has := m["tcp_flags"]; !has {
		m["tcp_flags"] = "SYN,!ACK"
	}
	// Always normalize protocol for tcp_syn (fixes {decoder} → "tcp_syn" expansion)
	proto, _ := m["protocol"].(string)
	if correct := decoderToXDropProtocol(attack.DecoderFamily); correct != "" {
		if proto == "" || proto == attack.DecoderFamily {
			m["protocol"] = correct
		}
	}
	out, err := json.Marshal(m)
	if err != nil {
		return body
	}
	return out
}

func truncateStr(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen]
}
