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

	"github.com/littlewolf9527/xsight/controller/internal/metrics"
	"github.com/littlewolf9527/xsight/controller/internal/store"
	"github.com/littlewolf9527/xsight/shared/decoder"
)

// xDropCompatibleDecoders is the set of xSight decoder_family values that
// are allowed to produce xDrop rules. xDrop v2.6.1 supports three dispatch
// paths on top of its 33-combo BPF lookup:
//
//   - Protocol + (optional) 5-tuple → L4 standard decoders (tcp/udp/icmp) +
//     other IP protocols (gre/esp/igmp). fragment collapses to protocol=all.
//   - Protocol=tcp + tcp_flags specialization → TCP flag family
//     (tcp_syn/tcp_ack/tcp_rst/tcp_fin). tcp_flags is a single (mask,value)
//     pair; each decoder has a canonical pattern (see tcpFlagDecoderMap).
//   - decoder field → anomaly family (bad_fragment/invalid). xdrop
//     Controller translates to match_anomaly bitmap internally; protocol
//     is wildcard. See xdrop docs/v2.6.1-deploy-summary.md.
//
// Exclusions:
//
//   - `ip`: L3 aggregate "any IP protocol". xDrop can only express this
//     as protocol=all, which combined with absent flow-derived port fields
//     (common when source is diffuse) degrades into a silent full-prefix
//     blackhole. Use BGP null-route for L3 aggregates.
//   - `ip_other`: operator-declared "none of tcp/udp/icmp/fragment/gre/
//     esp/igmp" — collapses to a useless full-wildcard xDrop rule with no
//     meaningful 5-tuple constraint. BGP null-route is the correct layer.
//
// fragment inclusion rationale: fragment floods are a clear attack signal
// by construction; dropping broadly at the xDrop layer is an acceptable
// response. fragment → `all` in the xDrop payload is a semantic downgrade
// but not a silent one because operators who configure a fragment-decoder
// threshold have already accepted the aggressive drop intent.
//
// Maintenance: to extend support to a new decoder, update this map + the
// protocol mapping in decoderToXDropProtocol (or isAnomalyDecoder if the
// decoder goes through xdrop's `decoder` field) + UI help text + roadmap
// compatibility matrix.
var xDropCompatibleDecoders = map[string]bool{
	// L4 standard
	"tcp":      true,
	"tcp_syn":  true,
	"udp":      true,
	"icmp":     true,
	"fragment": true,
	// TCP flag family (v1.3) — protocol=tcp + tcp_flags specialization
	"tcp_ack": true,
	"tcp_rst": true,
	"tcp_fin": true,
	// Other IP protocols (v1.3) — xdrop proto-agnostic lookup matches on
	// IANA number; tcp_flags / ports degrade to wildcards.
	"gre":  true,
	"esp":  true,
	"igmp": true,
	// Anomaly family (v1.3 / xdrop v2.6.1) — dispatched via `decoder`
	// field, translated to match_anomaly bitmap by xdrop Controller.
	// Drop-only: xdrop 400-rejects rate_limit + anomaly (see
	// SkipReasonXDropAnomalyRequiresDrop engine.go gate).
	"bad_fragment": true,
	"invalid":      true,
	// "ip" / "ip_other" intentionally excluded — see doc comment above.
}

// IsXDropCompatibleDecoder reports whether an attack with the given
// decoder_family is eligible for xDrop rule creation. Exposed so the
// action engine dispatch path can gate xDrop actions without reaching
// into xdrop.go internals.
func IsXDropCompatibleDecoder(decoder string) bool {
	return xDropCompatibleDecoders[decoder]
}

// isAnomalyRateLimitBody reports whether a final xdrop request body would
// violate xdrop v2.6.1's anomaly-drop-only contract. True when the attack
// decoder is anomaly (bad_fragment/invalid) AND the payload's top-level
// `action` field is "rate_limit". Used by the late dispatch gate in
// executeXDrop to catch custom payloads that set action=rate_limit even
// when act.XDropAction=filter_l4. See codex v1.3.x audit P2.
//
// Malformed / unparseable bodies return false (non-JSON or JSON without
// an `action` string) — those paths are handled by the downstream
// rate_limit sanity check, which still fires and fails the dispatch.
func isAnomalyRateLimitBody(body []byte, decoder string) bool {
	if !isAnomalyDecoder(decoder) {
		return false
	}
	var check map[string]any
	if json.Unmarshal(body, &check) != nil {
		return false
	}
	a, _ := check["action"].(string)
	return a == "rate_limit"
}

// isAnomalyDecoder reports whether the decoder is an xdrop v2.6.1 anomaly
// family member. Anomaly decoders have distinct dispatch semantics:
//   - routed through xdrop's `decoder` field (not protocol)
//   - translated to match_anomaly bitmap by xdrop Controller
//   - drop-only (xdrop 400-rejects action=rate_limit + anomaly)
//   - IPv6 bad_fragment rejected by xdrop (scope guard, v1.3 limitation);
//     invalid allowed on both IPv4 and IPv6
//
// Used both by the default payload builder (to set Decoder field instead
// of Protocol) and by the engine dispatch gate (to fail-fast on
// action=rate_limit combos).
func isAnomalyDecoder(decoder string) bool {
	return decoder == "bad_fragment" || decoder == "invalid"
}

// tcpFlagDecoderMap maps TCP-flag family decoders to their canonical
// tcp_flags pattern. Patterns chosen to minimize false positives:
//   tcp_syn → "SYN,!ACK": pure SYN (handshake opener), excludes SYN+ACK
//   tcp_ack → "ACK,!SYN": ACK-flood / established traffic, excludes handshake
//   tcp_rst → "RST":       connection reset flood
//   tcp_fin → "FIN":       half-open close flood
//
// Used by both the default payload builder and injectTcpFlags (custom
// payload path).
var tcpFlagDecoderMap = map[string]string{
	"tcp_syn": "SYN,!ACK",
	"tcp_ack": "ACK,!SYN",
	"tcp_rst": "RST",
	"tcp_fin": "FIN",
}

// specializeXDropDecoder mutates payload in place to add the fields that
// depend on the attack's decoder_family, per the three xdrop dispatch
// paths described on xDropCompatibleDecoders:
//
//   Anomaly (bad_fragment/invalid): set `decoder` field; xdrop Controller
//     translates to match_anomaly bitmap. Protocol stays wildcard.
//   TCP-flag family (tcp_syn/tcp_ack/tcp_rst/tcp_fin): protocol=tcp +
//     canonical tcp_flags pattern from tcpFlagDecoderMap.
//   Other IP protocols (gre/esp/igmp): set protocol only.
//   tcp / udp / icmp / fragment / unknown: leave untouched. xdrop accepts
//     an absent protocol as wildcard which is fine when dst_ip is set;
//     keeping these branches empty preserves v1.2 behavior.
//
// Called by the default payload builder in executeXDrop. Exported
// (lowercase within-package) so xdrop_flags_test.go can exercise the
// switch directly without duplicating the logic.
func specializeXDropDecoder(payload *xdropRuleRequest, decoder string) {
	switch {
	case isAnomalyDecoder(decoder):
		payload.Decoder = decoder
	case tcpFlagDecoderMap[decoder] != "":
		payload.Protocol = "tcp"
		flags := tcpFlagDecoderMap[decoder]
		payload.TcpFlags = &flags
	case decoder == "gre", decoder == "esp", decoder == "igmp":
		payload.Protocol = decoder
	}
}

// specializeXDropDecoderBody is the custom-payload counterpart of
// specializeXDropDecoder. Auto-fills dispatch-specific fields in an
// already-expanded custom payload body if the operator didn't specify
// them — parallel to how injectTcpFlags auto-fills tcp_flags for TCP-flag-
// family attacks. Runs AFTER normalizeXDropProtocol + injectTcpFlags
// so it observes the final payload shape.
//
// Rules (idempotent, operator-supplied fields preserved):
//
//   anomaly attack (bad_fragment/invalid) + `decoder` absent → inject
//     decoder=<family>. Also strips `protocol` if it still holds the
//     anomaly decoder name (defense-in-depth; normalize usually clears
//     this but a bare `"protocol":"bad_fragment"` in a payload that
//     skipped normalize — e.g. via a future test harness — would still
//     land here).
//   gre/esp/igmp attack + `protocol` absent → inject protocol=<family>.
//   TCP-flag family: handled by injectTcpFlags already — pass-through.
//   tcp/udp/icmp/fragment: no auto-fill (operator-authored custom
//     payloads are the spec; absent fields mean wildcard which is the
//     operator's prerogative, preserves v1.2 behavior).
//
// Without this function, gre/esp/igmp custom payloads that omit protocol
// would dispatch as wildcard rules (silent semantic downgrade), and
// anomaly custom payloads that omit `decoder` would hit xdrop's 400
// (no decoder-bit means no match_anomaly → xdrop rejects as "not an
// anomaly rule on v2.6.1 path").
func specializeXDropDecoderBody(body []byte, attack *store.Attack) []byte {
	decoderName := attack.DecoderFamily
	dc := decoder.GetDispatchClass(decoderName)
	isAnomaly := dc == decoder.Anomaly
	isIPProto := dc == decoder.PortlessProto && decoderName != "icmp" && decoderName != "fragment"
	if !isAnomaly && !isIPProto {
		return body
	}
	var m map[string]any
	if json.Unmarshal(body, &m) != nil {
		return body
	}
	if isAnomaly {
		if _, has := m["decoder"]; !has {
			m["decoder"] = decoderName
		}
		if proto, _ := m["protocol"].(string); isAnomalyDecoder(proto) {
			delete(m, "protocol")
		}
	}
	if isIPProto {
		if _, has := m["protocol"]; !has {
			m["protocol"] = decoderName
		}
	}
	out, err := json.Marshal(m)
	if err != nil {
		return body
	}
	return out
}

// sanitizeXDropPayloadForDecoder is the dispatch-boundary enforcement point:
// it strips fields from the final xDrop HTTP body that are illegal for the
// attack's decoder DispatchClass. Called as the LAST step in the custom-payload
// pipeline (after specializeXDropDecoderBody) and after the default-payload
// marshal, so it sees the final shape before POST.
//
// DispatchClass rules:
//
//	Ported       → no-op (src_port/dst_port/tcp_flags all legal)
//	PortlessProto → delete src_port, dst_port, tcp_flags
//	Anomaly      → delete protocol, src_port, dst_port, tcp_flags
//	Unsupported  → no-op (engine.go gate prevents reaching here)
//
// See fix-plan-xdrop-port-bgp-schedule-2026-05-02.md §Bug 1.
func sanitizeXDropPayloadForDecoder(body []byte, decoderFamily string) []byte {
	dc := decoder.GetDispatchClass(decoderFamily)
	if dc == decoder.Ported || dc == decoder.Unsupported {
		return body
	}
	var m map[string]any
	if json.Unmarshal(body, &m) != nil {
		return body
	}
	switch dc {
	case decoder.PortlessProto:
		delete(m, "src_port")
		delete(m, "dst_port")
		delete(m, "tcp_flags")
	case decoder.Anomaly:
		delete(m, "protocol")
		delete(m, "src_port")
		delete(m, "dst_port")
		delete(m, "tcp_flags")
	}
	out, err := json.Marshal(m)
	if err != nil {
		return body
	}
	return out
}

// xDropSyntheticFailedRuleIDPrefix is attached to a rule row when xDrop's
// POST /rules failed before any real rule ID was returned (connect refused,
// timeout, 4xx/5xx, etc.). Surfaces the failure in `xdrop_active_rules` so
// Mitigations UI can show a "failed" badge, while letting the later unblock
// path recognize there's no real rule on the xDrop side to DELETE.
const xDropSyntheticFailedRuleIDPrefix = "failed-create-"

// syntheticFailedXDropRuleID returns a deterministic synthetic rule ID for a
// failed xDrop create. Deterministic on (attack, action) so retries upsert
// the same row (idempotent), and distinguishable via the prefix so the
// unblock path can skip the DELETE.
func syntheticFailedXDropRuleID(attackID, actionID int) string {
	return fmt.Sprintf("%s%d-%d", xDropSyntheticFailedRuleIDPrefix, attackID, actionID)
}

func isSyntheticFailedXDropRuleID(ruleID string) bool {
	return strings.HasPrefix(ruleID, xDropSyntheticFailedRuleIDPrefix)
}

// CloseSyntheticXDropRuleLocal honors the "no real rule to DELETE" contract
// for synthetic "failed-create-*" IDs: writes an audit log, marks the
// xdrop_active_rules row withdrawn, and (if `engine` is non-nil and
// scheduledActionID > 0) completes the corresponding scheduled_action.
//
// Called by both immediate and delayed unblock code paths. Keeping a single
// function guarantees the two paths can never drift — which is what the
// PR-8 audit specifically asked to lock down.
//
// Exported for focused integration testing from the tests package.
func CloseSyntheticXDropRuleLocal(
	ctx context.Context,
	s store.Store,
	engine *Engine,
	attackID, actionID, connectorID int,
	connectorName, triggerPhase, ruleID string,
	scheduledActionID int,
) {
	connID := connectorID
	s.ActionExecLog().Create(ctx, &store.ActionExecutionLog{
		AttackID:       attackID,
		ActionID:       actionID,
		ActionType:     "xdrop",
		ConnectorName:  connectorName,
		ConnectorID:    &connID,
		TriggerPhase:   triggerPhase,
		ExternalRuleID: ruleID,
		Status:         "success",
		ErrorMessage:   "synthetic failed-create rule; no xDrop DELETE needed",
		ExecutedAt:     time.Now(),
	})
	s.XDropActiveRules().MarkWithdrawn(ctx, attackID, actionID, connectorID, ruleID)
	if engine != nil && scheduledActionID > 0 {
		engine.CompleteDelay(ctx, scheduledActionID, attackID, actionID, connectorID, ruleID)
	}
}

// xdropRuleRequest is the default request body sent to xDrop API.
// Matches xDrop's RuleRequest format — any field left empty/zero is treated as wildcard.
type xdropRuleRequest struct {
	DstIP    string  `json:"dst_ip,omitempty"`
	DstCIDR  string  `json:"dst_cidr,omitempty"` // v1.3: subnet-scope rule (carpet bombing)
	SrcIP    string  `json:"src_ip,omitempty"`
	SrcCIDR  string  `json:"src_cidr,omitempty"`
	DstPort  int     `json:"dst_port,omitempty"`
	SrcPort  int     `json:"src_port,omitempty"`
	Protocol string  `json:"protocol,omitempty"`
	TcpFlags *string `json:"tcp_flags,omitempty"` // e.g. "SYN,!ACK"; requires protocol=tcp
	// Decoder (xdrop v2.6.1): set ONLY for anomaly decoders
	// (bad_fragment / invalid). xdrop Controller translates to
	// match_anomaly bitmap and protocol becomes wildcard. Non-anomaly
	// decoders MUST leave this field empty and use Protocol + TcpFlags.
	Decoder   string `json:"decoder,omitempty"`
	Action    string `json:"action"`               // "drop" or "rate_limit"
	RateLimit int    `json:"rate_limit,omitempty"` // PPS, required if action=rate_limit
	Source    string `json:"source"`               // "xsight"
	Comment   string `json:"comment,omitempty"`
}

// splitIPOrCIDR separates "10.0.0.1" vs "10.0.0.0/24".
// Returns (ip, cidr) where exactly one is populated: ip for /32|/128|bare,
// cidr for anything shorter. Used to route subnet-scope attacks (carpet bombing)
// to xDrop's dst_cidr match field instead of exact dst_ip.
func splitIPOrCIDR(s string) (ip, cidr string) {
	idx := strings.IndexByte(s, '/')
	if idx < 0 {
		return s, ""
	}
	host := s[:idx]
	plStr := s[idx+1:]
	// IPv4 /32 and IPv6 /128 are effectively exact IPs; route to dst_ip.
	if strings.Contains(host, ":") {
		if plStr == "128" {
			return host, ""
		}
	} else {
		if plStr == "32" {
			return host, ""
		}
	}
	return "", s
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
	engine *Engine, // nil-safe: if non-nil, used to schedule per-artifact cancelable delays
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
		// Normalize protocol field: xSight decoder_family values like "ip"
		// and "fragment" are not in xDrop's protocol enum; translate them
		// (e.g. "ip" → "all") so custom payloads with `{decoder}` work
		// across all threshold rule types without operator translation.
		body = normalizeXDropProtocol(body)
		// Auto-inject tcp_flags for TCP-flag-family attacks if not already
		// specified. Runs AFTER normalize so its protocol rewrite still
		// wins when protocol=<tcp_flag_decoder> expanded from {decoder}.
		body = injectTcpFlags(body, attack)
		// Auto-fill decoder / protocol for anomaly + gre/esp/igmp attacks
		// when operator's custom payload omitted them (parallel to
		// specializeXDropDecoder on the default-payload path). Runs last
		// so it sees the post-normalize + post-inject shape.
		body = specializeXDropDecoderBody(body, attack)
		// Final enforcement: strip fields illegal for this decoder's
		// DispatchClass (e.g. src_port/dst_port on GRE attacks). Runs
		// last so it catches any stray fields from expandParams or
		// fixPayloadTypes that the earlier steps did not remove.
		body = sanitizeXDropPayloadForDecoder(body, attack.DecoderFamily)
	} else {
		// Default payload: dst_ip drop/rate_limit based on xdrop_action.
		// v1.3 Phase 1c.1: subnet-scope attacks (carpet bombing) use dst_cidr
		// instead of dst_ip so xDrop matches on the whole subnet.
		actionStr := "drop"
		if xdropAction == "rate_limit" {
			actionStr = "rate_limit"
		}
		dstIP, dstCIDR := splitIPOrCIDR(attack.DstIP)
		payload := xdropRuleRequest{
			DstIP:   dstIP,
			DstCIDR: dstCIDR,
			Action:  actionStr,
			Source:  "xsight",
			Comment: fmt.Sprintf("attack #%d %s", attack.ID, attack.AttackType),
		}
		specializeXDropDecoder(&payload, attack.DecoderFamily)
		body, err = json.Marshal(payload)
		if err != nil {
			return nil, fmt.Errorf("marshal xdrop payload: %w", err)
		}
		// Defense-in-depth: the typed struct never sets ports for non-L4
		// decoders, but run the sanitizer anyway so the invariant holds
		// regardless of future struct changes.
		body = sanitizeXDropPayloadForDecoder(body, attack.DecoderFamily)
	}

	// Late anomaly fail-fast: the engine.go gate catches XDropAction=rate_limit
	// + anomaly decoder combos when the action record is used directly. But a
	// custom payload can inject `"action":"rate_limit"` in its JSON body even
	// when act.XDropAction == "filter_l4" (operator mismatch). Check the
	// final body here to catch that case with the same skip_reason —
	// dispatch-time fail-fast on real body semantics, not just on the action
	// record. See codex v1.3.x audit P2.
	if isAnomalyRateLimitBody(body, attack.DecoderFamily) {
		// Caller (engine.go xdrop branch) persists the returned execLog via
		// ActionExecLog().Create — we must NOT write it ourselves here, or
		// both rows + both status="skipped" counter increments would land
		// (see codex v1.3.x re-audit finding). RecordSkip IS ours to call
		// because the caller doesn't know the skip_reason.
		skipLog := &store.ActionExecutionLog{
			AttackID:     attackDBID,
			ActionID:     action.ID,
			ResponseName: responseName,
			ActionType:   "xdrop",
			TriggerPhase: triggerPhase,
			Status:       "skipped",
			SkipReason:   SkipReasonXDropAnomalyRequiresDrop,
			ErrorMessage: fmt.Sprintf(
				"decoder=%s + body action=rate_limit unsupported (xdrop v2.6.1 anomaly rules are drop-only); custom payload overrides XDropAction",
				attack.DecoderFamily),
			RequestBody: truncateStr(string(body), 1024),
			ExecutedAt:  time.Now(),
		}
		metrics.RecordSkip(SkipReasonXDropAnomalyRequiresDrop)
		return skipLog, nil
	}

	// Runtime sanity: rate_limit action must have a positive rate_limit in the payload.
	// API validation should prevent this, but guard against malformed DB rows.
	//
	// v1.3.4: previously returned (nil, err), which caused the caller to skip
	// writing an action_execution_log row — operator saw nothing in UI/timeline
	// despite the dispatch being rejected. Now returns a populated failed log
	// so the reason is visible in the execution history.
	if xdropAction == "rate_limit" {
		var check map[string]any
		if json.Unmarshal(body, &check) == nil {
			rl, _ := check["rate_limit"].(float64)
			if rl <= 0 {
				errMsg := "xdrop rate_limit action has no valid rate_limit value in payload"
				failLog := &store.ActionExecutionLog{
					AttackID:     attackDBID,
					ActionID:     action.ID,
					ResponseName: responseName,
					ActionType:   "xdrop",
					TriggerPhase: triggerPhase,
					Status:       "failed",
					ErrorMessage: errMsg,
					RequestBody:  truncateStr(string(body), 1024),
					ExecutedAt:   time.Now(),
				}
				return failLog, fmt.Errorf("%s", errMsg)
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

			// Per-artifact manual_override suppression: v1.2 PR-2 uses the
			// indexed action_manual_overrides table instead of scanning
			// execution logs. Pre-fetch set for the attack, then O(1)
			// membership check per rule.
			//
			// Key must include action_id — two different actions on the same
			// attack may share connector+rule, but operator force-removing one
			// must NOT suppress the other. Matches the UNIQUE business key on
			// the action_manual_overrides table.
			overrides, err := s.ManualOverrides().ListByAttack(ctx, attackDBID)
			if err != nil {
				log.Printf("action: xdrop unblock override lookup failed (attack=%d): %v — proceeding without override filter", attackDBID, err)
			}
			overrideSet := make(map[string]bool, len(overrides))
			for _, o := range overrides {
				overrideSet[fmt.Sprintf("%d:%d:%s", o.ActionID, o.ConnectorID, o.ExternalRuleID)] = true
			}
			var filteredRules []store.RuleWithAction
			for _, ra := range rulesWithActions {
				key := fmt.Sprintf("%d:%d:%s", ra.ActionID, conn.ID, ra.RuleID)
				if overrideSet[key] {
					log.Printf("action: xdrop unblock skipping rule %s (manual override, attack=%d action=%d)", ra.RuleID, attackDBID, ra.ActionID)
					continue
				}
				filteredRules = append(filteredRules, ra)
			}
			rulesWithActions = filteredRules
			if len(rulesWithActions) == 0 {
				continue // all rules on this connector were force-removed
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

			// Delete immediate rules now — write per-rule exec log so Mitigations can match
			deleted := 0
			var lastErr string
			for _, ruleID := range immediateRules {
				// v1.2 PR-4: transition active→withdrawing before side effect.
				// If the row has already moved to withdrawing/withdrawn/failed
				// (another goroutine got there first, or a force-remove landed),
				// MarkWithdrawing returns false and we skip this artifact.
				actionIDForRule := action.ID
				for _, ra := range rulesWithActions {
					if ra.RuleID == ruleID {
						actionIDForRule = ra.ActionID
						break
					}
				}
				if ok, _ := s.XDropActiveRules().MarkWithdrawing(ctx, attackDBID, actionIDForRule, connID, ruleID); !ok {
					// Row not in active/delayed — either no row (legacy) or already
					// past this transition. Proceed anyway for backward compat with
					// rules that predate PR-4 bootstrap.
					log.Printf("action: xdrop unblock rule %s not in active state (proceeding, attack=%d)", ruleID, attackDBID)
				}

				// Synthetic "failed-create-*" IDs never made it onto the xDrop
				// node, so DELETE would pointlessly 404. Skip the HTTP call and
				// close the row locally — this also cleans up failed rows in
				// the state table instead of letting them linger.
				if isSyntheticFailedXDropRuleID(ruleID) {
					deleted++
					CloseSyntheticXDropRuleLocal(ctx, s, nil, attackDBID, actionIDForRule, connID, conn.Name, triggerPhase, ruleID, 0)
					continue
				}

				delURL := apiURL + "/" + ruleID
				req, err := http.NewRequestWithContext(ctx, "DELETE", delURL, nil)
				if err != nil {
					lastErr = fmt.Sprintf("create request: %v", err)
					s.ActionExecLog().Create(ctx, &store.ActionExecutionLog{
						AttackID: attackDBID, ActionID: actionIDForRule, ActionType: "xdrop",
						ConnectorName: conn.Name, ConnectorID: &connID, TriggerPhase: triggerPhase,
						ExternalRuleID: ruleID, Status: "failed", ErrorMessage: lastErr, ExecutedAt: time.Now(),
					})
					s.XDropActiveRules().MarkFailed(ctx, attackDBID, actionIDForRule, connID, ruleID, lastErr)
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
					s.ActionExecLog().Create(ctx, &store.ActionExecutionLog{
						AttackID: attackDBID, ActionID: actionIDForRule, ActionType: "xdrop",
						ConnectorName: conn.Name, ConnectorID: &connID, TriggerPhase: triggerPhase,
						ExternalRuleID: ruleID, Status: "failed", ErrorMessage: lastErr, ExecutedAt: time.Now(),
					})
					s.XDropActiveRules().MarkFailed(ctx, attackDBID, actionIDForRule, connID, ruleID, lastErr)
					continue
				}
				resp.Body.Close()
				if resp.StatusCode < 400 || resp.StatusCode == 404 {
					// Success or 404 (rule already gone) — treat as idempotent success
					deleted++
					status := "success"
					errMsg := ""
					if resp.StatusCode == 404 {
						errMsg = "idempotent: rule already deleted"
						log.Printf("action: xdrop unblock rule %s already gone (404, attack=%d)", ruleID, attackDBID)
					}
					ruleLog := &store.ActionExecutionLog{
						AttackID:       attackDBID,
						ActionID:       actionIDForRule,
						ActionType:     "xdrop",
						ConnectorName:  conn.Name,
						ConnectorID:    &connID,
						TriggerPhase:   triggerPhase,
						ExternalRuleID: ruleID,
						Status:         status,
						ErrorMessage:   errMsg,
						ExecutedAt:     time.Now(),
					}
					if _, err := s.ActionExecLog().Create(ctx, ruleLog); err != nil {
						log.Printf("action: create per-rule unblock log: %v", err)
					}
					s.XDropActiveRules().MarkWithdrawn(ctx, attackDBID, actionIDForRule, connID, ruleID)
				} else {
					lastErr = fmt.Sprintf("DELETE %s: HTTP %d", delURL, resp.StatusCode)
					// Write per-rule failed log with full business key
					failLog := &store.ActionExecutionLog{
						AttackID:       attackDBID,
						ActionID:       actionIDForRule,
						ActionType:     "xdrop",
						ConnectorName:  conn.Name,
						ConnectorID:    &connID,
						TriggerPhase:   triggerPhase,
						ExternalRuleID: ruleID,
						Status:         "failed",
						ErrorMessage:   fmt.Sprintf("HTTP %d", resp.StatusCode),
						ExecutedAt:     time.Now(),
					}
					if _, err := s.ActionExecLog().Create(ctx, failLog); err != nil {
						log.Printf("action: create per-rule failed log: %v", err)
					}
					s.XDropActiveRules().MarkFailed(ctx, attackDBID, actionIDForRule, connID, ruleID, fmt.Sprintf("HTTP %d", resp.StatusCode))
				}
			}

			// Schedule delayed rule deletions — write "scheduled" log entries for Mitigations UI
			for _, dr := range delayedRules {
				scheduledFor := time.Now().Add(dr.delay)
				// Resolve the action_id for THIS rule (may differ from the
				// enclosing action when rules came from multiple actions).
				ruleActionID := action.ID
				for _, ra := range rulesWithActions {
					if ra.RuleID == dr.ruleID {
						ruleActionID = ra.ActionID
						break
					}
				}
				// v1.2 PR-4 P2 fix: persist the schedule FIRST, before mutating
				// xdrop_active_rules. If persistence fails we must not put the
				// rule into the authoritative `delayed` state — that would leave
				// it permanently stuck in Mitigations UI with no recovery path
				// (ReconcileOnStartup only scans scheduled_actions/withdrawing,
				// never xdrop_active_rules.delayed alone).
				var schedID int
				var cancelCtx context.Context
				var persistErr error
				if engine != nil {
					id, cctx, perr := engine.ScheduleDelay(ctx, "xdrop_unblock", attackDBID, ruleActionID, connID, dr.ruleID, scheduledFor)
					if perr != nil {
						persistErr = perr
						log.Printf("action: xdrop ScheduleDelay persist failed rule=%s attack=%d action=%d: %v", dr.ruleID, attackDBID, ruleActionID, perr)
					} else {
						schedID = id
						cancelCtx = cctx
					}
				}
				if persistErr != nil {
					// Schedule did not persist — refuse to pretend the artifact is
					// in durable delayed state. Mark as failed so operator can see
					// the broken state in Mitigations and Force Unblock manually.
					// No goroutine launched: without persistence, a restart mid-delay
					// would lose the task silently, which is exactly what PR-3/PR-4
					// are trying to prevent.
					errMsg := fmt.Sprintf("schedule persist failed: %v", persistErr)
					s.XDropActiveRules().MarkFailed(ctx, attackDBID, ruleActionID, connID, dr.ruleID, errMsg)
					failSched := &store.ActionExecutionLog{
						AttackID:       attackDBID,
						ActionID:       ruleActionID,
						ActionType:     "xdrop",
						TriggerPhase:   triggerPhase,
						ResponseName:   responseName,
						ConnectorName:  conn.Name,
						ConnectorID:    &connID,
						ExternalRuleID: dr.ruleID,
						Status:         "failed",
						ErrorMessage:   errMsg,
						ExecutedAt:     time.Now(),
					}
					if _, err := s.ActionExecLog().Create(ctx, failSched); err != nil {
						log.Printf("action: create failed schedule log rule=%s: %v", dr.ruleID, err)
					}
					continue
				}

				// Schedule persisted — safe to advertise delayed state.
				if err := s.XDropActiveRules().MarkDelayed(ctx, attackDBID, ruleActionID, connID, dr.ruleID, int(dr.delay/time.Minute)); err != nil {
					log.Printf("action: xdrop_active_rules mark delayed rule=%s: %v", dr.ruleID, err)
				}
				schedLog := &store.ActionExecutionLog{
					AttackID:       attackDBID,
					ActionID:       ruleActionID,
					ActionType:     "xdrop",
					TriggerPhase:   triggerPhase,
					ResponseName:   responseName,
					ConnectorName:  conn.Name,
					ConnectorID:    &connID,
					ExternalRuleID: dr.ruleID,
					Status:         "scheduled",
					ErrorMessage:   fmt.Sprintf("delayed unblock in %v", dr.delay),
					ScheduledFor:   &scheduledFor,
					ExecutedAt:     time.Now(),
				}
				if _, err := s.ActionExecLog().Create(ctx, schedLog); err != nil {
					log.Printf("action: create scheduled log for rule %s: %v", dr.ruleID, err)
				}
				log.Printf("action: scheduling delayed unblock rule %s in %v (attack=%d connector=%d)",
					dr.ruleID, dr.delay, attackDBID, conn.ID)
				go func(ruleID string, d time.Duration, connCopy store.XDropConnector, cID int, sid int, cctx context.Context, aID int) {
					// Per-artifact cancelable delay via Engine
					if engine != nil && cctx != nil {
						select {
						case <-time.After(d):
							// Race guard before side-effect
							execGuardCtx, gc := context.WithTimeout(context.Background(), 5*time.Second)
							ok := engine.MarkExecutingDelay(execGuardCtx, sid)
							gc()
							if !ok {
								log.Printf("action: delayed unblock rule %s skipped attack=%d scheduled_id=%d (no longer pending)", ruleID, attackDBID, sid)
								return
							}
						case <-cctx.Done():
							log.Printf("action: delayed unblock rule %s cancelled attack=%d scheduled_id=%d", ruleID, attackDBID, sid)
							return
						}
					} else {
						time.Sleep(d) // legacy fallback
					}
					// v1.2 PR-4: transition delayed → withdrawing before side effect
					markCtx, mc := context.WithTimeout(context.Background(), 5*time.Second)
					s.XDropActiveRules().MarkWithdrawing(markCtx, attackDBID, aID, cID, ruleID)
					mc()

					// Synthetic "failed-create-*" IDs never made it onto the
					// xDrop node. Same contract as the immediate unblock loop:
					// skip the HTTP DELETE, close the row locally, and mark
					// the scheduled_action complete. Without this, delayed
					// unblock would fire a real DELETE against /rules/failed-
					// create-... which could 4xx/5xx and leak the row into a
					// spurious failed state. PR-8 audit P1.
					if isSyntheticFailedXDropRuleID(ruleID) {
						log.Printf("action: delayed unblock rule %s is synthetic failed-create; no xDrop DELETE needed (attack=%d)", ruleID, attackDBID)
						localCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
						CloseSyntheticXDropRuleLocal(localCtx, s, engine, attackDBID, aID, cID, connCopy.Name, triggerPhase, ruleID, sid)
						cancel()
						return
					}

					delCtx, delCancel := context.WithTimeout(context.Background(), 30*time.Second)
					defer delCancel()
					delURL := strings.TrimRight(connCopy.APIURL, "/") + "/rules/" + ruleID
					req, err := http.NewRequestWithContext(delCtx, "DELETE", delURL, nil)
					if err != nil {
						log.Printf("action: delayed unblock rule %s failed: %v", ruleID, err)
						errCtx, ec := context.WithTimeout(context.Background(), 5*time.Second)
						s.ActionExecLog().Create(errCtx, &store.ActionExecutionLog{
							AttackID: attackDBID, ActionID: aID, ActionType: "xdrop",
							ConnectorName: connCopy.Name, ConnectorID: &cID, TriggerPhase: triggerPhase,
							ExternalRuleID: ruleID, Status: "failed", ErrorMessage: fmt.Sprintf("create request: %v", err), ExecutedAt: time.Now(),
						})
						s.XDropActiveRules().MarkFailed(errCtx, attackDBID, aID, cID, ruleID, fmt.Sprintf("create request: %v", err))
						ec()
						if engine != nil {
							engine.FailDelay(context.Background(), sid, attackDBID, aID, cID, ruleID, fmt.Sprintf("create request: %v", err))
						}
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
						errCtx2, ec2 := context.WithTimeout(context.Background(), 5*time.Second)
						s.ActionExecLog().Create(errCtx2, &store.ActionExecutionLog{
							AttackID: attackDBID, ActionID: aID, ActionType: "xdrop",
							ConnectorName: connCopy.Name, ConnectorID: &cID, TriggerPhase: triggerPhase,
							ExternalRuleID: ruleID, Status: "failed", ErrorMessage: fmt.Sprintf("DELETE: %v", err), ExecutedAt: time.Now(),
						})
						s.XDropActiveRules().MarkFailed(errCtx2, attackDBID, aID, cID, ruleID, fmt.Sprintf("DELETE: %v", err))
						ec2()
						if engine != nil {
							engine.FailDelay(context.Background(), sid, attackDBID, aID, cID, ruleID, fmt.Sprintf("DELETE: %v", err))
						}
						return
					}
					resp.Body.Close()
					log.Printf("action: delayed unblock rule %s completed (HTTP %d, attack=%d)", ruleID, resp.StatusCode, attackDBID)
					if resp.StatusCode < 400 || resp.StatusCode == 404 {
						// Success or 404 (already gone) — idempotent success
						logStatus := "success"
						logErr := ""
						if resp.StatusCode == 404 {
							logStatus = "success"
							logErr = "idempotent: rule already deleted"
							log.Printf("action: delayed unblock rule %s already gone (404, attack=%d)", ruleID, attackDBID)
						}
						ruleLog := &store.ActionExecutionLog{
							AttackID:       attackDBID,
							ActionID:       aID,
							ActionType:     "xdrop",
							ConnectorName:  connCopy.Name,
							ConnectorID:    &cID,
							TriggerPhase:   triggerPhase,
							ExternalRuleID: ruleID,
							Status:         logStatus,
							ErrorMessage:   logErr,
							ExecutedAt:     time.Now(),
						}
						logCtx, lc := context.WithTimeout(context.Background(), 5*time.Second)
						if _, err := s.ActionExecLog().Create(logCtx, ruleLog); err != nil {
							log.Printf("action: create per-rule delayed unblock log: %v", err)
						}
						// v1.2 PR-4: state table withdrawing → withdrawn
						s.XDropActiveRules().MarkWithdrawn(logCtx, attackDBID, aID, cID, ruleID)
						lc()
						// v1.2 PR-3: mark scheduled_action completed
						if engine != nil {
							doneCtx, dc := context.WithTimeout(context.Background(), 5*time.Second)
							engine.CompleteDelay(doneCtx, sid, attackDBID, aID, cID, ruleID)
							dc()
						}
					} else {
						// Real failure — write per-rule failed log
						failLog := &store.ActionExecutionLog{
							AttackID:       attackDBID,
							ActionID:       aID,
							ActionType:     "xdrop",
							ConnectorName:  connCopy.Name,
							ConnectorID:    &cID,
							TriggerPhase:   triggerPhase,
							ExternalRuleID: ruleID,
							Status:         "failed",
							ErrorMessage:   fmt.Sprintf("HTTP %d", resp.StatusCode),
							ExecutedAt:     time.Now(),
						}
						logCtx2, lc2 := context.WithTimeout(context.Background(), 5*time.Second)
						if _, err := s.ActionExecLog().Create(logCtx2, failLog); err != nil {
							log.Printf("action: create per-rule delayed failed log: %v", err)
						}
						// v1.2 PR-4: state table → failed
						s.XDropActiveRules().MarkFailed(logCtx2, attackDBID, aID, cID, ruleID, fmt.Sprintf("HTTP %d", resp.StatusCode))
						lc2()
						// v1.2 PR-3: mark scheduled_action failed
						if engine != nil {
							doneCtx, dc := context.WithTimeout(context.Background(), 5*time.Second)
							engine.FailDelay(doneCtx, sid, attackDBID, aID, cID, ruleID, fmt.Sprintf("HTTP %d", resp.StatusCode))
							dc()
						}
					}
				}(dr.ruleID, dr.delay, conn, connID, schedID, cancelCtx, ruleActionID)
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
			// v1.2 PR-4 bug fix: surface create failures in xdrop_active_rules
			// via a synthetic rule ID so Mitigations UI shows a failed badge
			// instead of silently dropping the failure on the floor.
			if triggerPhase == "on_detected" {
				execLog.ExternalRuleID = syntheticFailedXDropRuleID(attackDBID, action.ID)
				s.XDropActiveRules().Upsert(ctx, &store.XDropActiveRule{
					AttackID: attackDBID, ActionID: action.ID, ConnectorID: conn.ID,
					ExternalRuleID: execLog.ExternalRuleID,
					Status:         "failed",
					ErrorMessage:   execLog.ErrorMessage,
				})
			}
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
			// v1.2 PR-4 bug fix: see above — synthetic ID keeps failed state
			// visible in Mitigations even when the HTTP layer never completed.
			if triggerPhase == "on_detected" {
				execLog.ExternalRuleID = syntheticFailedXDropRuleID(attackDBID, action.ID)
				s.XDropActiveRules().Upsert(ctx, &store.XDropActiveRule{
					AttackID: attackDBID, ActionID: action.ID, ConnectorID: conn.ID,
					ExternalRuleID: execLog.ExternalRuleID,
					Status:         "failed",
					ErrorMessage:   execLog.ErrorMessage,
				})
			}
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
			// v1.2 PR-4 bug fix: no real rule ID returned on 4xx/5xx — use a
			// synthetic one so the failure lands in xdrop_active_rules.
			if triggerPhase == "on_detected" {
				execLog.ExternalRuleID = syntheticFailedXDropRuleID(attackDBID, action.ID)
			}
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

		// v1.2 PR-4: record xdrop rule state. Written for both success and
		// failure so Mitigations UI can surface 'failed' state from the table
		// rather than reverse-engineering from execution log. Failure paths
		// above populate a synthetic ExternalRuleID — see
		// syntheticFailedXDropRuleID.
		if triggerPhase == "on_detected" && execLog.ExternalRuleID != "" {
			ruleState := &store.XDropActiveRule{
				AttackID:       attackDBID,
				ActionID:       action.ID,
				ConnectorID:    conn.ID,
				ExternalRuleID: execLog.ExternalRuleID,
				Status:         "active",
			}
			if execLog.Status == "failed" {
				ruleState.Status = "failed"
				ruleState.ErrorMessage = execLog.ErrorMessage
			}
			if _, err := s.XDropActiveRules().Upsert(ctx, ruleState); err != nil {
				log.Printf("action: xdrop_active_rules upsert rule=%s: %v", execLog.ExternalRuleID, err)
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

// decoderToXDropProtocol maps xSight decoder_family values to xDrop's
// protocol field.
//
//	xSight decoder_family (protocol path):
//	  tcp / tcp_syn / tcp_ack / tcp_rst / tcp_fin → "tcp"
//	  udp                                         → "udp"
//	  icmp                                        → "icmp"
//	  gre / esp / igmp                            → "gre" / "esp" / "igmp"
//	  ip / fragment                               → "all"
//	  "" / unknown                                → ""  (caller leaves field alone)
//
// Anomaly decoders (bad_fragment/invalid) do NOT appear here — they
// dispatch through xdrop's `decoder` field (see isAnomalyDecoder +
// default-payload builder); trying to set protocol would either collapse
// to "all" (ambiguous) or duplicate the anomaly bit that Controller
// derives from `decoder`.
//
// TCP-flag-family decoders collapse to "tcp"; the flag specialization
// is injected separately by injectTcpFlags / the default payload builder.
func decoderToXDropProtocol(decoder string) string {
	switch decoder {
	case "tcp", "tcp_syn", "tcp_ack", "tcp_rst", "tcp_fin":
		return "tcp"
	case "udp":
		return "udp"
	case "icmp":
		return "icmp"
	case "gre":
		return "gre"
	case "esp":
		return "esp"
	case "igmp":
		return "igmp"
	case "ip", "fragment":
		return "all"
	default:
		return ""
	}
}

// normalizeXDropProtocol rewrites the `protocol` field in a custom xDrop
// payload to a value the xDrop API accepts. Runs unconditionally for every
// custom-payload xDrop request (after expandParams + fixPayloadTypes, before
// injectTcpFlags).
//
// Why this exists: operators configure payloads like
// `"protocol": "{decoder}"` for convenience. `{decoder}` expands to xSight's
// decoder_family name, which xDrop rejects as-is because its protocol enum
// is narrower. Without this normalization the rule create fails with HTTP
// 400 and the attack's xdrop_active_rules row goes to the failed state.
//
// Rewrite rules:
//   - protocol already a valid xDrop value (all/tcp/udp/icmp/icmpv6/gre/
//     esp/igmp) → no change
//   - protocol is an anomaly decoder (bad_fragment/invalid): MOVE the
//     value to the `decoder` field (anomaly rules are protocol-wildcard +
//     decoder-bit in xdrop v2.6.1) and delete `protocol`. Idempotent if
//     `decoder` is already set.
//   - protocol maps via decoderToXDropProtocol (tcp_syn/tcp_ack/tcp_rst/
//     tcp_fin → tcp, fragment → all, ip → all) → rewrite protocol
//   - protocol is something else → no change (let xDrop surface error)
//
// Not reached paths (kept for defense-in-depth): `ip` / `ip_other` are
// gated out at the engine dispatch layer before executeXDrop runs (see
// IsXDropCompatibleDecoder), but decoderToXDropProtocol still maps `ip`
// → `all` so an operator who hand-crafts a payload with literal
// "protocol":"ip" gets a working rule instead of a 400.
func normalizeXDropProtocol(body []byte) []byte {
	var m map[string]any
	if json.Unmarshal(body, &m) != nil {
		return body
	}
	proto, ok := m["protocol"].(string)
	if !ok || proto == "" {
		return body
	}
	// Already valid xDrop value — leave alone. Include gre/esp/igmp so
	// custom payloads with literal `"protocol":"gre"` don't get rewritten.
	switch proto {
	case "all", "tcp", "udp", "icmp", "icmpv6", "gre", "esp", "igmp":
		return body
	}
	// Anomaly decoder expanded from {decoder}: move to the xdrop `decoder`
	// field. xdrop anomaly rules are protocol-wildcard + decoder-bit; keeping
	// protocol set to a non-enum value would be rejected.
	if isAnomalyDecoder(proto) {
		delete(m, "protocol")
		if _, has := m["decoder"]; !has {
			m["decoder"] = proto
		}
		if out, err := json.Marshal(m); err == nil {
			return out
		}
		return body
	}
	if mapped := decoderToXDropProtocol(proto); mapped != "" && mapped != proto {
		m["protocol"] = mapped
		if out, err := json.Marshal(m); err == nil {
			return out
		}
	}
	return body
}

// injectTcpFlags auto-injects tcp_flags and normalizes protocol for the
// TCP-flag family (tcp_syn/tcp_ack/tcp_rst/tcp_fin). Pass-through for
// non-TCP-flag decoders.
//
// Rules:
//   - TCP-flag attack without tcp_flags → inject canonical pattern from
//     tcpFlagDecoderMap + protocol=tcp
//   - TCP-flag attack with tcp_flags already set → keep operator's flags,
//     still ensure protocol=tcp
//   - TCP-flag attack with protocol=<decoder> (from {decoder} expansion) → tcp
//   - non-TCP-flag attack → no changes
func injectTcpFlags(body []byte, attack *store.Attack) []byte {
	canonicalFlags, ok := tcpFlagDecoderMap[attack.DecoderFamily]
	if !ok {
		return body
	}
	var m map[string]any
	if json.Unmarshal(body, &m) != nil {
		return body
	}
	if _, has := m["tcp_flags"]; !has {
		m["tcp_flags"] = canonicalFlags
	}
	// Always normalize protocol to tcp (covers bare + {decoder}-expanded cases)
	proto, _ := m["protocol"].(string)
	if proto == "" || proto == attack.DecoderFamily {
		m["protocol"] = "tcp"
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
