package action

import (
	"context"
	"fmt"
	"log"
	"net"
	"os/exec"
	"strings"
	"time"

	"github.com/littlewolf9527/xsight/controller/internal/store"
)

// addressFamilyForPrefix returns the FRR address-family string based on the prefix's IP version.
// Uses net.ParseCIDR / net.ParseIP for robust detection — not string heuristics.
func addressFamilyForPrefix(prefix string) string {
	if isIPv6(prefix) {
		return "ipv6 unicast"
	}
	return "ipv4 unicast"
}

// isIPv6 determines whether a prefix or IP string is IPv6.
// Handles both CIDR ("2001:db8::/32") and plain IP ("2001:db8::1") forms.
func isIPv6(s string) bool {
	if _, cidr, err := net.ParseCIDR(s); err == nil {
		return cidr.IP.To4() == nil
	}
	if ip := net.ParseIP(s); ip != nil {
		return ip.To4() == nil
	}
	return false
}

// splitExternalRuleID splits "{prefix}|{route_map}" into (prefix, routeMap).
// Uses "|" as separator to avoid collision with ":" in IPv6 addresses.
// Falls back to ":" for backward compatibility with pre-v1.1.1 records.
func splitExternalRuleID(ruleID string) []string {
	if idx := strings.LastIndex(ruleID, "|"); idx >= 0 {
		return []string{ruleID[:idx], ruleID[idx+1:]}
	}
	// Backward compat: old records used ":" separator.
	// Use LastIndex to handle IPv6 addresses like "2001:db8::1/128:RTBH".
	if idx := strings.LastIndex(ruleID, ":"); idx >= 0 {
		return []string{ruleID[:idx], ruleID[idx+1:]}
	}
	return []string{ruleID}
}

// executeBGP runs a vtysh command to inject or withdraw a BGP route.
// on_detected: "network {dst_ip} route-map {route_map}"
// on_expired:  looks up prior injections from action_execution_log and withdraws each.
func executeBGP(ctx context.Context, s store.Store, act store.ResponseAction,
	attack *store.Attack, eventType, prefixStr, responseName, triggerPhase string,
	attackDBID int, fa func() *FlowAnalysis) (*store.ActionExecutionLog, error) {

	conn, err := s.BGPConnectors().Get(ctx, *act.BGPConnectorID)
	if err != nil {
		return &store.ActionExecutionLog{
			AttackID:     attackDBID,
			ActionID:     act.ID,
			ActionType:   "bgp",
			TriggerPhase: triggerPhase,
			ResponseName: responseName,
			Status:       "failed",
			ErrorMessage: fmt.Sprintf("bgp connector %d not found: %v", *act.BGPConnectorID, err),
			ExecutedAt:   time.Now(),
		}, err
	}

	if !conn.Enabled {
		return &store.ActionExecutionLog{
			AttackID:      attackDBID,
			ActionID:      act.ID,
			ActionType:    "bgp",
			TriggerPhase:  triggerPhase,
			ResponseName:  responseName,
			ConnectorName: conn.Name,
			Status:        "skipped",
			ErrorMessage:  "bgp connector disabled",
			ExecutedAt:    time.Now(),
		}, nil
	}

	// Determine the target prefix/IP to announce or withdraw
	dstIP := attack.DstIP
	// Ensure mask suffix for plain IPs (internal_ip domain): /32 for IPv4, /128 for IPv6
	if !strings.Contains(dstIP, "/") {
		if isIPv6(dstIP) {
			dstIP = dstIP + "/128"
		} else {
			dstIP = dstIP + "/32"
		}
	}

	switch triggerPhase {
	case "on_detected":
		return bgpAnnounce(ctx, conn, act, dstIP, attackDBID, responseName, triggerPhase)
	case "on_expired":
		return bgpWithdraw(ctx, s, conn, act, dstIP, attackDBID, responseName, triggerPhase)
	default:
		return &store.ActionExecutionLog{
			AttackID:     attackDBID,
			ActionID:     act.ID,
			ActionType:   "bgp",
			TriggerPhase: triggerPhase,
			ResponseName: responseName,
			Status:       "skipped",
			ErrorMessage: fmt.Sprintf("unknown trigger_phase: %s", triggerPhase),
			ExecutedAt:   time.Now(),
		}, nil
	}
}

// bgpAnnounce injects a route via vtysh.
func bgpAnnounce(ctx context.Context, conn *store.BGPConnector, act store.ResponseAction,
	dstIP string, attackDBID int, responseName, triggerPhase string) (*store.ActionExecutionLog, error) {

	routeMap := act.BGPRouteMap
	af := addressFamilyForPrefix(dstIP)
	cmd := fmt.Sprintf("configure terminal\nrouter bgp %d\naddress-family %s\nnetwork %s route-map %s",
		conn.BGPASN, af, dstIP, routeMap)

	t0 := time.Now()
	out, err := runVtysh(ctx, conn.VtyshPath, cmd)
	durationMs := int(time.Since(t0).Milliseconds())

	externalRuleID := fmt.Sprintf("%s|%s", dstIP, routeMap)

	if err != nil {
		log.Printf("action: bgp announce failed: %v output=%s", err, out)
		return &store.ActionExecutionLog{
			AttackID:       attackDBID,
			ActionID:       act.ID,
			ActionType:     "bgp",
			TriggerPhase:   triggerPhase,
			ResponseName:   responseName,
			ConnectorName:  conn.Name,
			Status:         "failed",
			ErrorMessage:   fmt.Sprintf("vtysh: %v", err),
			RequestBody:    cmd,
			ResponseBody:   out,
			ExternalRuleID: externalRuleID,
			DurationMs:     durationMs,
			ExecutedAt:     t0,
		}, err
	}

	log.Printf("action: bgp announce %s route-map=%s connector=%s", dstIP, routeMap, conn.Name)
	connID := &conn.ID
	return &store.ActionExecutionLog{
		AttackID:       attackDBID,
		ActionID:       act.ID,
		ActionType:     "bgp",
		TriggerPhase:   triggerPhase,
		ResponseName:   responseName,
		ConnectorName:  conn.Name,
		ConnectorID:    connID,
		Status:         "success",
		RequestBody:    cmd,
		ResponseBody:   out,
		ExternalRuleID: externalRuleID,
		DurationMs:     durationMs,
		ExecutedAt:     t0,
	}, nil
}

// bgpWithdraw removes previously injected routes for an attack.
func bgpWithdraw(ctx context.Context, s store.Store, conn *store.BGPConnector, act store.ResponseAction,
	dstIP string, attackDBID int, responseName, triggerPhase string) (*store.ActionExecutionLog, error) {

	// Find all BGP routes injected for this attack from action_execution_log
	logs, err := s.ActionExecLog().ListByAttack(ctx, attackDBID)
	if err != nil {
		return &store.ActionExecutionLog{
			AttackID:     attackDBID,
			ActionID:     act.ID,
			ActionType:   "bgp",
			TriggerPhase: triggerPhase,
			ResponseName: responseName,
			Status:       "failed",
			ErrorMessage: fmt.Sprintf("lookup prior bgp rules: %v", err),
			ExecutedAt:   time.Now(),
		}, err
	}

	var withdrawn []string
	var errors []string
	var skippedOverride int
	for _, logEntry := range logs {
		if logEntry.ActionType != "bgp" || logEntry.Status != "success" || logEntry.TriggerPhase != "on_detected" || logEntry.ExternalRuleID == "" {
			continue
		}
		// Only withdraw routes injected by this connector (prevents cross-connector deletion)
		if logEntry.ConnectorID != nil && *logEntry.ConnectorID != conn.ID {
			continue
		}
		// Per-artifact manual_override suppression: skip if this specific artifact was force-removed
		overridden := false
		for _, l2 := range logs {
			if l2.TriggerPhase == "manual_override" && l2.Status == "success" && l2.ExternalRuleID == logEntry.ExternalRuleID {
				c2 := 0
				if l2.ConnectorID != nil {
					c2 = *l2.ConnectorID
				}
				if c2 == conn.ID {
					overridden = true
					break
				}
			}
		}
		if overridden {
			skippedOverride++
			log.Printf("action: bgp withdraw skipping %s (manual override, attack=%d)", logEntry.ExternalRuleID, attackDBID)
			continue
		}
		// external_rule_id format: "{prefix}:{route_map}"
		parts := splitExternalRuleID(logEntry.ExternalRuleID)
		if len(parts) != 2 {
			continue
		}
		prefix, routeMap := parts[0], parts[1]

		waf := addressFamilyForPrefix(prefix)
		cmd := fmt.Sprintf("configure terminal\nrouter bgp %d\naddress-family %s\nno network %s route-map %s",
			conn.BGPASN, waf, prefix, routeMap)

		out, err := runVtysh(ctx, conn.VtyshPath, cmd)
		cid := conn.ID
		if err != nil {
			outStr := strings.TrimSpace(out)
			if strings.Contains(outStr, "Can't find") || strings.Contains(outStr, "No such") || strings.Contains(outStr, "does not exist") {
				// Route already gone — treat as idempotent success
				withdrawn = append(withdrawn, logEntry.ExternalRuleID)
				log.Printf("action: bgp withdraw %s already gone (idempotent success, attack=%d)", logEntry.ExternalRuleID, attackDBID)
				routeLog := &store.ActionExecutionLog{
					AttackID:       attackDBID,
					ActionID:       act.ID,
					ActionType:     "bgp",
					ConnectorName:  conn.Name,
					ConnectorID:    &cid,
					TriggerPhase:   triggerPhase,
					ExternalRuleID: logEntry.ExternalRuleID,
					Status:         "success",
					ErrorMessage:   "idempotent: route already withdrawn",
					ExecutedAt:     time.Now(),
				}
				if _, err2 := s.ActionExecLog().Create(ctx, routeLog); err2 != nil {
					log.Printf("action: create per-route withdraw log: %v", err2)
				}
			} else {
				// Real failure — write per-route failed log with full business key
				errors = append(errors, fmt.Sprintf("%s: %v (%s)", logEntry.ExternalRuleID, err, out))
				failLog := &store.ActionExecutionLog{
					AttackID:       attackDBID,
					ActionID:       act.ID,
					ActionType:     "bgp",
					ConnectorName:  conn.Name,
					ConnectorID:    &cid,
					TriggerPhase:   triggerPhase,
					ExternalRuleID: logEntry.ExternalRuleID,
					Status:         "failed",
					ErrorMessage:   fmt.Sprintf("%v (%s)", err, outStr),
					ExecutedAt:     time.Now(),
				}
				if _, err2 := s.ActionExecLog().Create(ctx, failLog); err2 != nil {
					log.Printf("action: create per-route failed log: %v", err2)
				}
			}
		} else {
			withdrawn = append(withdrawn, logEntry.ExternalRuleID)
			log.Printf("action: bgp withdraw %s route-map=%s connector=%s", prefix, routeMap, conn.Name)
			routeLog := &store.ActionExecutionLog{
				AttackID:       attackDBID,
				ActionID:       act.ID,
				ActionType:     "bgp",
				ConnectorName:  conn.Name,
				ConnectorID:    &cid,
				TriggerPhase:   triggerPhase,
				ExternalRuleID: logEntry.ExternalRuleID,
				Status:         "success",
				ExecutedAt:     time.Now(),
			}
			if _, err := s.ActionExecLog().Create(ctx, routeLog); err != nil {
				log.Printf("action: create per-route withdraw log: %v", err)
			}
		}
	}

	status := "success"
	errMsg := ""
	if len(errors) > 0 {
		if len(withdrawn) == 0 {
			status = "failed"
		} else {
			status = "partial"
		}
		errMsg = strings.Join(errors, "; ")
	}

	// Per-route success logs are already written above.
	// This summary log is for the overall connector-level result only.
	connID := conn.ID
	return &store.ActionExecutionLog{
		AttackID:      attackDBID,
		ActionID:      act.ID,
		ActionType:    "bgp",
		TriggerPhase:  triggerPhase,
		ResponseName:  responseName,
		ConnectorName: conn.Name,
		ConnectorID:   &connID,
		Status:        status,
		ErrorMessage:  errMsg,
		ResponseBody:  fmt.Sprintf("withdrawn: %v", withdrawn),
		ExecutedAt:    time.Now(),
	}, nil
}

// RecoverBGPRoutes reconciles FRR state on Controller startup:
// 1. Find all BGP routes xSight previously injected (from action_execution_log)
// 2. Clean up stale routes (attack no longer active)
// 3. Re-inject routes for still-active attacks (FRR ephemeral state lost on restart)
func RecoverBGPRoutes(ctx context.Context, s store.Store) {
	connectors, err := s.BGPConnectors().List(ctx)
	if err != nil || len(connectors) == 0 {
		return
	}

	// Build set of active attack IDs
	activeAttacks, err := s.Attacks().ListActive(ctx, 10000)
	if err != nil {
		log.Printf("bgp recovery: list active attacks: %v", err)
		return
	}
	activeIDs := make(map[int]bool, len(activeAttacks))
	for _, a := range activeAttacks {
		activeIDs[a.ID] = true
	}

	// Scan all BGP injection records
	connByID := make(map[int]*store.BGPConnector, len(connectors))
	for i := range connectors {
		connByID[connectors[i].ID] = &connectors[i]
	}

	reinjected, cleaned := 0, 0
	activeRuleIDs := make(map[string]bool) // track rule IDs re-injected for active attacks
	for _, attack := range activeAttacks {
		logs, err := s.ActionExecLog().ListByAttack(ctx, attack.ID)
		if err != nil {
			continue
		}
		for _, logEntry := range logs {
			if logEntry.ActionType != "bgp" || logEntry.Status != "success" || logEntry.TriggerPhase != "on_detected" || logEntry.ExternalRuleID == "" {
				continue
			}
			conn := resolveConnector(logEntry, connByID, connectors)
			if conn == nil || !conn.Enabled {
				continue
			}
			parts := splitExternalRuleID(logEntry.ExternalRuleID)
			if len(parts) != 2 {
				continue
			}
			prefix, routeMap := parts[0], parts[1]

			// Re-inject for active attacks
			raf := addressFamilyForPrefix(prefix)
			cmd := fmt.Sprintf("configure terminal\nrouter bgp %d\naddress-family %s\nnetwork %s route-map %s",
				conn.BGPASN, raf, prefix, routeMap)
			if _, err := runVtysh(ctx, conn.VtyshPath, cmd); err != nil {
				log.Printf("bgp recovery: re-inject %s route-map=%s failed: %v", prefix, routeMap, err)
			} else {
				reinjected++
				activeRuleIDs[logEntry.ExternalRuleID] = true
			}
		}
	}

	// Clean up stale routes: find BGP logs for NON-active attacks and withdraw
	// Query recent attacks that have ended but may have leftover BGP routes
	allLogs, err := s.Attacks().List(ctx, store.AttackFilter{Limit: 500, Status: "expired"})
	if err == nil {
		for _, attack := range allLogs {
			if activeIDs[attack.ID] {
				continue // still active, already handled above
			}
			logs, err := s.ActionExecLog().ListByAttack(ctx, attack.ID)
			if err != nil {
				continue
			}
			for _, logEntry := range logs {
				if logEntry.ActionType != "bgp" || logEntry.Status != "success" || logEntry.TriggerPhase != "on_detected" || logEntry.ExternalRuleID == "" {
					continue
				}
				// Skip if this rule was just re-injected for an active attack
				if activeRuleIDs[logEntry.ExternalRuleID] {
					continue
				}
				// Check if there's already a successful withdraw for this rule
				hasWithdraw := false
				for _, l2 := range logs {
					if l2.ActionType == "bgp" && l2.TriggerPhase == "on_expired" && l2.Status == "success" {
						hasWithdraw = true
						break
					}
				}
				if hasWithdraw {
					continue
				}
				conn := resolveConnector(logEntry, connByID, connectors)
				if conn == nil || !conn.Enabled {
					continue
				}
				parts := splitExternalRuleID(logEntry.ExternalRuleID)
				if len(parts) != 2 {
					continue
				}
				prefix, routeMap := parts[0], parts[1]
				caf := addressFamilyForPrefix(prefix)
				cmd := fmt.Sprintf("configure terminal\nrouter bgp %d\naddress-family %s\nno network %s route-map %s",
					conn.BGPASN, caf, prefix, routeMap)
				if _, err := runVtysh(ctx, conn.VtyshPath, cmd); err != nil {
					// Ignore errors — route may already have been withdrawn normally
					log.Printf("bgp recovery: cleanup stale %s route-map=%s (may already be gone): %v", prefix, routeMap, err)
				}
				cleaned++
			}
		}
	}

	if reinjected > 0 || cleaned > 0 {
		log.Printf("bgp recovery: re-injected %d routes, cleaned %d stale routes", reinjected, cleaned)
	}
}

func resolveConnector(logEntry store.ActionExecutionLog, byID map[int]*store.BGPConnector, all []store.BGPConnector) *store.BGPConnector {
	if logEntry.ConnectorID != nil {
		if c, ok := byID[*logEntry.ConnectorID]; ok {
			return c
		}
	}
	if len(all) == 1 {
		return &all[0]
	}
	return nil
}

// runVtysh executes vtysh with the given commands (newline-separated).
func runVtysh(ctx context.Context, vtyshPath, commands string) (string, error) {
	args := []string{}
	for _, line := range strings.Split(commands, "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			args = append(args, "-c", line)
		}
	}
	out, err := exec.CommandContext(ctx, vtyshPath, args...).CombinedOutput()
	return strings.TrimSpace(string(out)), err
}
