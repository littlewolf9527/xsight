package action

import (
	"context"
	"fmt"
	"log"
	"os/exec"
	"strings"
	"time"

	"github.com/littlewolf9527/xsight/controller/internal/store"
)

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
		if strings.Contains(dstIP, ":") {
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
	cmd := fmt.Sprintf("configure terminal\nrouter bgp %d\naddress-family %s\nnetwork %s route-map %s",
		conn.BGPASN, conn.AddressFamily, dstIP, routeMap)

	t0 := time.Now()
	out, err := runVtysh(ctx, conn.VtyshPath, cmd)
	durationMs := int(time.Since(t0).Milliseconds())

	externalRuleID := fmt.Sprintf("%s:%s", dstIP, routeMap)

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
		parts := strings.SplitN(logEntry.ExternalRuleID, ":", 2)
		if len(parts) != 2 {
			continue
		}
		prefix, routeMap := parts[0], parts[1]

		cmd := fmt.Sprintf("configure terminal\nrouter bgp %d\naddress-family %s\nno network %s route-map %s",
			conn.BGPASN, conn.AddressFamily, prefix, routeMap)

		out, err := runVtysh(ctx, conn.VtyshPath, cmd)
		if err != nil {
			errors = append(errors, fmt.Sprintf("%s: %v (%s)", logEntry.ExternalRuleID, err, out))
		} else {
			withdrawn = append(withdrawn, logEntry.ExternalRuleID)
			log.Printf("action: bgp withdraw %s route-map=%s connector=%s", prefix, routeMap, conn.Name)
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

	// Build external_rule_id for the result log — use the first withdrawn/attempted route
	// so that buildActiveActions can match on_expired with on_detected.
	resultRuleID := ""
	if len(withdrawn) > 0 {
		resultRuleID = withdrawn[0]
	} else if len(errors) > 0 {
		// Parse from error string: "10.0.0.1/32:RTBH: exit status 1 (...)"
		parts := strings.SplitN(errors[0], ":", 3)
		if len(parts) >= 2 {
			resultRuleID = parts[0] + ":" + parts[1]
		}
	}

	connID := conn.ID
	return &store.ActionExecutionLog{
		AttackID:       attackDBID,
		ActionID:       act.ID,
		ActionType:     "bgp",
		TriggerPhase:   triggerPhase,
		ResponseName:   responseName,
		ConnectorName:  conn.Name,
		ConnectorID:    &connID,
		ExternalRuleID: resultRuleID,
		Status:         status,
		ErrorMessage:   errMsg,
		ResponseBody:   fmt.Sprintf("withdrawn: %v", withdrawn),
		ExecutedAt:     time.Now(),
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
			parts := strings.SplitN(logEntry.ExternalRuleID, ":", 2)
			if len(parts) != 2 {
				continue
			}
			prefix, routeMap := parts[0], parts[1]

			// Re-inject for active attacks
			cmd := fmt.Sprintf("configure terminal\nrouter bgp %d\naddress-family %s\nnetwork %s route-map %s",
				conn.BGPASN, conn.AddressFamily, prefix, routeMap)
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
				parts := strings.SplitN(logEntry.ExternalRuleID, ":", 2)
				if len(parts) != 2 {
					continue
				}
				prefix, routeMap := parts[0], parts[1]
				cmd := fmt.Sprintf("configure terminal\nrouter bgp %d\naddress-family %s\nno network %s route-map %s",
					conn.BGPASN, conn.AddressFamily, prefix, routeMap)
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
