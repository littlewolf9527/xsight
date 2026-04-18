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

// isFRRRouteAbsentError returns true if vtysh stderr indicates "there's
// nothing here to remove" — a withdraw against a route that's already gone.
// xSight treats this as idempotent success.
//
// We intentionally match ONLY specific, verified phrases observed in the wild
// for this exact case. Broader patterns like "No such" or "does not exist"
// would also catch legitimate FRR config errors (e.g., `No such route-map
// entry` from a typo in route-map name, or `address-family ... does not
// exist`) and mask them as success — leaving announcements falsely marked
// withdrawn while FRR still holds the route. Per PR-7 audit P1.
//
// Known idempotent phrases:
//   - "Can't find static route"
//       Classic: `no network X route-map Y` when that exact network never
//       existed.
//   - "route-map name doesn't match static route"
//       Surfaces when `network X route-map Y` was rejected during origination
//       (e.g., two different route-maps for the same prefix — BGP keeps only
//       one) and xSight later tries to withdraw the rejected one. See L14.
//
// If other genuinely-idempotent FRR phrasings are observed, add them here
// with a concrete case; do not re-broaden to generic "not found" wording.
func isFRRRouteAbsentError(output string) bool {
	if output == "" {
		return false
	}
	for _, pat := range []string{
		"Can't find static route",
		"route-map name doesn't match static route",
	} {
		if strings.Contains(output, pat) {
			return true
		}
	}
	return false
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
// on_detected: Attach to announcement; run vtysh network if refcount→1
// on_expired:  Detach from announcement; run vtysh no network if refcount→0 and delay=0
//
// The `engine` parameter is required for the delayed-withdraw path (PR-5
// arms timers via engine.ScheduleDelay with announcement_id). Can be nil
// when called from recovery/tests that drive timers externally.
func executeBGP(ctx context.Context, s store.Store, engine *Engine, act store.ResponseAction,
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
		return bgpAnnounce(ctx, s, engine, conn, act, dstIP, attackDBID, responseName, triggerPhase)
	case "on_expired":
		return bgpWithdraw(ctx, s, engine, conn, act, dstIP, attackDBID, responseName, triggerPhase)
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

// bgpAnnounce attaches this attack to an announcement (creating one if
// necessary) and invokes vtysh network only when the refcount-based manager
// tells us this is a new announcement.
//
// v1.2 PR-5: replaces per-attack vtysh announce. Multiple attacks sharing
// the same (prefix, route_map, connector) will all attach to a single
// announcement — only the first attack triggers vtysh, subsequent attaches
// just bump the refcount.
//
// `engine` is used to cancel any in-memory delay timer if this attach
// resurrected a delayed announcement. Can be nil in tests / recovery paths
// that don't care about the timer.
func bgpAnnounce(ctx context.Context, s store.Store, engine *Engine, conn *store.BGPConnector, act store.ResponseAction,
	dstIP string, attackDBID int, responseName, triggerPhase string) (*store.ActionExecutionLog, error) {

	routeMap := act.BGPRouteMap
	externalRuleID := fmt.Sprintf("%s|%s", dstIP, routeMap)
	actID := act.ID
	connID := conn.ID

	// Look up the attack's per-action bgp_withdraw_delay — this attack's
	// contribution to the announcement's effective delay. The announcement's
	// final delay is MAX across all attached attacks.
	delayMinutes := act.BGPWithdrawDelayMinutes

	attachResult, err := s.BGPAnnouncements().Attach(ctx, store.BGPAttachParams{
		AttackID:     attackDBID,
		ActionID:     &actID,
		ResponseName: responseName,
		DelayMinutes: delayMinutes,
		Prefix:       dstIP,
		RouteMap:     routeMap,
		ConnectorID:  connID,
	})
	if err != nil {
		log.Printf("action: bgp attach failed attack=%d prefix=%s: %v", attackDBID, dstIP, err)
		return &store.ActionExecutionLog{
			AttackID:       attackDBID,
			ActionID:       act.ID,
			ActionType:     "bgp",
			TriggerPhase:   triggerPhase,
			ResponseName:   responseName,
			ConnectorName:  conn.Name,
			ConnectorID:    &connID,
			Status:         "failed",
			ErrorMessage:   fmt.Sprintf("attach: %v", err),
			ExternalRuleID: externalRuleID,
			ExecutedAt:     time.Now(),
		}, err
	}

	if !attachResult.NeedAnnounce {
		// Shared attach (refcount++ on existing active announcement) OR
		// delay-cancelling attach (refcount 0→1 resurrecting a delayed
		// announcement). In either case, no vtysh needed. If the announcement
		// was in delayed state, the Attach already transitioned status back
		// to active in DB — but we ALSO need to cancel the in-memory timer
		// goroutine so it doesn't fire withdrawal. Idempotent: if no timer is
		// armed the map lookup is a miss and CancelAnnouncementDelay no-ops.
		if engine != nil {
			engine.CancelAnnouncementDelay(attachResult.AnnouncementID, "rebreach: attack attached during delay")
		}
		log.Printf("action: bgp attach shared prefix=%s announcement_id=%d attack=%d",
			dstIP, attachResult.AnnouncementID, attackDBID)
		detail := fmt.Sprintf("attached to announcement_id=%d (shared)", attachResult.AnnouncementID)
		return &store.ActionExecutionLog{
			AttackID:       attackDBID,
			ActionID:       act.ID,
			ActionType:     "bgp",
			TriggerPhase:   triggerPhase,
			ResponseName:   responseName,
			ConnectorName:  conn.Name,
			ConnectorID:    &connID,
			Status:         "success",
			Detail:         detail,
			ExternalRuleID: externalRuleID,
			ExecutedAt:     time.Now(),
		}, nil
	}

	// First attach — execute vtysh network.
	af := addressFamilyForPrefix(dstIP)
	cmd := fmt.Sprintf("configure terminal\nrouter bgp %d\naddress-family %s\nnetwork %s route-map %s",
		conn.BGPASN, af, dstIP, routeMap)

	t0 := time.Now()
	out, vErr := runVtysh(ctx, conn.VtyshPath, cmd)
	durationMs := int(time.Since(t0).Milliseconds())

	if vErr != nil {
		log.Printf("action: bgp announce failed announcement_id=%d: %v output=%s",
			attachResult.AnnouncementID, vErr, out)
		// Compensate: delete row if refcount=1, else mark failed.
		if cErr := s.BGPAnnouncements().MarkFailedAnnounce(ctx, attachResult.AnnouncementID, vErr.Error()); cErr != nil {
			log.Printf("action: bgp compensate announce failure announcement_id=%d: %v",
				attachResult.AnnouncementID, cErr)
		}
		return &store.ActionExecutionLog{
			AttackID:       attackDBID,
			ActionID:       act.ID,
			ActionType:     "bgp",
			TriggerPhase:   triggerPhase,
			ResponseName:   responseName,
			ConnectorName:  conn.Name,
			ConnectorID:    &connID,
			Status:         "failed",
			ErrorMessage:   fmt.Sprintf("vtysh: %v", vErr),
			RequestBody:    cmd,
			ResponseBody:   out,
			ExternalRuleID: externalRuleID,
			DurationMs:     durationMs,
			ExecutedAt:     t0,
		}, vErr
	}

	if mErr := s.BGPAnnouncements().MarkAnnounced(ctx, attachResult.AnnouncementID); mErr != nil {
		log.Printf("action: bgp MarkAnnounced announcement_id=%d: %v", attachResult.AnnouncementID, mErr)
	}
	log.Printf("action: bgp announce %s route-map=%s connector=%s announcement_id=%d",
		dstIP, routeMap, conn.Name, attachResult.AnnouncementID)
	detail := fmt.Sprintf("triggered announcement_id=%d", attachResult.AnnouncementID)
	return &store.ActionExecutionLog{
		AttackID:       attackDBID,
		ActionID:       act.ID,
		ActionType:     "bgp",
		TriggerPhase:   triggerPhase,
		ResponseName:   responseName,
		ConnectorName:  conn.Name,
		ConnectorID:    &connID,
		Status:         "success",
		Detail:         detail,
		RequestBody:    cmd,
		ResponseBody:   out,
		ExternalRuleID: externalRuleID,
		DurationMs:     durationMs,
		ExecutedAt:     t0,
	}, nil
}

// bgpWithdraw detaches this attack from the announcement. Depending on
// refcount/delay the manager tells us whether to run vtysh immediately,
// arm a delay timer, or do nothing (shared detach).
//
// v1.2 PR-5: replaces per-attack vtysh withdraw. When multiple attacks
// share an announcement, only the LAST detach triggers vtysh. Eliminates
// the withdraw race that plagued v1.1.x.
//
// `engine` must be non-nil when the delayed-withdraw path can trigger (i.e.
// when any attached attack carries a non-zero bgp_withdraw_delay). Recovery
// paths that already hold the timer state can pass nil.
func bgpWithdraw(ctx context.Context, s store.Store, engine *Engine, conn *store.BGPConnector, act store.ResponseAction,
	dstIP string, attackDBID int, responseName, triggerPhase string) (*store.ActionExecutionLog, error) {

	routeMap := act.BGPRouteMap
	externalRuleID := fmt.Sprintf("%s|%s", dstIP, routeMap)
	connID := conn.ID
	actID := act.ID

	// Per-artifact manual_override: if operator already force-removed this
	// attack's artifact, emit a skip log and return. Detach is idempotent
	// anyway, but an explicit skip log keeps the audit trail clean.
	if overridden, _ := s.ManualOverrides().Exists(ctx, attackDBID, actID, connID, externalRuleID); overridden {
		log.Printf("action: bgp withdraw skipping %s (manual override, attack=%d)", externalRuleID, attackDBID)
		return &store.ActionExecutionLog{
			AttackID:       attackDBID,
			ActionID:       act.ID,
			ActionType:     "bgp",
			TriggerPhase:   triggerPhase,
			ResponseName:   responseName,
			ConnectorName:  conn.Name,
			ConnectorID:    &connID,
			Status:         "skipped",
			SkipReason:     SkipReasonManualOverride,
			ErrorMessage:   "force-removed by operator",
			ExternalRuleID: externalRuleID,
			ExecutedAt:     time.Now(),
		}, nil
	}

	result, err := s.BGPAnnouncements().Detach(ctx, attackDBID, dstIP, routeMap, connID)
	if err != nil {
		return &store.ActionExecutionLog{
			AttackID:       attackDBID,
			ActionID:       act.ID,
			ActionType:     "bgp",
			TriggerPhase:   triggerPhase,
			ResponseName:   responseName,
			ConnectorName:  conn.Name,
			ConnectorID:    &connID,
			Status:         "failed",
			ErrorMessage:   fmt.Sprintf("detach: %v", err),
			ExternalRuleID: externalRuleID,
			ExecutedAt:     time.Now(),
		}, err
	}

	if result.AnnouncementID == 0 {
		// No announcement found — attack never attached. Idempotent success.
		log.Printf("action: bgp detach no-op (no announcement) attack=%d prefix=%s", attackDBID, dstIP)
		return &store.ActionExecutionLog{
			AttackID:       attackDBID,
			ActionID:       act.ID,
			ActionType:     "bgp",
			TriggerPhase:   triggerPhase,
			ResponseName:   responseName,
			ConnectorName:  conn.Name,
			ConnectorID:    &connID,
			Status:         "success",
			Detail:         "no announcement to detach (idempotent)",
			ExternalRuleID: externalRuleID,
			ExecutedAt:     time.Now(),
		}, nil
	}

	// Shared detach: refcount > 0 after decrement, nothing to do.
	if !result.NeedWithdraw && !result.Delayed {
		log.Printf("action: bgp detach shared announcement_id=%d refcount=%d attack=%d",
			result.AnnouncementID, result.RefcountAfter, attackDBID)
		detail := fmt.Sprintf("detached from announcement_id=%d (refcount=%d, kept active)",
			result.AnnouncementID, result.RefcountAfter)
		return &store.ActionExecutionLog{
			AttackID:       attackDBID,
			ActionID:       act.ID,
			ActionType:     "bgp",
			TriggerPhase:   triggerPhase,
			ResponseName:   responseName,
			ConnectorName:  conn.Name,
			ConnectorID:    &connID,
			Status:         "success",
			Detail:         detail,
			ExternalRuleID: externalRuleID,
			ExecutedAt:     time.Now(),
		}, nil
	}

	// Delayed path: the announcement is already in 'delayed' status.
	// Arm a persistent delay timer keyed on announcement_id. When the timer
	// fires (or is cancelled by re-breach), perform or skip the withdraw.
	if result.Delayed {
		delay := time.Duration(result.DelayMinutes) * time.Minute
		scheduledFor := time.Now().Add(delay)
		annID := result.AnnouncementID

		if engine == nil {
			// No engine reference — recovery path manages its own timer.
			// Just return the scheduled log.
			detail := fmt.Sprintf("delayed withdraw in %dm (announcement_id=%d, timer externally managed)",
				result.DelayMinutes, annID)
			return &store.ActionExecutionLog{
				AttackID: attackDBID, ActionID: act.ID, ActionType: "bgp",
				TriggerPhase: triggerPhase, ResponseName: responseName,
				ConnectorName: conn.Name, ConnectorID: &connID,
				Status:         "scheduled",
				Detail:         detail,
				ScheduledFor:   &scheduledFor,
				ExternalRuleID: externalRuleID,
				ExecutedAt:     time.Now(),
			}, nil
		}

		schedID, cancelCtx, perr := engine.ScheduleDelayForAnnouncement(ctx, annID, scheduledFor)
		if perr != nil {
			log.Printf("action: bgp ScheduleDelay persist failed announcement_id=%d: %v", annID, perr)
			// Compensate: mark announcement failed so it doesn't linger in delayed forever.
			_ = s.BGPAnnouncements().MarkFailedWithdraw(ctx, annID, fmt.Sprintf("schedule persist failed: %v", perr))
			return &store.ActionExecutionLog{
				AttackID: attackDBID, ActionID: act.ID, ActionType: "bgp",
				TriggerPhase: triggerPhase, ResponseName: responseName,
				ConnectorName: conn.Name, ConnectorID: &connID,
				Status:         "failed",
				ErrorMessage:   fmt.Sprintf("schedule persist failed: %v", perr),
				ExternalRuleID: externalRuleID,
				ExecutedAt:     time.Now(),
			}, perr
		}

		// Goroutine waits for timer or cancellation.
		go bgpDelayedWithdrawWorker(s, engine, conn, act, dstIP, routeMap, attackDBID,
			annID, schedID, cancelCtx, delay, responseName)

		detail := fmt.Sprintf("delayed withdraw in %dm (announcement_id=%d, scheduled_id=%d)",
			result.DelayMinutes, annID, schedID)
		return &store.ActionExecutionLog{
			AttackID: attackDBID, ActionID: act.ID, ActionType: "bgp",
			TriggerPhase: triggerPhase, ResponseName: responseName,
			ConnectorName: conn.Name, ConnectorID: &connID,
			Status:         "scheduled",
			Detail:         detail,
			ErrorMessage:   fmt.Sprintf("delayed withdraw in %dm", result.DelayMinutes),
			ScheduledFor:   &scheduledFor,
			ExternalRuleID: externalRuleID,
			ExecutedAt:     time.Now(),
		}, nil
	}

	// Immediate withdraw: refcount=0, delay=0. Detach already transitioned
	// the announcement to 'withdrawing'. Run vtysh now and finalize.
	return performBGPWithdraw(ctx, s, conn, act, dstIP, routeMap, attackDBID, result.AnnouncementID, responseName, triggerPhase)
}

// bgpDelayedWithdrawWorker is the goroutine body that waits for the delay
// timer, then executes the actual BGP withdraw — or bails cleanly if the
// announcement was cancelled (re-breach, force-remove, or explicit cancel).
//
// v1.2 PR-5: all lifecycle bookkeeping (MarkExecuting, MarkWithdrawing,
// MarkWithdrawn, MarkFailedWithdraw, CompleteDelay, FailDelay) flows through
// the Engine so recovery can pick up from any interruption.
func bgpDelayedWithdrawWorker(s store.Store, engine *Engine, conn *store.BGPConnector,
	act store.ResponseAction, dstIP, routeMap string, attackDBID, announcementID, schedID int,
	cancelCtx context.Context, delay time.Duration, responseName string) {

	log.Printf("action: bgp delayed withdraw scheduled in %v announcement_id=%d scheduled_id=%d",
		delay, announcementID, schedID)

	select {
	case <-time.After(delay):
		// Race guard — only one goroutine may execute this task.
		execCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if !engine.MarkExecutingDelay(execCtx, schedID) {
			log.Printf("action: bgp delayed withdraw skipped scheduled_id=%d (no longer pending)", schedID)
			return
		}

		// Transition announcement active/delayed → withdrawing before vtysh.
		// Returns false if concurrent attach cancelled (refcount now > 0).
		ok, mErr := s.BGPAnnouncements().MarkWithdrawing(execCtx, announcementID)
		if mErr != nil {
			log.Printf("action: bgp delayed MarkWithdrawing announcement_id=%d: %v", announcementID, mErr)
			engine.FailDelayForAnnouncement(execCtx, schedID, announcementID, mErr.Error())
			return
		}
		if !ok {
			// Announcement is no longer in active/delayed — likely re-breached
			// and back to active with refcount > 0. Don't withdraw.
			log.Printf("action: bgp delayed withdraw bailing announcement_id=%d (no longer in delayed/active — likely re-breached)", announcementID)
			engine.CompleteDelayForAnnouncement(execCtx, schedID, announcementID)
			return
		}

		// Run the actual vtysh withdraw and finalize.
		execLog, wErr := performBGPWithdraw(execCtx, s, conn, act, dstIP, routeMap, attackDBID, announcementID, responseName, "on_expired")
		if wErr != nil {
			engine.FailDelayForAnnouncement(execCtx, schedID, announcementID, wErr.Error())
		} else {
			engine.CompleteDelayForAnnouncement(execCtx, schedID, announcementID)
		}
		if execLog != nil {
			if _, err := s.ActionExecLog().Create(execCtx, execLog); err != nil {
				log.Printf("action: create delayed bgp withdraw log: %v", err)
			}
		}

	case <-cancelCtx.Done():
		log.Printf("action: bgp delayed withdraw cancelled announcement_id=%d scheduled_id=%d", announcementID, schedID)
		// Cancel context was triggered (re-breach / operator cancel) — the
		// scheduled_actions row was already transitioned to cancelled by the
		// caller (CancelAnnouncementDelay). Just clean up the in-memory map.
		engine.delayMu.Lock()
		delete(engine.pendingDelay, announcementDelayKey(announcementID))
		engine.delayMu.Unlock()
	}
}

// PerformBGPWithdrawForOrphan is the exported wrapper over performBGPWithdraw
// used by the API layer's orphanForceWithdraw handler. Writes a
// manual_override audit log (not a normal on_expired) since there's no
// attack attached.
func PerformBGPWithdrawForOrphan(ctx context.Context, s store.Store, conn *store.BGPConnector,
	act store.ResponseAction, dstIP, routeMap string, announcementID int) (*store.ActionExecutionLog, error) {
	return performBGPWithdraw(ctx, s, conn, act, dstIP, routeMap,
		0 /* no attack */, announcementID, "" /* no response name */, "manual_override")
}

// performBGPWithdraw runs the actual vtysh no network command for a
// withdrawing-state announcement and transitions to withdrawn/failed.
// Called from bgpWithdraw's immediate branch and from the delayed goroutine.
func performBGPWithdraw(ctx context.Context, s store.Store, conn *store.BGPConnector,
	act store.ResponseAction, dstIP, routeMap string, attackDBID, announcementID int,
	responseName, triggerPhase string) (*store.ActionExecutionLog, error) {

	externalRuleID := fmt.Sprintf("%s|%s", dstIP, routeMap)
	connID := conn.ID

	waf := addressFamilyForPrefix(dstIP)
	cmd := fmt.Sprintf("configure terminal\nrouter bgp %d\naddress-family %s\nno network %s route-map %s",
		conn.BGPASN, waf, dstIP, routeMap)

	t0 := time.Now()
	out, vErr := runVtysh(ctx, conn.VtyshPath, cmd)
	durationMs := int(time.Since(t0).Milliseconds())

	if vErr != nil {
		outStr := strings.TrimSpace(out)
		if isFRRRouteAbsentError(outStr) {
			// Idempotent success — route already gone.
			log.Printf("action: bgp withdraw %s already gone (idempotent, announcement_id=%d)", externalRuleID, announcementID)
			if mErr := s.BGPAnnouncements().MarkWithdrawn(ctx, announcementID); mErr != nil {
				log.Printf("action: bgp MarkWithdrawn announcement_id=%d: %v", announcementID, mErr)
			}
			return &store.ActionExecutionLog{
				AttackID:       attackDBID,
				ActionID:       act.ID,
				ActionType:     "bgp",
				TriggerPhase:   triggerPhase,
				ResponseName:   responseName,
				ConnectorName:  conn.Name,
				ConnectorID:    &connID,
				Status:         "success",
				ErrorMessage:   "idempotent: route already withdrawn",
				Detail:         fmt.Sprintf("announcement_id=%d withdrawn", announcementID),
				RequestBody:    cmd,
				ResponseBody:   out,
				ExternalRuleID: externalRuleID,
				DurationMs:     durationMs,
				ExecutedAt:     t0,
			}, nil
		}
		// Real failure.
		if mErr := s.BGPAnnouncements().MarkFailedWithdraw(ctx, announcementID, vErr.Error()); mErr != nil {
			log.Printf("action: bgp MarkFailedWithdraw announcement_id=%d: %v", announcementID, mErr)
		}
		return &store.ActionExecutionLog{
			AttackID:       attackDBID,
			ActionID:       act.ID,
			ActionType:     "bgp",
			TriggerPhase:   triggerPhase,
			ResponseName:   responseName,
			ConnectorName:  conn.Name,
			ConnectorID:    &connID,
			Status:         "failed",
			ErrorMessage:   fmt.Sprintf("%v (%s)", vErr, outStr),
			RequestBody:    cmd,
			ResponseBody:   out,
			ExternalRuleID: externalRuleID,
			DurationMs:     durationMs,
			ExecutedAt:     t0,
		}, vErr
	}

	// Success.
	log.Printf("action: bgp withdraw %s route-map=%s connector=%s announcement_id=%d", dstIP, routeMap, conn.Name, announcementID)
	if mErr := s.BGPAnnouncements().MarkWithdrawn(ctx, announcementID); mErr != nil {
		log.Printf("action: bgp MarkWithdrawn announcement_id=%d: %v", announcementID, mErr)
	}
	return &store.ActionExecutionLog{
		AttackID:       attackDBID,
		ActionID:       act.ID,
		ActionType:     "bgp",
		TriggerPhase:   triggerPhase,
		ResponseName:   responseName,
		ConnectorName:  conn.Name,
		ConnectorID:    &connID,
		Status:         "success",
		Detail:         fmt.Sprintf("announcement_id=%d withdrawn", announcementID),
		RequestBody:    cmd,
		ResponseBody:   out,
		ExternalRuleID: externalRuleID,
		DurationMs:     durationMs,
		ExecutedAt:     t0,
	}, nil
}

// bgpWithdrawLegacyUNUSED is the pre-PR-5 log-iteration withdraw that scanned
// action_execution_log for prior BGP successes. Kept temporarily as a
// reference during migration — will be removed once v1.2 is fully deployed.
//
// Deprecated: use bgpWithdraw (announcement-based) instead.
func bgpWithdrawLegacyUNUSED(ctx context.Context, s store.Store, conn *store.BGPConnector, act store.ResponseAction,
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

	// v1.2 PR-2: pre-fetch manual overrides for this attack once, build a
	// local set, then do O(1) membership checks per artifact. Replaces the
	// v1.1 O(N²) inner scan of `logs`.
	//
	// Key must include action_id — override is scoped to a specific
	// ResponseAction (matches the UNIQUE (attack_id, action_id, connector_id,
	// external_rule_id) constraint). Two different actions on the same attack
	// may share connector+rule, but operator force-removing one must NOT
	// suppress the other.
	overrides, err := s.ManualOverrides().ListByAttack(ctx, attackDBID)
	if err != nil {
		log.Printf("action: bgp withdraw override lookup failed (attack=%d): %v — proceeding without override filter", attackDBID, err)
	}
	overrideSet := make(map[string]struct{}, len(overrides))
	for _, o := range overrides {
		overrideSet[fmt.Sprintf("%d:%d:%s", o.ActionID, o.ConnectorID, o.ExternalRuleID)] = struct{}{}
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
		// Per-artifact manual_override suppression: O(1) via pre-fetched set.
		// Key must match the UNIQUE business key — action-scoped, not just connector+rule.
		if _, ok := overrideSet[fmt.Sprintf("%d:%d:%s", logEntry.ActionID, conn.ID, logEntry.ExternalRuleID)]; ok {
			skippedOverride++
			log.Printf("action: bgp withdraw skipping %s (manual override, attack=%d action=%d)", logEntry.ExternalRuleID, attackDBID, logEntry.ActionID)
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
			if isFRRRouteAbsentError(outStr) {
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
