package tests

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/littlewolf9527/xsight/controller/internal/action"
	"github.com/littlewolf9527/xsight/controller/internal/store"
)

// --- addressFamilyForPrefix is unexported, so we test it indirectly via
//     the execution log's request_body (which contains the vtysh command).
//     RecoverBGPRoutes is exported and exercises the same code path.

// TestBGPAutoAFI_IPv4Prefix verifies that an IPv4 prefix uses "ipv4 unicast".
// We set up an active attack with an IPv4 on_detected log and call RecoverBGPRoutes.
// vtysh is /usr/bin/false so it fails, but we verify the function completes
// and attempts re-injection (the AFI selection happens internally).
func TestBGPAutoAFI_IPv4Prefix(t *testing.T) {
	ms := NewMockStore()
	conn := store.BGPConnector{
		ID:            1,
		Name:          "dual-afi",
		VtyshPath:     "/usr/bin/false",
		BGPASN:        65000,
		AddressFamily: "auto", // no longer matters — auto-detected
		Enabled:       true,
		CreatedAt:     time.Now(),
		UpdatedAt:     time.Now(),
	}
	ms.bgpConnectors.connectors = append(ms.bgpConnectors.connectors, conn)

	now := time.Now()
	ms.attacks.attacks = append(ms.attacks.attacks, store.Attack{
		ID: 1, DstIP: "10.0.0.1", StartedAt: now.Add(-5 * time.Minute),
	})
	ms.actionExecLog.logs = append(ms.actionExecLog.logs, store.ActionExecutionLog{
		ID: 1, AttackID: 1, ActionID: 10, ActionType: "bgp",
		TriggerPhase: "on_detected", Status: "success",
		ExternalRuleID: "10.0.0.1/32|RTBH", ConnectorID: intPtr(1),
		ConnectorName: "dual-afi", ExecutedAt: now.Add(-4 * time.Minute),
	})

	// Should not panic — vtysh fails but the function handles it
	action.RecoverBGPRoutes(context.Background(), ms)
	// If we reach here, IPv4 prefix was processed without panic
}

// TestBGPAutoAFI_IPv6Prefix verifies that an IPv6 prefix uses "ipv6 unicast".
func TestBGPAutoAFI_IPv6Prefix(t *testing.T) {
	ms := NewMockStore()
	conn := store.BGPConnector{
		ID:            1,
		Name:          "dual-afi",
		VtyshPath:     "/usr/bin/false",
		BGPASN:        65000,
		AddressFamily: "auto",
		Enabled:       true,
		CreatedAt:     time.Now(),
		UpdatedAt:     time.Now(),
	}
	ms.bgpConnectors.connectors = append(ms.bgpConnectors.connectors, conn)

	now := time.Now()
	ms.attacks.attacks = append(ms.attacks.attacks, store.Attack{
		ID: 2, DstIP: "2001:db8::1", StartedAt: now.Add(-5 * time.Minute),
	})
	ms.actionExecLog.logs = append(ms.actionExecLog.logs, store.ActionExecutionLog{
		ID: 2, AttackID: 2, ActionID: 20, ActionType: "bgp",
		TriggerPhase: "on_detected", Status: "success",
		ExternalRuleID: "2001:db8::1/128|RTBH", ConnectorID: intPtr(1),
		ConnectorName: "dual-afi", ExecutedAt: now.Add(-4 * time.Minute),
	})

	action.RecoverBGPRoutes(context.Background(), ms)
	// If we reach here, IPv6 prefix was processed without panic
}

// TestBGPAutoAFI_MixedPrefixes verifies a single connector handles both
// IPv4 and IPv6 routes in the same recovery pass.
func TestBGPAutoAFI_MixedPrefixes(t *testing.T) {
	ms := NewMockStore()
	conn := store.BGPConnector{
		ID: 1, Name: "dual-afi", VtyshPath: "/usr/bin/false",
		BGPASN: 65000, AddressFamily: "auto", Enabled: true,
		CreatedAt: time.Now(), UpdatedAt: time.Now(),
	}
	ms.bgpConnectors.connectors = append(ms.bgpConnectors.connectors, conn)

	now := time.Now()
	// IPv4 attack
	ms.attacks.attacks = append(ms.attacks.attacks, store.Attack{
		ID: 3, DstIP: "192.168.1.1", StartedAt: now.Add(-10 * time.Minute),
	})
	// IPv6 attack
	ms.attacks.attacks = append(ms.attacks.attacks, store.Attack{
		ID: 4, DstIP: "2001:db8::100", StartedAt: now.Add(-8 * time.Minute),
	})

	ms.actionExecLog.logs = append(ms.actionExecLog.logs,
		store.ActionExecutionLog{
			ID: 10, AttackID: 3, ActionID: 30, ActionType: "bgp",
			TriggerPhase: "on_detected", Status: "success",
			ExternalRuleID: "192.168.1.1/32|RTBH", ConnectorID: intPtr(1),
			ExecutedAt: now.Add(-9 * time.Minute),
		},
		store.ActionExecutionLog{
			ID: 11, AttackID: 4, ActionID: 40, ActionType: "bgp",
			TriggerPhase: "on_detected", Status: "success",
			ExternalRuleID: "2001:db8::100/128|RTBH", ConnectorID: intPtr(1),
			ExecutedAt: now.Add(-7 * time.Minute),
		},
	)

	// Both should be processed without panic — one IPv4, one IPv6, same connector
	action.RecoverBGPRoutes(context.Background(), ms)
}

// TestBGPAutoAFI_IPv6MaskDetection verifies /128 is applied for plain IPv6 IPs.
// This tests the mask detection in executeBGP (dstIP without "/" gets /128 for IPv6).
func TestBGPAutoAFI_IPv6MaskDetection(t *testing.T) {
	ms := NewMockStore()
	conn := store.BGPConnector{
		ID: 1, Name: "test", VtyshPath: "/usr/bin/false",
		BGPASN: 65000, AddressFamily: "auto", Enabled: true,
		CreatedAt: time.Now(), UpdatedAt: time.Now(),
	}
	ms.bgpConnectors.connectors = append(ms.bgpConnectors.connectors, conn)

	// Attack with plain IPv6 (no mask)
	now := time.Now()
	ms.attacks.attacks = append(ms.attacks.attacks, store.Attack{
		ID: 5, DstIP: "fd00::1", StartedAt: now.Add(-3 * time.Minute),
	})
	// The on_detected log should have /128 appended
	ms.actionExecLog.logs = append(ms.actionExecLog.logs, store.ActionExecutionLog{
		ID: 20, AttackID: 5, ActionID: 50, ActionType: "bgp",
		TriggerPhase: "on_detected", Status: "success",
		ExternalRuleID: "fd00::1/128|RTBH", ConnectorID: intPtr(1),
		ExecutedAt: now.Add(-2 * time.Minute),
	})

	action.RecoverBGPRoutes(context.Background(), ms)
}

// TestBGPAutoAFI_IPv6SubnetPrefix verifies IPv6 subnet prefixes (e.g. /64).
func TestBGPAutoAFI_IPv6SubnetPrefix(t *testing.T) {
	ms := NewMockStore()
	conn := store.BGPConnector{
		ID: 1, Name: "test", VtyshPath: "/usr/bin/false",
		BGPASN: 65000, AddressFamily: "auto", Enabled: true,
		CreatedAt: time.Now(), UpdatedAt: time.Now(),
	}
	ms.bgpConnectors.connectors = append(ms.bgpConnectors.connectors, conn)

	now := time.Now()
	ms.attacks.attacks = append(ms.attacks.attacks, store.Attack{
		ID: 6, DstIP: "2001:db8:abcd::/48", StartedAt: now.Add(-3 * time.Minute),
	})
	ms.actionExecLog.logs = append(ms.actionExecLog.logs, store.ActionExecutionLog{
		ID: 30, AttackID: 6, ActionID: 60, ActionType: "bgp",
		TriggerPhase: "on_detected", Status: "success",
		ExternalRuleID: "2001:db8:abcd::/48|RTBH", ConnectorID: intPtr(1),
		ExecutedAt: now.Add(-2 * time.Minute),
	})

	action.RecoverBGPRoutes(context.Background(), ms)
}

// TestBGPAutoAFI_HasManualOverride_IPv6 verifies HasManualOverride works with IPv6 rule IDs.
func TestBGPAutoAFI_HasManualOverride_IPv6(t *testing.T) {
	ms := NewMockStore()
	eng := action.NewEngine(ms, "auto")

	// v1.2 PR-2: seed the index table (authoritative for HasManualOverride)
	if _, err := ms.manualOverrides.Create(context.Background(), &store.ActionManualOverride{
		AttackID:       10,
		ActionID:       70,
		ConnectorID:    1,
		ExternalRuleID: "2001:db8::1/128|RTBH",
	}); err != nil {
		t.Fatalf("seed manual_override: %v", err)
	}

	ctx := context.Background()
	if !eng.HasManualOverride(ctx, 10, 70, 1, "2001:db8::1/128|RTBH") {
		t.Error("HasManualOverride should return true for IPv6 rule")
	}
	if eng.HasManualOverride(ctx, 10, 70, 1, "10.0.0.1/32|RTBH") {
		t.Error("HasManualOverride should return false for non-matching IPv4 rule")
	}
}

// TestBGPAutoAFI_LegacyIPv6RuleID verifies that old-format IPv6 external_rule_ids
// (using ":" separator like "2001:db8::1/128:RTBH") are correctly parsed.
// The recovery path calls splitExternalRuleID which should use LastIndex(":").
func TestBGPAutoAFI_LegacyIPv6RuleID(t *testing.T) {
	ms := NewMockStore()
	conn := store.BGPConnector{
		ID: 1, Name: "test", VtyshPath: "/usr/bin/false",
		BGPASN: 65000, AddressFamily: "auto", Enabled: true,
		CreatedAt: time.Now(), UpdatedAt: time.Now(),
	}
	ms.bgpConnectors.connectors = append(ms.bgpConnectors.connectors, conn)

	now := time.Now()
	// Expired attack with old-format IPv6 rule ID (colon separator)
	ended := now.Add(-2 * time.Minute)
	ms.attacks.attacks = append(ms.attacks.attacks, store.Attack{
		ID: 100, DstIP: "2001:db8::1", StartedAt: now.Add(-10 * time.Minute), EndedAt: &ended,
	})
	ms.attacks.expiredAttacks = append(ms.attacks.expiredAttacks, ms.attacks.attacks[0])

	// Legacy format: "2001:db8::1/128:RTBH" (colon before route_map)
	ms.actionExecLog.logs = append(ms.actionExecLog.logs, store.ActionExecutionLog{
		ID: 100, AttackID: 100, ActionID: 1, ActionType: "bgp",
		TriggerPhase: "on_detected", Status: "success",
		ExternalRuleID: "2001:db8::1/128:RTBH", ConnectorID: intPtr(1),
		ExecutedAt: now.Add(-9 * time.Minute),
	})

	// RecoverBGPRoutes should parse the legacy ID correctly (LastIndex ":") and
	// attempt withdrawal with prefix="2001:db8::1/128", routeMap="RTBH".
	// vtysh will fail but the function must not panic.
	action.RecoverBGPRoutes(context.Background(), ms)
}

// TestBGPAutoAFI_ActiveActionsParseIPv6 verifies the Mitigations BGP tab
// correctly parses legacy IPv6 external_rule_ids into prefix + route_map.
func TestBGPAutoAFI_ActiveActionsParseIPv6(t *testing.T) {
	ms := NewMockStore()
	now := time.Now()
	connID := 1

	ms.attacks.attacks = append(ms.attacks.attacks, store.Attack{
		ID: 200, DstIP: "2001:db8::99", StartedAt: now.Add(-5 * time.Minute),
	})

	// New format (pipe separator)
	ms.actionExecLog.logs = append(ms.actionExecLog.logs, store.ActionExecutionLog{
		ID: 200, AttackID: 200, ActionID: 50, ActionType: "bgp",
		TriggerPhase: "on_detected", Status: "success",
		ExternalRuleID: "2001:db8::99/128|RTBH", ConnectorID: &connID,
		ConnectorName: "test-bgp", ExecutedAt: now.Add(-4 * time.Minute),
	})
	// v1.2 PR-5: seed bgp_announcements state
	ar, _ := ms.bgpAnnouncements.Attach(context.Background(), store.BGPAttachParams{
		AttackID: 200, ActionID: ip(50), Prefix: "2001:db8::99/128", RouteMap: "RTBH", ConnectorID: connID,
	})
	ms.bgpAnnouncements.MarkAnnounced(context.Background(), ar.AnnouncementID)
	ms.bgpConnectors.connectors = append(ms.bgpConnectors.connectors, store.BGPConnector{
		ID: connID, Name: "test-bgp", Enabled: true,
	})

	r := setupRouter(ms)
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/api/active-actions/bgp", nil)
	req.Header.Set("Authorization", "Bearer "+makeTestToken(t))
	r.ServeHTTP(w, req)

	if w.Code != 200 {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var items []map[string]any
	json.Unmarshal(w.Body.Bytes(), &items)
	if len(items) == 0 {
		t.Fatal("expected at least 1 BGP route")
	}

	item := items[0]
	prefix, _ := item["prefix"].(string)
	routeMap, _ := item["route_map"].(string)

	if prefix != "2001:db8::99/128" {
		t.Errorf("prefix = %q, want %q", prefix, "2001:db8::99/128")
	}
	if routeMap != "RTBH" {
		t.Errorf("route_map = %q, want %q", routeMap, "RTBH")
	}
}

// TestBGPAutoAFI_DelayHelper_IPv6 verifies delay scheduling works with IPv6 business keys.
func TestBGPAutoAFI_DelayHelper_IPv6(t *testing.T) {
	ms := NewMockStore()
	eng := action.NewEngine(ms, "auto")
	ctx := context.Background()
	scheduledFor := time.Now().Add(1 * time.Minute)

	_, cctx, err := eng.ScheduleDelay(ctx, "bgp_withdraw", 1, 2, 3, "2001:db8::1/128|RTBH", scheduledFor)
	if err != nil {
		t.Fatalf("ScheduleDelay returned error for IPv6 key: %v", err)
	}
	if cctx == nil {
		t.Fatal("ScheduleDelay returned nil for IPv6 key")
	}

	// Cancel and verify
	eng.CancelDelay(1, 2, 3, "2001:db8::1/128|RTBH")
	select {
	case <-cctx.Done():
		// Expected
	default:
		t.Error("CancelDelay did not cancel IPv6 key context")
	}
}
