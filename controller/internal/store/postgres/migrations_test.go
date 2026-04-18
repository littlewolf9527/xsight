package postgres

// Invariant tests for migration SQL that can't easily be exercised with a mock
// store. The v1.2 bootstrap queries are only interesting against real
// Postgres, but the structural invariants they must satisfy are testable as
// string assertions — and a string assertion is better than no regression
// guard at all.

import (
	"strings"
	"testing"
)

// TestXDropBootstrap_NoActionIDInMatch guards the v1.2.0 bootstrap bug where
// the xdrop_active_rules backfill mis-matched paired actions.
//
// The paired on_detected → on_expired actions have *different* action_ids
// (auto-pair creates a child action). If the NOT EXISTS clause includes
// `l2.action_id = l.action_id`, the match never fires and every historical
// xDrop rule — including ones with a clean successful unblock — ends up
// backfilled as `status=active`. Prod hit this on the v1.2.0 deploy (40
// ghost rows pointing at rules that xDrop had long since deleted).
//
// The correct match uses only (attack_id, connector_id, external_rule_id),
// mirroring the BGP backfill above it in the migration list.
func TestXDropBootstrap_NoActionIDInMatch(t *testing.T) {
	var stmt string
	for _, m := range migrations {
		if strings.Contains(m, "INSERT INTO xdrop_active_rules") &&
			strings.Contains(m, "action_execution_log") {
			stmt = m
			break
		}
	}
	if stmt == "" {
		t.Fatal("xdrop_active_rules bootstrap INSERT not found in migrations — did the migration list get refactored without updating this test?")
	}

	// Find the NOT EXISTS block.
	ne := strings.Index(stmt, "NOT EXISTS")
	if ne < 0 {
		t.Fatal("NOT EXISTS clause not found in xdrop bootstrap; v1.2 bootstrap structure changed unexpectedly")
	}
	end := strings.Index(stmt[ne:], ")")
	if end < 0 {
		t.Fatal("malformed NOT EXISTS clause in xdrop bootstrap")
	}
	block := stmt[ne : ne+end]

	// The bug pattern. Must NOT appear inside the NOT EXISTS.
	bug := "l2.action_id = l.action_id"
	if strings.Contains(block, bug) {
		t.Errorf("xdrop bootstrap NOT EXISTS matches on action_id — this was the v1.2.0 bug.\n"+
			"Paired on_expired actions have a *different* action_id (auto-pair creates a child action),\n"+
			"so this predicate never fires, and every on_detected success gets backfilled as active\n"+
			"regardless of whether it was already unblocked.\n"+
			"Match on (attack_id, connector_id, external_rule_id) only; see BGP backfill for the correct pattern.\n"+
			"found: %s", block)
	}

	// Positive asserts — the business-key triple that *must* be in the match.
	for _, must := range []string{
		"l2.attack_id = l.attack_id",
		"l2.connector_id = l.connector_id",
		"l2.external_rule_id = l.external_rule_id",
	} {
		if !strings.Contains(block, must) {
			t.Errorf("xdrop bootstrap NOT EXISTS missing %q — needed to identify the rule", must)
		}
	}
}
