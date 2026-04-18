package metrics

// Tests for the v1.2.1 Prometheus metrics layer.
//
// Coverage:
//   - Inline counter increments (RecordVtysh / RecordAction) show up in
//     the registered CounterVec
//   - Custom status collectors run their count function on scrape and emit
//     one metric per status bucket
//   - Stale scrape (count function errors) silently drops the scrape without
//     returning 500 — the Prometheus convention
//
// We don't exercise the HTTP /metrics endpoint directly here; that's
// covered in the live test (curl against the running controller).

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

// ─────────────────────────────────────────────────────────────────────────────
// Counter tests
// ─────────────────────────────────────────────────────────────────────────────

func TestVtyshOps_IncrementsByLabel(t *testing.T) {
	// Use a fresh registry so state from other tests doesn't leak in.
	reg := prometheus.NewRegistry()
	VtyshOps.Reset() // reset the package-global counter for this test
	reg.MustRegister(VtyshOps)

	RecordVtysh("announce", "success")
	RecordVtysh("announce", "success")
	RecordVtysh("announce", "failed")
	RecordVtysh("withdraw", "idempotent")

	if got := testutil.ToFloat64(VtyshOps.WithLabelValues("announce", "success")); got != 2 {
		t.Errorf("announce/success = %v, want 2", got)
	}
	if got := testutil.ToFloat64(VtyshOps.WithLabelValues("announce", "failed")); got != 1 {
		t.Errorf("announce/failed = %v, want 1", got)
	}
	if got := testutil.ToFloat64(VtyshOps.WithLabelValues("withdraw", "idempotent")); got != 1 {
		t.Errorf("withdraw/idempotent = %v, want 1", got)
	}
	// Never-incremented labelsets should NOT show up in /metrics output
	// (CounterVec only emits labelsets that have been touched).
	if got := testutil.ToFloat64(VtyshOps.WithLabelValues("withdraw", "success")); got != 0 {
		t.Errorf("withdraw/success = %v, want 0 (not incremented)", got)
	}
}

func TestActionExecutions_IncrementsByLabel(t *testing.T) {
	ActionExecutions.Reset()
	reg := prometheus.NewRegistry()
	reg.MustRegister(ActionExecutions)

	RecordAction("bgp", "success")
	RecordAction("bgp", "failed")
	RecordAction("xdrop", "skipped")
	RecordAction("webhook", "success")
	RecordAction("webhook", "success")

	if got := testutil.ToFloat64(ActionExecutions.WithLabelValues("bgp", "success")); got != 1 {
		t.Errorf("bgp/success = %v, want 1", got)
	}
	if got := testutil.ToFloat64(ActionExecutions.WithLabelValues("webhook", "success")); got != 2 {
		t.Errorf("webhook/success = %v, want 2", got)
	}
	if got := testutil.ToFloat64(ActionExecutions.WithLabelValues("xdrop", "skipped")); got != 1 {
		t.Errorf("xdrop/skipped = %v, want 1", got)
	}
}

func TestActionSkip_IncrementsByReason(t *testing.T) {
	ActionSkip.Reset()
	reg := prometheus.NewRegistry()
	reg.MustRegister(ActionSkip)

	RecordSkip("precondition_not_matched")
	RecordSkip("precondition_not_matched")
	RecordSkip("first_match_suppressed")
	RecordSkip("decoder_not_xdrop_compatible")

	if got := testutil.ToFloat64(ActionSkip.WithLabelValues("precondition_not_matched")); got != 2 {
		t.Errorf("precondition_not_matched = %v, want 2", got)
	}
	if got := testutil.ToFloat64(ActionSkip.WithLabelValues("first_match_suppressed")); got != 1 {
		t.Errorf("first_match_suppressed = %v, want 1", got)
	}
	if got := testutil.ToFloat64(ActionSkip.WithLabelValues("decoder_not_xdrop_compatible")); got != 1 {
		t.Errorf("decoder_not_xdrop_compatible = %v, want 1", got)
	}
	// Never-incremented reason should NOT appear in output
	if got := testutil.ToFloat64(ActionSkip.WithLabelValues("mode_observe")); got != 0 {
		t.Errorf("mode_observe = %v, want 0 (not incremented)", got)
	}
}

func TestScheduledActionsRecovered_IncrementsByOutcome(t *testing.T) {
	ScheduledActionsRecovered.Reset()
	reg := prometheus.NewRegistry()
	reg.MustRegister(ScheduledActionsRecovered)

	RecordRecovered("armed")
	RecordRecovered("armed")
	RecordRecovered("armed")
	RecordRecovered("overdue_fired")
	RecordRecovered("executing_retried")

	if got := testutil.ToFloat64(ScheduledActionsRecovered.WithLabelValues("armed")); got != 3 {
		t.Errorf("armed = %v, want 3", got)
	}
	if got := testutil.ToFloat64(ScheduledActionsRecovered.WithLabelValues("overdue_fired")); got != 1 {
		t.Errorf("overdue_fired = %v, want 1", got)
	}
	if got := testutil.ToFloat64(ScheduledActionsRecovered.WithLabelValues("executing_retried")); got != 1 {
		t.Errorf("executing_retried = %v, want 1", got)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Status collector tests
// ─────────────────────────────────────────────────────────────────────────────

func TestStatusGaugeCollector_EmitsOneMetricPerStatus(t *testing.T) {
	reg := prometheus.NewRegistry()
	reg.MustRegister(newStatusGaugeCollector(
		"test_widgets", "Test help",
		func(ctx context.Context) (map[string]int, error) {
			return map[string]int{
				"active":    3,
				"withdrawn": 12,
				"failed":    1,
			}, nil
		},
	))

	// CollectAndCount returns the number of metrics emitted for a given
	// metric family — here, one sample per status bucket.
	got := testutil.CollectAndCount(reg, "test_widgets")
	if got != 3 {
		t.Errorf("emitted metrics = %d, want 3 (one per status bucket)", got)
	}

	// Lint the exposition format (label naming, help text, type).
	expected := `
# HELP test_widgets Test help
# TYPE test_widgets gauge
test_widgets{status="active"} 3
test_widgets{status="failed"} 1
test_widgets{status="withdrawn"} 12
`
	if err := testutil.CollectAndCompare(reg, strings.NewReader(expected), "test_widgets"); err != nil {
		t.Errorf("exposition mismatch: %v", err)
	}
}

func TestStatusGaugeCollector_SwallowsErrors(t *testing.T) {
	reg := prometheus.NewRegistry()
	reg.MustRegister(newStatusGaugeCollector(
		"test_widgets", "Test help",
		func(ctx context.Context) (map[string]int, error) {
			return nil, fmt.Errorf("db unavailable")
		},
	))

	// Error path: Collect returns nothing rather than a 500. Prometheus
	// sees the timeseries go blank, which is the signal "collector error".
	got := testutil.CollectAndCount(reg, "test_widgets")
	if got != 0 {
		t.Errorf("on error, expected 0 metrics emitted; got %d", got)
	}
}

func TestStatusGaugeCollector_EmptyMapNoPanics(t *testing.T) {
	reg := prometheus.NewRegistry()
	reg.MustRegister(newStatusGaugeCollector(
		"test_widgets", "Test help",
		func(ctx context.Context) (map[string]int, error) {
			return map[string]int{}, nil
		},
	))

	got := testutil.CollectAndCount(reg, "test_widgets")
	if got != 0 {
		t.Errorf("empty count map: expected 0 metrics; got %d", got)
	}
}
