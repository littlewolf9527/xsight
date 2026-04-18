// Package metrics exposes xSight controller state as Prometheus metrics.
//
// Design principles:
//   - Only expose metrics an operator can actually alert on or dashboard
//     (see roadmap v1.2.1 Scope). No speculative metrics.
//   - Gauges that read DB state use Prometheus custom collectors so the
//     value is fresh-at-scrape-time. No background refresh goroutine
//     (simpler, no staleness window).
//   - Counters (vtysh ops, action executions) are incremented inline at
//     call sites. Single source of truth is the Go variable — DB state
//     is NOT re-derived from counters.
//   - /metrics endpoint is unauthenticated, matching industry convention
//     for Prometheus scraping (relies on network-level isolation).
//
// Layer A (v1.2 Action State gauges — custom collectors):
//
//	xsight_bgp_announcements{status}       current announcements by status
//	xsight_xdrop_rules{status}             current xDrop rules by status
//	xsight_scheduled_actions{status}       current scheduled actions by status
//
// Layer A (inline counters):
//
//	xsight_vtysh_ops_total{operation,result}  vtysh announce/withdraw outcomes
//	xsight_action_executions_total{action_type,status}  action engine dispatch outcomes
//
// Layer B (attack tracker — wrap existing atomic counters):
//
//	xsight_attacks_active                   current active attacks (gauge)
//	xsight_attacks_created_total            lifetime attacks created
//	xsight_attacks_suppressed_total         lifetime attacks suppressed (dedup)
//	xsight_attacks_evicted_total            lifetime attacks evicted (cap hit)
//
// Layer C: Go runtime metrics are auto-registered by promhttp default (free).

package metrics

import (
	"context"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/littlewolf9527/xsight/controller/internal/store"
	"github.com/littlewolf9527/xsight/controller/internal/tracker"
)

// ─────────────────────────────────────────────────────────────────────────────
// Layer A — inline counters
// ─────────────────────────────────────────────────────────────────────────────

// VtyshOps counts outcomes of vtysh commands xSight issues for BGP state
// changes. Incremented by bgp.go at each performBGPAnnounce / performBGPWithdraw
// / retry / recovery call site.
//
// Labels:
//   - operation: "announce" | "withdraw"
//   - result:    "success" | "failed" | "idempotent"
//                ("idempotent" = vtysh returned a "route-absent" error on
//                 withdraw that xSight treats as success; tracked separately
//                 so operators can see how often FRR drift is absorbed).
var VtyshOps = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: "xsight_vtysh_ops_total",
		Help: "Total vtysh operations by operation and result.",
	},
	[]string{"operation", "result"},
)

// ActionExecutions counts action engine dispatch outcomes.
//
// Labels:
//   - action_type: "bgp" | "xdrop" | "webhook" | "shell"
//   - status:      "success" | "failed" | "timeout" | "skipped" | "scheduled"
//                  "scheduled" = action was queued for delayed execution
//                  (not yet run). "success" is fired when the delayed action
//                  completes. Operator can rate-monitor any dimension.
var ActionExecutions = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: "xsight_action_executions_total",
		Help: "Total action engine dispatches by action type and outcome status.",
	},
	[]string{"action_type", "status"},
)

// ActionSkip breaks out action_executions_total{status="skipped"} by the
// specific skip_reason. Lets operators alert on precondition_not_matched
// spikes, decoder_not_xdrop_compatible surges (misconfiguration signal),
// or first_match_suppressed rates without having to pull log rows.
//
// Labels:
//   - skip_reason: one of SkipReason* enum values in action.engine.go
//
// Cardinality: bounded by the enum (currently 6 values), no explosion.
var ActionSkip = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: "xsight_action_skip_total",
		Help: "Total actions skipped by dispatch gate, broken down by skip_reason.",
	},
	[]string{"skip_reason"},
)

// ScheduledActionsRecovered counts outcomes of the startup reconciliation
// for persisted scheduled_actions rows. A non-zero rate of
// outcome="overdue_fired" after restart is the expected tail of the v1.2
// persistence model (delayed tasks whose schedule time passed during
// downtime). "executing_retried" counts rows stuck in the executing state
// from a crash between MarkExecuting and Complete/Fail — should stay at 0
// in steady state; a non-zero reading is an incident signal.
//
// Labels:
//   - outcome: "armed" | "overdue_fired" | "executing_retried"
var ScheduledActionsRecovered = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: "xsight_scheduled_actions_recovered_total",
		Help: "Total scheduled_actions rows processed by startup recovery, by outcome.",
	},
	[]string{"outcome"},
)

// RecordVtysh is a small helper so the action package doesn't need to
// import the prometheus namespace directly.
func RecordVtysh(operation, result string) {
	VtyshOps.WithLabelValues(operation, result).Inc()
}

// RecordAction increments the action-execution counter. Mirrors the status
// strings already written to action_execution_log.
func RecordAction(actionType, status string) {
	ActionExecutions.WithLabelValues(actionType, status).Inc()
}

// RecordSkip increments xsight_action_skip_total for the given skip_reason.
// Called from writeSkipLog in the action package so every logged skip
// simultaneously bumps both the log row and the counter.
func RecordSkip(skipReason string) {
	ActionSkip.WithLabelValues(skipReason).Inc()
}

// RecordRecovered increments xsight_scheduled_actions_recovered_total.
// Called from ReconcileOnStartup paths when a scheduled row transitions
// under recovery.
func RecordRecovered(outcome string) {
	ScheduledActionsRecovered.WithLabelValues(outcome).Inc()
}

// ─────────────────────────────────────────────────────────────────────────────
// Layer A — custom collectors (fresh-at-scrape gauges)
// ─────────────────────────────────────────────────────────────────────────────

// statusCountFunc queries a state table for (status → count) pairs. Each
// v1.2 state repo implements this via a CountByStatus method.
type statusCountFunc func(ctx context.Context) (map[string]int, error)

// statusGaugeCollector is a Prometheus collector that emits one gauge per
// status value returned by the count function, as of scrape time.
//
// Why not a GaugeVec with background refresh: the background approach
// leaves a staleness window (up to refresh interval) and requires reasoning
// about reset semantics when a status disappears. Scrape-time collection
// is always fresh and the "status disappeared" case is handled naturally
// (we simply don't emit that labelset).
type statusGaugeCollector struct {
	desc    *prometheus.Desc
	countFn statusCountFunc
}

func newStatusGaugeCollector(name, help string, fn statusCountFunc) *statusGaugeCollector {
	return &statusGaugeCollector{
		desc:    prometheus.NewDesc(name, help, []string{"status"}, nil),
		countFn: fn,
	}
}

func (c *statusGaugeCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.desc
}

func (c *statusGaugeCollector) Collect(ch chan<- prometheus.Metric) {
	// Bound every scrape to 5s so a slow DB can't pile up scrape goroutines.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	counts, err := c.countFn(ctx)
	if err != nil {
		// Swallow — metrics endpoint must never return 500. Operators will
		// see that the expected timeseries went blank in Prometheus, which
		// is the standard signal for "collector error".
		return
	}
	for status, count := range counts {
		ch <- prometheus.MustNewConstMetric(
			c.desc, prometheus.GaugeValue, float64(count), status,
		)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Layer B — attack tracker wrappers
// ─────────────────────────────────────────────────────────────────────────────

// trackerCollector emits the four attack-tracker counters as Prometheus
// metrics. The tracker already maintains atomic Int64 counters that
// /api/stats/summary consumes — we just expose them in Prometheus format.
type trackerCollector struct {
	tracker *tracker.Tracker

	activeDesc     *prometheus.Desc
	createdDesc    *prometheus.Desc
	suppressedDesc *prometheus.Desc
	evictedDesc    *prometheus.Desc
}

func newTrackerCollector(t *tracker.Tracker) *trackerCollector {
	return &trackerCollector{
		tracker: t,
		activeDesc: prometheus.NewDesc(
			"xsight_attacks_active",
			"Current active attacks tracked in memory.",
			nil, nil,
		),
		createdDesc: prometheus.NewDesc(
			"xsight_attacks_created_total",
			"Lifetime count of attacks created.",
			nil, nil,
		),
		suppressedDesc: prometheus.NewDesc(
			"xsight_attacks_suppressed_total",
			"Lifetime count of attacks suppressed by dedup.",
			nil, nil,
		),
		evictedDesc: prometheus.NewDesc(
			"xsight_attacks_evicted_total",
			"Lifetime count of attacks evicted due to tracker capacity. "+
				"Non-zero indicates capacity limit reached — increase cap or investigate.",
			nil, nil,
		),
	}
}

func (c *trackerCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.activeDesc
	ch <- c.createdDesc
	ch <- c.suppressedDesc
	ch <- c.evictedDesc
}

func (c *trackerCollector) Collect(ch chan<- prometheus.Metric) {
	ch <- prometheus.MustNewConstMetric(c.activeDesc, prometheus.GaugeValue,
		float64(c.tracker.ActiveCount()))
	ch <- prometheus.MustNewConstMetric(c.createdDesc, prometheus.CounterValue,
		float64(c.tracker.CreatedTotal.Load()))
	ch <- prometheus.MustNewConstMetric(c.suppressedDesc, prometheus.CounterValue,
		float64(c.tracker.SuppressedTotal.Load()))
	ch <- prometheus.MustNewConstMetric(c.evictedDesc, prometheus.CounterValue,
		float64(c.tracker.EvictedTotal.Load()))
}

// ─────────────────────────────────────────────────────────────────────────────
// Registration
// ─────────────────────────────────────────────────────────────────────────────

// Register wires every xSight metric into the given registry. Call once at
// startup. The default Prometheus registry (used by promhttp.Handler()) is
// the typical choice; tests pass a fresh registry to isolate state.
//
// The Go runtime collector is already auto-registered in the default
// registry, so callers using promhttp.Handler() get it for free.
func Register(reg prometheus.Registerer, s store.Store, t *tracker.Tracker) error {
	// Inline counters
	if err := reg.Register(VtyshOps); err != nil {
		return err
	}
	if err := reg.Register(ActionExecutions); err != nil {
		return err
	}
	if err := reg.Register(ActionSkip); err != nil {
		return err
	}
	if err := reg.Register(ScheduledActionsRecovered); err != nil {
		return err
	}
	// State-table gauges (one query per scrape per collector)
	if err := reg.Register(newStatusGaugeCollector(
		"xsight_bgp_announcements",
		"Current BGP announcements by lifecycle status.",
		s.BGPAnnouncements().CountByStatus,
	)); err != nil {
		return err
	}
	if err := reg.Register(newStatusGaugeCollector(
		"xsight_xdrop_rules",
		"Current xDrop filter rules by lifecycle status.",
		s.XDropActiveRules().CountByStatus,
	)); err != nil {
		return err
	}
	if err := reg.Register(newStatusGaugeCollector(
		"xsight_scheduled_actions",
		"Current scheduled actions by status.",
		s.ScheduledActions().CountByStatus,
	)); err != nil {
		return err
	}
	// Attack tracker
	if err := reg.Register(newTrackerCollector(t)); err != nil {
		return err
	}
	return nil
}
