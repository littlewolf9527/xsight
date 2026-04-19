package store

import (
	"context"
	"time"
)

// Store groups all repository interfaces. Implementations (postgres, sqlite)
// provide a concrete Store via their constructor.
type Store interface {
	Nodes() NodeRepo
	Prefixes() PrefixRepo
	ThresholdTemplates() ThresholdTemplateRepo
	Thresholds() ThresholdRepo
	Responses() ResponseRepo
	Attacks() AttackRepo
	ActionsLog() ActionsLogRepo
	Users() UserRepo
	Webhooks() WebhookRepo
	AuditLog() AuditLogRepo
	Stats() StatsRepo
	DynDetect() DynDetectRepo
	// Response System v2 connectors
	WebhookConnectors() WebhookConnectorRepo
	XDropConnectors() XDropConnectorRepo
	ShellConnectors() ShellConnectorRepo
	ActionExecLog() ActionExecLogRepo
	XDropTargets() XDropTargetRepo
	Preconditions() PreconditionRepo
	// v1.2 PR-2: O(1) manual override lookup
	ManualOverrides() ActionManualOverrideRepo
	// v1.2 PR-3: persisted scheduled delay actions (pendingDelay replacement)
	ScheduledActions() ScheduledActionRepo
	// v1.2 PR-4: authoritative xDrop rule state (replaces log-derivation)
	XDropActiveRules() XDropActiveRuleRepo
	// v1.2 PR-5: refcount-based BGP announcements (replaces per-attack withdraw)
	BGPAnnouncements() BGPAnnouncementRepo
	FlowLogs() FlowLogRepo
	// v3.0: Flow listeners + sources
	FlowListeners() FlowListenerRepo
	FlowSources() FlowSourceRepo
	// v3.1: BGP connectors
	BGPConnectors() BGPConnectorRepo
	Close()
}

// DynDetectConfig holds the dynamic detection configuration (single row).
type DynDetectConfig struct {
	Enabled      bool    `json:"enabled"`
	DeviationMin int     `json:"deviation_min"`
	DeviationMax int     `json:"deviation_max"`
	StableWeeks  int     `json:"stable_weeks"`
	MinPPS       int64   `json:"min_pps"`
	MinBPS       int64   `json:"min_bps"`
	EWMAAlpha    float32 `json:"ewma_alpha"`
}

// PrefixProfile holds one slot of a prefix's traffic profile.
type PrefixProfile struct {
	NodeID       string `json:"node_id"`
	Prefix       string `json:"prefix"`
	SlotIndex    int    `json:"slot_index"`
	ExpectedPPS  int64  `json:"expected_pps"`
	ExpectedBPS  int64  `json:"expected_bps"`
	SampleWeeks  int    `json:"sample_weeks"`
	LastSampleYW int    `json:"last_sample_yw"`
}

// DynDetectRepo manages dynamic detection config and profiles.
type DynDetectRepo interface {
	GetConfig(ctx context.Context) (*DynDetectConfig, error)
	UpdateConfig(ctx context.Context, cfg *DynDetectConfig) error
	ListProfiles(ctx context.Context, slotIndex int) ([]PrefixProfile, error)
	UpsertProfile(ctx context.Context, p *PrefixProfile) error
	BulkUpsertProfiles(ctx context.Context, profiles []PrefixProfile) error
	DeleteAllProfiles(ctx context.Context) error
}

// NodeRepo manages Node registrations (XDP + Flow).
type NodeRepo interface {
	List(ctx context.Context) ([]Node, error)
	Get(ctx context.Context, id string) (*Node, error)
	Create(ctx context.Context, n *Node) error
	Update(ctx context.Context, n *Node) error
	Delete(ctx context.Context, id string) error
	UpdateMode(ctx context.Context, id, mode string) error
	UpdateDeliveryVersionCurrent(ctx context.Context, id string, version int64) error
	UpdateACK(ctx context.Context, id string, versionApplied int64) error
}

// PrefixRepo manages watch prefixes (CIDR tree).
type PrefixRepo interface {
	List(ctx context.Context) ([]WatchPrefix, error)
	Count(ctx context.Context) (int, error)
	Get(ctx context.Context, id int) (*WatchPrefix, error)
	Create(ctx context.Context, p *WatchPrefix) (int, error) // returns ID
	Update(ctx context.Context, p *WatchPrefix) error
	Delete(ctx context.Context, id int) error
	ListTree(ctx context.Context) ([]WatchPrefix, error) // flat list with parent_id for tree building
}

// ThresholdTemplateRepo manages threshold templates.
type ThresholdTemplateRepo interface {
	List(ctx context.Context) ([]ThresholdTemplate, error)
	Get(ctx context.Context, id int) (*ThresholdTemplate, error)
	Create(ctx context.Context, t *ThresholdTemplate) (int, error)
	Update(ctx context.Context, t *ThresholdTemplate) error
	Delete(ctx context.Context, id int) error // RESTRICT: fails if in use
	Duplicate(ctx context.Context, id int, newName string) (int, error)
	ListRules(ctx context.Context, templateID int) ([]Threshold, error)
	ListPrefixesUsing(ctx context.Context, templateID int) ([]WatchPrefix, error)
}

// ThresholdRepo manages detection thresholds (template rules + per-prefix overrides).
type ThresholdRepo interface {
	List(ctx context.Context) ([]Threshold, error)
	Count(ctx context.Context) (int, error)
	ListByPrefix(ctx context.Context, prefixID int) ([]Threshold, error)
	Get(ctx context.Context, id int) (*Threshold, error)
	Create(ctx context.Context, t *Threshold) (int, error)
	Update(ctx context.Context, t *Threshold) error
	Delete(ctx context.Context, id int) error
}

// ResponseRepo manages responses and their actions.
type ResponseRepo interface {
	List(ctx context.Context) ([]Response, error)
	Get(ctx context.Context, id int) (*Response, error)
	Create(ctx context.Context, r *Response) (int, error)
	Update(ctx context.Context, r *Response) error
	Delete(ctx context.Context, id int) error
	// Actions
	ListActions(ctx context.Context, responseID int) ([]ResponseAction, error)
	GetAction(ctx context.Context, id int) (*ResponseAction, error)
	CreateAction(ctx context.Context, a *ResponseAction) (int, error)
	UpdateAction(ctx context.Context, a *ResponseAction) error
	DeleteAction(ctx context.Context, id int) error
	SetPairedWith(ctx context.Context, actionID int, pairedID *int) error
	// Connector usage checks (for safe deletion)
	CountActionsByWebhookConnector(ctx context.Context, connectorID int) (int, error)
	CountActionsByShellConnector(ctx context.Context, connectorID int) (int, error)
	CountActionsByBGPConnector(ctx context.Context, connectorID int) (int, error)
}

// AttackRepo manages attack records.
type AttackRepo interface {
	List(ctx context.Context, filter AttackFilter) ([]Attack, error)
	Count(ctx context.Context, filter AttackFilter) (int, error)
	Get(ctx context.Context, id int) (*Attack, error)
	Create(ctx context.Context, a *Attack) (int, error)
	Update(ctx context.Context, a *Attack) error
	ListActive(ctx context.Context, limit int) ([]Attack, error)
	CountActive(ctx context.Context) (int, error)
}

// ActionsLogRepo tracks action execution history.
type ActionsLogRepo interface {
	Create(ctx context.Context, l *ActionLog) (int, error)
	Update(ctx context.Context, l *ActionLog) error
	FindByAttackAndAction(ctx context.Context, attackID, actionID int) (*ActionLog, error)
	ListByAttack(ctx context.Context, attackID int) ([]ActionLog, error)
}

// UserRepo manages Web UI user accounts.
type UserRepo interface {
	List(ctx context.Context) ([]User, error)
	Get(ctx context.Context, id int) (*User, error)
	GetByUsername(ctx context.Context, username string) (*User, error)
	Create(ctx context.Context, u *User) (int, error)
	Update(ctx context.Context, u *User) error
	Delete(ctx context.Context, id int) error
}

// WebhookRepo manages webhook endpoints.
type WebhookRepo interface {
	List(ctx context.Context) ([]Webhook, error)
	Get(ctx context.Context, id int) (*Webhook, error)
	Create(ctx context.Context, w *Webhook) (int, error)
	Update(ctx context.Context, w *Webhook) error
	Delete(ctx context.Context, id int) error
}

// ──────────────── Response System v2 Connector Repos ────────────────

// WebhookConnectorRepo manages webhook connector configurations.
type WebhookConnectorRepo interface {
	List(ctx context.Context) ([]WebhookConnector, error)
	ListGlobal(ctx context.Context) ([]WebhookConnector, error) // global=true only
	Get(ctx context.Context, id int) (*WebhookConnector, error)
	Create(ctx context.Context, c *WebhookConnector) (int, error)
	Update(ctx context.Context, c *WebhookConnector) error
	Delete(ctx context.Context, id int) error
}

// XDropConnectorRepo manages xDrop controller endpoint configurations.
type XDropConnectorRepo interface {
	List(ctx context.Context) ([]XDropConnector, error)
	ListEnabled(ctx context.Context) ([]XDropConnector, error)
	Get(ctx context.Context, id int) (*XDropConnector, error)
	Create(ctx context.Context, c *XDropConnector) (int, error)
	Update(ctx context.Context, c *XDropConnector) error
	Delete(ctx context.Context, id int) error
}

// ShellConnectorRepo manages shell script configurations.
type ShellConnectorRepo interface {
	List(ctx context.Context) ([]ShellConnector, error)
	Get(ctx context.Context, id int) (*ShellConnector, error)
	Create(ctx context.Context, c *ShellConnector) (int, error)
	Update(ctx context.Context, c *ShellConnector) error
	Delete(ctx context.Context, id int) error
}

// ActionExecLogRepo manages action execution logs (replaces ActionsLogRepo).
type ActionExecLogRepo interface {
	Create(ctx context.Context, l *ActionExecutionLog) (int, error)
	ListByAttack(ctx context.Context, attackID int) ([]ActionExecutionLog, error)
	FindByAttackAndAction(ctx context.Context, attackID, actionID int, triggerPhase string) (*ActionExecutionLog, error)
	FindExternalRuleIDs(ctx context.Context, attackID, actionID int) ([]string, error)
	FindExternalRulesWithActions(ctx context.Context, attackID int) ([]RuleWithAction, error)
}

// v1.2 PR-5: BGPAnnouncementRepo manages refcount-based BGP announcements.
// All writes happen inside repo-level transactions (the store abstraction
// does NOT leak pgx.Tx). Callers invoke atomic operations (Attach, Detach,
// MarkAnnounced, etc.) and the repo takes care of SELECT FOR UPDATE + COMMIT.
//
// Side effects (vtysh announce/withdraw) are invoked by AnnouncementManager
// outside the transaction, using the returned intent flags. This is
// compensating consistency, not atomic — the `announcing` and `withdrawing`
// statuses exist as crash-recovery landmarks.
type BGPAnnouncementRepo interface {
	// Get returns an announcement by ID, or nil if not found.
	Get(ctx context.Context, id int) (*BGPAnnouncement, error)
	// FindByBusinessKey returns an announcement by (prefix, route_map, connector_id).
	// Returns nil (not error) if not found.
	FindByBusinessKey(ctx context.Context, prefix, routeMap string, connectorID int) (*BGPAnnouncement, error)

	// Attach atomically creates or updates an announcement to reflect a new
	// attack attachment. Returns the announcement's DB ID and an intent flag
	// that tells the caller whether to invoke vtysh announce outside the tx.
	//
	// Semantics:
	//   No existing row         → INSERT status='announcing', refcount=1 → NeedAnnounce=true
	//   Existing row (active)   → refcount++ → NeedAnnounce=false (already announced)
	//   Existing row (delayed)  → refcount++, status back to 'active' → NeedAnnounce=false (cancel delay)
	//   Existing row (withdrawn)→ resurrect: status='announcing', refcount=1 → NeedAnnounce=true
	//   Existing row (failed)   → resurrect: status='announcing', refcount=1 → NeedAnnounce=true
	Attach(ctx context.Context, params BGPAttachParams) (BGPAttachResult, error)

	// Detach atomically records an attack's detachment (sets detached_at)
	// and recomputes refcount + delay_minutes.
	//
	// Semantics:
	//   refcount > 0 after decrement  → NeedWithdraw=false (still in use)
	//   refcount == 0 + delay == 0    → status='withdrawing' → NeedWithdraw=true
	//   refcount == 0 + delay > 0     → status='delayed', delay_started_at=now → NeedWithdraw=false
	Detach(ctx context.Context, attackID int, prefix, routeMap string, connectorID int) (BGPDetachResult, error)

	// MarkAnnounced transitions announcing → active after a successful vtysh announce.
	MarkAnnounced(ctx context.Context, id int) error
	// MarkWithdrawing transitions active/delayed → withdrawing before vtysh no network.
	// Used on delay expiry to trigger the actual withdraw.
	MarkWithdrawing(ctx context.Context, id int) (bool, error)
	// MarkWithdrawn transitions withdrawing → withdrawn after a successful vtysh no network.
	MarkWithdrawn(ctx context.Context, id int) error
	// MarkFailedAnnounce handles compensation for announce failure. If refcount=1
	// (no concurrent attach), deletes the row; otherwise sets status=failed.
	MarkFailedAnnounce(ctx context.Context, id int, errMsg string) error
	// MarkFailedWithdraw sets status=failed on withdraw failure. Row kept for
	// operator retry via ForceWithdraw.
	MarkFailedWithdraw(ctx context.Context, id int, errMsg string) error

	// ForceWithdraw transitions any active/delayed/failed announcement to
	// withdrawing, detaching all attached attacks. Used by operator Force Withdraw.
	ForceWithdraw(ctx context.Context, id int) error

	// Dismiss transitions an orphan to dismissed (operator rejected).
	Dismiss(ctx context.Context, id int) error
	// Undismiss transitions a dismissed/dismissed_on_upgrade row back to orphan
	// so the operator can re-surface it in the warning banner after a mistaken
	// dismissal. FRR state is not touched (the route either still exists, in
	// which case orphan re-evaluation is correct, or it was withdrawn earlier
	// and the next bootstrap cycle will clean up the row).
	Undismiss(ctx context.Context, id int) error

	// ListActive returns announcements in active/delayed/failed/announcing/withdrawing status
	// for Mitigations UI. Excludes withdrawn (audit-only), orphan, dismissed*.
	ListActive(ctx context.Context) ([]BGPAnnouncement, error)
	// ListDismissed returns announcements in dismissed or dismissed_on_upgrade
	// status, sorted newest-first. Used by the "View dismissed orphans" UI.
	ListDismissed(ctx context.Context) ([]BGPAnnouncement, error)
	// ListByStatus is used by reconciliation.
	ListByStatus(ctx context.Context, status string) ([]BGPAnnouncement, error)

	// ListAttacks returns attacks attached to an announcement (both attached and detached).
	ListAttacks(ctx context.Context, announcementID int) ([]BGPAnnouncementAttack, error)

	// ListAttachmentsForAttack returns every announcement attachment record
	// for a given attack (across all announcements), ordered by attached_at
	// ASC. Used by mitigation-summary to enumerate which BGP announcements
	// an attack touched.
	ListAttachmentsForAttack(ctx context.Context, attackID int) ([]BGPAnnouncementAttack, error)

	// HasOperationalHistory reports whether any bgp_announcements row exists
	// that wasn't produced by the bootstrap scan itself. Used at startup to
	// decide whether to mark newly-discovered FRR drift as a silent
	// `dismissed_on_upgrade` (first-ever v1.2 boot) or a banner-visible
	// `orphan` (v1.2 has been running, FRR drifted).
	HasOperationalHistory(ctx context.Context) (bool, error)

	// CountByStatus returns the count of bgp_announcements grouped by
	// status. Used by the Prometheus xsight_bgp_announcements gauge; the
	// map key is the status string, value is the row count.
	CountByStatus(ctx context.Context) (map[string]int, error)

	// UpsertOrphan records one FRR-detected prefix as an orphan (or
	// dismissed_on_upgrade, depending on the caller's chosen status).
	// Semantics:
	//   No row for this business key        → INSERT status, refcount=0, return created=true
	//   Existing row with status='withdrawn'→ UPDATE to the new status, return created=true
	//   Existing row with any other status  → no-op, return created=false
	// The last case is what keeps the bootstrap safe to re-run: operator-
	// dismissed rows stay dismissed; active/delayed mitigations stay as they
	// are. created=true means the caller should log + audit; false = silent.
	UpsertOrphan(ctx context.Context, prefix, routeMap string, connectorID int, status string) (bool, error)

	// AppendEvent writes a timeline entry.
	AppendEvent(ctx context.Context, announcementID int, eventType string, attackID *int, detail string) error
	// ListEvents returns the timeline for an announcement.
	ListEvents(ctx context.Context, announcementID int) ([]BGPAnnouncementEvent, error)
}

// BGPAttachParams bundles the inputs to Attach. action_id / response_name /
// delay_minutes are per-attack snapshot fields; the announcement-level delay
// is recomputed inside the transaction from bgp_announcement_attacks.
type BGPAttachParams struct {
	AttackID     int
	ActionID     *int
	ResponseName string
	DelayMinutes int
	Prefix       string
	RouteMap     string
	ConnectorID  int
}

// BGPAttachResult tells the caller what side effect (if any) to execute
// outside the transaction.
type BGPAttachResult struct {
	AnnouncementID int
	NeedAnnounce   bool // caller must run vtysh announce and report back via MarkAnnounced/MarkFailedAnnounce
}

// BGPDetachResult tells the caller whether to invoke vtysh withdraw now
// (delay=0) or arm a delay timer (delay>0).
type BGPDetachResult struct {
	AnnouncementID int
	NeedWithdraw   bool
	Delayed        bool
	DelayMinutes   int
	// Refcount AFTER decrement. Useful for caller log messages.
	RefcountAfter int
}

// v1.2 PR-4: XDropActiveRuleRepo is the authoritative state for xDrop rules.
// Mitigations UI / mitigation-summary API read from this table instead of
// reverse-engineering state from action_execution_log.
type XDropActiveRuleRepo interface {
	// Upsert inserts a new row or updates an existing one (idempotent on the
	// business key). Used by executeXDrop and by reconciliation paths that
	// need to record an observed state without a full state machine.
	Upsert(ctx context.Context, r *XDropActiveRule) (int, error)
	// MarkWithdrawing transitions active/delayed → withdrawing before the
	// DELETE side effect. Returns false if the row is not in a transitioning
	// state (lets callers bail out — another goroutine got there first).
	MarkWithdrawing(ctx context.Context, attackID, actionID, connectorID int, externalRuleID string) (bool, error)
	// MarkWithdrawn is called after DELETE success (or 404 idempotent).
	MarkWithdrawn(ctx context.Context, attackID, actionID, connectorID int, externalRuleID string) error
	// MarkFailed sets status=failed with an error message.
	MarkFailed(ctx context.Context, attackID, actionID, connectorID int, externalRuleID, errMsg string) error
	// MarkDelayed records entry into delayed state (waiting for unblock_delay_minutes timer).
	MarkDelayed(ctx context.Context, attackID, actionID, connectorID int, externalRuleID string, delayMinutes int) error
	// ListActive returns rules in active/delayed/failed status for Mitigations UI.
	// withdrawn and withdrawing are excluded (withdrawn is audit-only;
	// withdrawing is an internal recovery state).
	ListActive(ctx context.Context) ([]XDropActiveRule, error)
	// ListWithdrawing returns rows stuck in withdrawing — called on startup
	// for crash recovery to retry the DELETE side effect.
	ListWithdrawing(ctx context.Context) ([]XDropActiveRule, error)
	// ListByAttack returns all rows for a given attack regardless of status.
	ListByAttack(ctx context.Context, attackID int) ([]XDropActiveRule, error)
	// CountByStatus returns the count of xdrop_active_rules grouped by
	// status. Used by the Prometheus xsight_xdrop_rules gauge.
	CountByStatus(ctx context.Context) (map[string]int, error)
}

// v1.2 PR-3: ScheduledActionRepo persists delayed withdraw/unblock tasks so
// they survive controller restarts. Solves the v1.1 bug where the in-memory
// pendingDelay map silently lost all pending tasks on crash or restart.
type ScheduledActionRepo interface {
	// Schedule inserts a new pending row. Idempotent: if a pending row already
	// exists for the same business key, returns the existing ID rather than
	// failing (ON CONFLICT DO UPDATE). This matches engine.ScheduleDelay being
	// called multiple times for the same artifact (e.g. re-dispatch).
	Schedule(ctx context.Context, a *ScheduledAction) (int, error)
	// Cancel marks a pending row as cancelled with the given reason.
	// No-op if the row is no longer pending.
	Cancel(ctx context.Context, id int, reason string) error
	// CancelByBusinessKey marks a pending row as cancelled by artifact key.
	// Used by CancelDelay when the caller doesn't hold the DB ID.
	CancelByBusinessKey(ctx context.Context, actionType string, attackID, actionID, connectorID int, externalRuleID, reason string) error
	// CancelAllForAttack cancels every pending schedule for the given attack.
	// Used by re-breach handling (CancelDelaysForAttack in engine).
	CancelAllForAttack(ctx context.Context, attackID int, reason string) (int, error)
	// MarkExecuting is called right before the action runs. Guards against
	// concurrent recovery goroutines racing to execute the same task.
	MarkExecuting(ctx context.Context, id int) error
	// Complete marks a row as successfully completed.
	Complete(ctx context.Context, id int) error
	// Fail marks a row as failed with the given error message.
	Fail(ctx context.Context, id int, errMsg string) error
	// ListPending returns all pending rows, ordered by scheduled_for ASC.
	// Called on startup to re-arm timers for surviving tasks.
	ListPending(ctx context.Context) ([]ScheduledAction, error)
	// ListExecuting returns rows stuck in 'executing' — called on startup
	// to reconcile tasks where the process crashed between MarkExecuting
	// and Complete/Fail. The underlying side effects are idempotent, so
	// retry is safe. Added in v1.2 PR-4 to close the PR-3 leftover edge case.
	ListExecuting(ctx context.Context) ([]ScheduledAction, error)
	// CountByStatus returns the count of scheduled_actions grouped by
	// status. Used by the Prometheus xsight_scheduled_actions gauge.
	CountByStatus(ctx context.Context) (map[string]int, error)
}

// v1.2 PR-2: ActionManualOverrideRepo provides O(1) lookup for manual override
// records, replacing the linear scan of action_execution_log in v1.1.
type ActionManualOverrideRepo interface {
	// Create inserts an override row. Idempotent: if the business key already
	// exists, returns the existing row's ID (not an error) — makes repeated
	// force-remove calls safe.
	Create(ctx context.Context, o *ActionManualOverride) (int, error)
	// Exists checks if a specific artifact has been overridden. O(1) via UNIQUE index.
	Exists(ctx context.Context, attackID, actionID, connectorID int, externalRuleID string) (bool, error)
	// ListByAttack returns all overrides for an attack — used for pre-fetching
	// a filter set before iterating many artifacts (bgp.go / xdrop.go).
	ListByAttack(ctx context.Context, attackID int) ([]ActionManualOverride, error)
}

// XDropTargetRepo manages the many-to-many join between actions and xDrop connectors.
type XDropTargetRepo interface {
	List(ctx context.Context, actionID int) ([]XDropConnector, error)
	Set(ctx context.Context, actionID int, connectorIDs []int) error
	CountByConnector(ctx context.Context, connectorID int) (int, error) // how many actions target this connector
}

// PreconditionRepo manages structured action preconditions.
type PreconditionRepo interface {
	List(ctx context.Context, actionID int) ([]ActionPrecondition, error)
	Create(ctx context.Context, p *ActionPrecondition) (int, error)
	Delete(ctx context.Context, id int) error
	DeleteByAction(ctx context.Context, actionID int) error
	ReplaceAll(ctx context.Context, actionID int, preconditions []ActionPrecondition) error
}

// FlowLogRepo handles flow log bulk writes and queries.
type FlowLogRepo interface {
	BulkInsert(ctx context.Context, flows []FlowLog) error
	QueryByDstIP(ctx context.Context, filter FlowLogFilter) ([]FlowLog, error)
	QueryBySrcIP(ctx context.Context, filter FlowLogFilter) ([]FlowLog, error)
}

// AuditLogRepo records and queries configuration change history.
type AuditLogRepo interface {
	Create(ctx context.Context, l *AuditLog) error
	List(ctx context.Context, filter AuditFilter) ([]AuditLog, error)
}

// v3.1: BGPConnectorRepo manages BGP connector (local FRR) configurations.
type BGPConnectorRepo interface {
	List(ctx context.Context) ([]BGPConnector, error)
	Get(ctx context.Context, id int) (*BGPConnector, error)
	Create(ctx context.Context, c *BGPConnector) (int, error)
	Update(ctx context.Context, c *BGPConnector) error
	Delete(ctx context.Context, id int) error
}

// v3.0: FlowListenerRepo manages flow listener configurations.
type FlowListenerRepo interface {
	List(ctx context.Context, nodeID string) ([]FlowListener, error)
	Get(ctx context.Context, id int) (*FlowListener, error)
	Create(ctx context.Context, l *FlowListener) (int, error)
	Update(ctx context.Context, l *FlowListener) error
	Delete(ctx context.Context, id int) error
}

// v3.0: FlowSourceRepo manages flow source (exporter device) configurations.
type FlowSourceRepo interface {
	List(ctx context.Context, listenerID int) ([]FlowSource, error)
	Get(ctx context.Context, id int) (*FlowSource, error)
	Create(ctx context.Context, s *FlowSource) (int, error)
	Update(ctx context.Context, s *FlowSource) error
	Delete(ctx context.Context, id int) error
}

// TimeseriesFilter for querying ts_stats.
type TimeseriesFilter struct {
	Prefix     string
	NodeID     string
	From       time.Time
	To         time.Time
	Resolution string // "5s" | "5min" | "1h" (ts_stats granularity is ~5s)
	Direction  string // "receives" | "sends" | "both" | "" (empty = receives)
	Limit      int
	// IncludeExtras controls whether the response TimeseriesPoints populate
	// ExtraDecoderPPS / ExtraDecoderBPS. Default false preserves the pre-v1.3.2
	// 12-field JSON shape; set to true when the caller (chart UI) wants the
	// 9 v1.3 decoders merged in. Applies to both raw ts_stats and CAGG paths.
	IncludeExtras bool
}

// TimeseriesPoint is a single aggregated time-series data point.
type TimeseriesPoint struct {
	Time      time.Time `json:"time"`
	PPS       int64     `json:"pps"`
	BPS       int64     `json:"bps"`
	TCPPPS    int32     `json:"tcp_pps"`
	TCPSynPPS int32     `json:"tcp_syn_pps"`
	UDPPPS    int32     `json:"udp_pps"`
	ICMPPPS   int32     `json:"icmp_pps"`
	FragPPS   int32     `json:"frag_pps,omitempty"`
	TCPBPS    int64     `json:"tcp_bps"`
	UDPBPS    int64     `json:"udp_bps"`
	ICMPBPS   int64     `json:"icmp_bps"`
	FragBPS   int64     `json:"frag_bps,omitempty"`
	// v1.3 Phase 1a: extra decoders (index >= StandardCount) live in JSONB.
	// Only populated when the DB row has non-NULL values. Key = decoder.Names[i].
	ExtraDecoderPPS map[string]int32 `json:"extra_decoder_pps,omitempty"`
	ExtraDecoderBPS map[string]int64 `json:"extra_decoder_bps,omitempty"`
}

// P95Result holds percentile-95 values for a (node, prefix) pair.
type P95Result struct {
	NodeID     string
	Prefix     string
	P95PPS     int64
	P95BPS     int64
	DataPoints int
}

// StatsRepo handles time-series data bulk writes and queries.
type StatsRepo interface {
	BulkInsert(ctx context.Context, points []StatPoint) error
	QueryTimeseries(ctx context.Context, filter TimeseriesFilter) ([]TimeseriesPoint, error)
	QueryTotalTimeseries(ctx context.Context, filter TimeseriesFilter) ([]TimeseriesPoint, error)
	// QueryHourP95 computes P95 PPS/BPS from ts_stats for a closed hour window [start, end).
	// minPoints: minimum data points required (SQL HAVING filter).
	QueryHourP95(ctx context.Context, start, end time.Time, minPoints int) ([]P95Result, error)
	// QueryWindowP95 computes P95 PPS/BPS from ts_stats for a rolling window [end-duration, end).
	// minPoints: minimum data points required (SQL HAVING filter).
	QueryWindowP95(ctx context.Context, end time.Time, duration time.Duration, minPoints int) ([]P95Result, error)
}
