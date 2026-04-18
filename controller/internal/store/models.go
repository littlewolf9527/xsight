// Package store defines domain models and repository interfaces for the Controller.
package store

import (
	"encoding/json"
	"time"

	"github.com/littlewolf9527/xsight/shared/decoder"
)

// Node represents a Node registered with the Controller.
type Node struct {
	ID                     string     `json:"id"`
	APIKey                 string     `json:"-"` // never expose
	Description            string     `json:"description"`
	Mode                   string     `json:"mode"` // "xdp" (default) | "flow" — v3.0
	Enabled                bool       `json:"enabled"`
	DeliveryVersionCurrent int64      `json:"delivery_version_current"`
	DeliveryVersionApplied int64      `json:"delivery_version_applied"`
	ConfigStatus           string     `json:"config_status"` // synced | pending | failed
	LastACKAt              *time.Time `json:"last_ack_at"`
	CreatedAt              time.Time  `json:"created_at"`
	UpdatedAt              time.Time  `json:"updated_at"`
}

// WatchPrefix represents a monitored CIDR prefix.
type WatchPrefix struct {
	ID                  int        `json:"id"`
	Prefix              string     `json:"prefix"` // CIDR notation, e.g. "103.21.244.0/24"
	ParentID            *int       `json:"parent_id"`
	ThresholdTemplateID *int       `json:"threshold_template_id"`
	Name                string     `json:"name"`
	IPGroup   string     `json:"ip_group"`
	Enabled   bool       `json:"enabled"`
	CreatedAt time.Time  `json:"created_at"`
	Children  []WatchPrefix `json:"children,omitempty"` // populated by tree queries, not stored
}

// ThresholdTemplate is a named collection of threshold rules.
type ThresholdTemplate struct {
	ID          int       `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	ResponseID  *int      `json:"response_id"`
	RuleCount   int       `json:"rule_count"`
	PrefixCount int       `json:"prefix_count"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// Threshold defines a detection rule bound to a template OR a prefix (XOR).
type Threshold struct {
	ID          int       `json:"id"`
	TemplateID  *int      `json:"template_id"`
	PrefixID    *int      `json:"prefix_id"`
	Domain      string    `json:"domain"`      // internal_ip | subnet
	Direction   string    `json:"direction"`    // receives | sends
	Decoder     string    `json:"decoder"`      // tcp_syn | udp | icmp | ip | tcp | fragment
	Unit        string    `json:"unit"`         // pps | bps
	Comparison  string    `json:"comparison"`   // over | under
	Value       int64     `json:"value"`        // 0 = cancel inheritance
	Inheritable bool      `json:"inheritable"`
	ResponseID  *int      `json:"response_id"`
	Enabled     bool      `json:"enabled"`
	CreatedAt   time.Time `json:"created_at"`
}

// Response is a named container for Actions triggered by a threshold.
type Response struct {
	ID                 int       `json:"id"`
	Name               string    `json:"name"`
	Description        string    `json:"description"`
	Enabled            bool      `json:"enabled"`
	ActionCount        int       `json:"action_count"`
	BoundTemplateCount int       `json:"bound_template_count"`
	CreatedAt          time.Time `json:"created_at"`
}

// ResponseAction is a single action within a Response.
type ResponseAction struct {
	ID              int              `json:"id"`
	ResponseID      int              `json:"response_id"`
	ActionType      string           `json:"action_type"`      // webhook | xdrop | shell
	ExecutionPolicy string           `json:"execution_policy"` // once_on_enter | periodic | retry_until_success | once_on_exit
	Priority        int              `json:"priority"`
	Config          json.RawMessage  `json:"config"`
	Preconditions   json.RawMessage  `json:"preconditions"`
	Enabled         bool             `json:"enabled"`

	// Response System v2 fields
	TriggerPhase       string           `json:"trigger_phase"`        // on_detect | on_end
	RunMode            string           `json:"run_mode"`             // once | periodic | retry
	PeriodSeconds      int              `json:"period_seconds"`
	Execution          string           `json:"execution"`            // automatic | manual
	WebhookConnectorID *int             `json:"webhook_connector_id"`
	ShellConnectorID   *int             `json:"shell_connector_id"`
	XDropAction         string           `json:"xdrop_action"`           // filter_l4 | rate_limit | unblock
	XDropCustomPayload  json.RawMessage  `json:"xdrop_custom_payload"`
	ShellExtraArgs      string           `json:"shell_extra_args"`
	UnblockDelayMinutes int              `json:"unblock_delay_minutes"`  // extra delay before unblock (xdrop), 0 = immediate
	BGPConnectorID           *int             `json:"bgp_connector_id"`
	BGPRouteMap              string           `json:"bgp_route_map"`
	BGPWithdrawDelayMinutes  int              `json:"bgp_withdraw_delay_minutes"` // extra delay before withdraw (bgp), 0 = immediate

	// v1.1: Auto-paired action support
	PairedWith      *int `json:"paired_with,omitempty"`      // on_detected → on_expired child ID (single-direction)
	AutoGenerated   bool `json:"auto_generated,omitempty"`   // true for system-created on_expired actions
}

// RuleWithAction pairs an external rule ID with the action and connector that created it.
// Used by unblock to delete rules only on the correct connector (prevents cross-connector deletion).
type RuleWithAction struct {
	RuleID      string
	ActionID    int
	ConnectorID int // xDrop connector that originally created this rule
}

// Webhook stores a webhook endpoint for event notifications.
type Webhook struct {
	ID      int             `json:"id"`
	URL     string          `json:"url"`
	Events  []string        `json:"events"` // attack_start, attack_end, etc.
	Headers json.RawMessage `json:"headers"`
	Enabled bool            `json:"enabled"`
}

// Attack represents a detected attack instance.
type Attack struct {
	ID            int        `json:"id"`
	DstIP         string     `json:"dst_ip"`
	PrefixID      *int       `json:"prefix_id"`
	Direction     string     `json:"direction"`
	DecoderFamily string     `json:"decoder_family"`
	AttackType    string     `json:"attack_type"`
	Severity      string     `json:"severity"`
	Confidence    float32    `json:"confidence"`
	PeakPPS       int64      `json:"peak_pps"`
	PeakBPS       int64      `json:"peak_bps"`
	ReasonCodes   []string   `json:"reason_codes"`
	NodeSources   []string   `json:"node_sources"`
	ResponseID      *int       `json:"response_id"`
	ThresholdRuleID *int       `json:"threshold_rule_id"`
	StartedAt       time.Time  `json:"started_at"`
	EndedAt         *time.Time `json:"ended_at"`
	CreatedAt       time.Time  `json:"created_at"`
	// Enriched fields (populated via JOIN, not stored)
	TemplateName *string `json:"template_name,omitempty"`
	RuleSummary  *string `json:"rule_summary,omitempty"`
}

// ActionLog tracks the execution history of a response action.
type ActionLog struct {
	ID              int       `json:"id"`
	AttackID        int       `json:"attack_id"`
	ActionID        int       `json:"action_id"`
	ExecutionPolicy string    `json:"execution_policy"`
	Status          string    `json:"status"` // pending | success | failed | retrying
	ExternalID      string    `json:"external_id"`
	FirstAttemptAt  time.Time `json:"first_attempt_at"`
	LastAttemptAt   time.Time `json:"last_attempt_at"`
	LastResult      string    `json:"last_result"`
	RetryCount      int       `json:"retry_count"`
	CreatedAt       time.Time `json:"created_at"`
}

// ──────────────── Response System v2 Connectors ────────────────

// WebhookConnector stores a webhook endpoint configuration.
type WebhookConnector struct {
	ID        int             `json:"id"`
	Name      string          `json:"name"`
	URL       string          `json:"url"`
	Method    string          `json:"method"`
	Headers   json.RawMessage `json:"headers"`
	TimeoutMs int             `json:"timeout_ms"`
	Global    bool            `json:"global"`
	Enabled   bool            `json:"enabled"`
	CreatedAt time.Time       `json:"created_at"`
	UpdatedAt time.Time       `json:"updated_at"`
}

// XDropConnector stores an xDrop Controller API endpoint.
type XDropConnector struct {
	ID        int       `json:"id"`
	Name      string    `json:"name"`
	APIURL    string    `json:"api_url"`
	APIKey    string    `json:"-"` // never expose in API responses
	TimeoutMs int       `json:"timeout_ms"`
	Enabled   bool      `json:"enabled"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// ShellConnector stores a shell script configuration.
type ShellConnector struct {
	ID          int       `json:"id"`
	Name        string    `json:"name"`
	Command     string    `json:"command"`
	DefaultArgs string    `json:"default_args"`
	TimeoutMs   int       `json:"timeout_ms"`
	PassStdin   bool      `json:"pass_stdin"`
	Enabled     bool      `json:"enabled"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// BGPConnector stores a local FRR BGP instance configuration.
type BGPConnector struct {
	ID             int       `json:"id"`
	Name           string    `json:"name"`
	VtyshPath      string    `json:"vtysh_path"`
	BGPASN         int       `json:"bgp_asn"`
	AddressFamily  string    `json:"address_family"`
	Enabled        bool      `json:"enabled"`
	Description    string    `json:"description"`
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt      time.Time `json:"updated_at"`
}

// ActionExecutionLog records the execution of a response action.
type ActionExecutionLog struct {
	ID             int        `json:"id"`
	AttackID       int        `json:"attack_id"`
	ActionID       int        `json:"action_id"`
	ResponseName   string     `json:"response_name"`
	ActionType     string     `json:"action_type"`
	ConnectorName  string     `json:"connector_name"`
	TriggerPhase   string     `json:"trigger_phase"`
	Status         string     `json:"status"` // success | failed | timeout | skipped
	StatusCode     *int       `json:"status_code"`
	ErrorMessage   string     `json:"error_message"`
	RequestBody    string     `json:"request_body"`
	ResponseBody   string     `json:"response_body"`
	ExternalRuleID string     `json:"external_rule_id"`
	ConnectorID    *int       `json:"connector_id"`     // xDrop connector that created this rule
	DurationMs     int        `json:"duration_ms"`
	ExecutedAt     time.Time  `json:"executed_at"`
	ScheduledFor   *time.Time `json:"scheduled_for,omitempty"` // v1.1: when delayed action will fire
	Detail         string     `json:"detail,omitempty"`        // v1.2: human-readable annotation (e.g. BGP attach/detach semantics)
	SkipReason     string     `json:"skip_reason,omitempty"`   // v1.2: structured cause when status='skipped'
}

// v1.2 PR-5: BGPAnnouncement is the refcount-managed lifecycle record for a
// single BGP route (prefix + route_map + connector). Replaces per-attack BGP
// withdraw with shared announcement: multiple attacks can attach to the same
// announcement, and only the last attack detaching triggers vtysh withdraw.
type BGPAnnouncement struct {
	ID             int        `json:"id"`
	Prefix         string     `json:"prefix"`
	RouteMap       string     `json:"route_map"`
	ConnectorID    int        `json:"connector_id"`
	FirstActionID  *int       `json:"first_action_id,omitempty"`
	Status         string     `json:"status"`
	Refcount       int        `json:"refcount"`
	AnnouncedAt    time.Time  `json:"announced_at"`
	DelayStartedAt *time.Time `json:"delay_started_at,omitempty"`
	DelayMinutes   int        `json:"delay_minutes"`
	WithdrawnAt    *time.Time `json:"withdrawn_at,omitempty"`
	ErrorMessage   string     `json:"error_message,omitempty"`
	CreatedAt      time.Time  `json:"created_at"`
}

// v1.2 PR-5: BGPAnnouncementAttack is an attack→announcement attachment.
// detach_at=NULL means "still attached" (contributes to refcount and MAX(delay_minutes)).
type BGPAnnouncementAttack struct {
	AnnouncementID int        `json:"announcement_id"`
	AttackID       int        `json:"attack_id"`
	ActionID       *int       `json:"action_id,omitempty"`
	ResponseName   string     `json:"response_name"`
	DelayMinutes   int        `json:"delay_minutes"`
	AttachedAt     time.Time  `json:"attached_at"`
	DetachedAt     *time.Time `json:"detached_at,omitempty"`
}

// v1.2 PR-5: BGPAnnouncementEvent is a timeline entry for the Mitigations
// Detail Drawer. Append-only audit of lifecycle transitions.
type BGPAnnouncementEvent struct {
	ID             int       `json:"id"`
	AnnouncementID int       `json:"announcement_id"`
	EventType      string    `json:"event_type"`
	AttackID       *int      `json:"attack_id,omitempty"`
	Detail         string    `json:"detail,omitempty"`
	CreatedAt      time.Time `json:"created_at"`
}

// v1.2 PR-5: Event type constants.
const (
	BGPEventAnnounced       = "announced"
	BGPEventAttackAttached  = "attack_attached"
	BGPEventAttackDetached  = "attack_detached"
	BGPEventDelayStarted    = "delay_started"
	BGPEventDelayCancelled  = "delay_cancelled"
	BGPEventWithdrawn       = "withdrawn"
	BGPEventWithdrawFailed  = "withdraw_failed"
	BGPEventAnnounceFailed  = "announce_failed"
	BGPEventOrphanDetected  = "orphan_detected"
	BGPEventDismissed       = "dismissed"
	BGPEventUndismissed     = "undismissed"
)

// v1.2 PR-4: XDropActiveRule is the authoritative state for a single xDrop
// filter rule. Replaces the v1.1 log-derivation in buildActiveActions.
//
// Status transitions:
//   active      — rule created successfully, in effect on the xDrop node
//   delayed     — on_expired queued with unblock_delay_minutes
//   withdrawing — DELETE in flight (crash recovery landmark: on startup,
//                 controller re-issues DELETE; 404 treated as idempotent success)
//   withdrawn   — unblock completed; kept for audit, filtered from Mitigations
//   failed      — create or unblock failed; surfaced in Mitigations
//
// Business key (attack_id, action_id, connector_id, external_rule_id)
// matches the other v1.2 tables (manual_overrides, scheduled_actions).
type XDropActiveRule struct {
	ID             int        `json:"id"`
	AttackID       int        `json:"attack_id"`
	ActionID       int        `json:"action_id"`
	ConnectorID    int        `json:"connector_id"`
	ExternalRuleID string     `json:"external_rule_id"`
	Status         string     `json:"status"`
	DelayStartedAt *time.Time `json:"delay_started_at,omitempty"`
	DelayMinutes   int        `json:"delay_minutes"`
	ErrorMessage   string     `json:"error_message,omitempty"`
	CreatedAt      time.Time  `json:"created_at"`
	WithdrawnAt    *time.Time `json:"withdrawn_at,omitempty"`
}

// v1.2 PR-3: ScheduledAction persists a pending delayed withdraw/unblock so
// the controller can re-arm timers after a restart. Replaces the v1.1
// in-memory pendingDelay map, which silently lost tasks on crash/restart.
//
// Status lifecycle:
//   pending  — timer armed (in memory + DB row)
//   executing — timer fired, action is running (DB set before side effect)
//   completed — action finished successfully
//   failed    — action finished with error (ErrorMessage populated)
//   cancelled — re-breach or manual cancellation (CancelReason populated)
//
// announcement_id is reserved for v1.2 PR-5 (BGP Announcement Manager).
// PR-3 always leaves it NULL and identifies tasks by the per-artifact key
// (attack_id, action_id, connector_id, external_rule_id).
type ScheduledAction struct {
	ID             int        `json:"id"`
	ActionType     string     `json:"action_type"` // xdrop_unblock | bgp_withdraw
	AttackID       int        `json:"attack_id"`
	ActionID       int        `json:"action_id"`
	ConnectorID    int        `json:"connector_id"`
	ExternalRuleID string     `json:"external_rule_id"`
	AnnouncementID *int       `json:"announcement_id,omitempty"` // v1.2 PR-5 reserved
	ScheduledFor   time.Time  `json:"scheduled_for"`
	Status         string     `json:"status"`
	CancelReason   string     `json:"cancel_reason,omitempty"`
	ErrorMessage   string     `json:"error_message,omitempty"`
	CreatedAt      time.Time  `json:"created_at"`
	CompletedAt    *time.Time `json:"completed_at,omitempty"`
}

// v1.2 PR-2: ActionManualOverride records that an operator force-removed a
// specific artifact (BGP route / xDrop rule), so the engine should not
// auto-execute the paired on_expired action for that same artifact.
// Business key (attack_id, action_id, connector_id, external_rule_id) is
// enforced by a UNIQUE index — `Exists()` is O(1) via that index, replacing
// the old linear scan of action_execution_log.
type ActionManualOverride struct {
	ID             int       `json:"id"`
	AttackID       int       `json:"attack_id"`
	ActionID       int       `json:"action_id"`
	ConnectorID    int       `json:"connector_id"`
	ExternalRuleID string    `json:"external_rule_id"`
	CreatedAt      time.Time `json:"created_at"`
	CreatedBy      string    `json:"created_by"`
}

// ActionPrecondition is a structured condition for filtering action execution.
type ActionPrecondition struct {
	ID        int       `json:"id"`
	ActionID  int       `json:"action_id"`
	Attribute string    `json:"attribute"`  // cidr, decoder, severity, pps, bps, node, domain, attack_type, tcp_syn_pct
	Operator  string    `json:"operator"`   // eq, neq, gt, lt, gte, lte, in
	Value     string    `json:"value"`      // "24", "tcp", "critical,high", "1000000"
	CreatedAt time.Time `json:"created_at"`
}

// User represents a Web UI user account.
type User struct {
	ID        int       `json:"id"`
	Username  string    `json:"username"`
	Password  string    `json:"-"` // bcrypt hash, never expose
	Role      string    `json:"role"` // admin | operator | viewer
	Enabled   bool      `json:"enabled"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// AuditLog records configuration changes for traceability.
type AuditLog struct {
	ID              int             `json:"id"`
	UserID          *int            `json:"user_id"`
	EntityType      string          `json:"entity_type"` // watch_prefix | threshold | response | ...
	EntityID        string          `json:"entity_id"`
	Action          string          `json:"action"` // create | update | delete
	Diff            json.RawMessage `json:"diff"`
	DeliveryVersion *int64          `json:"delivery_version"`
	CreatedAt       time.Time       `json:"created_at"`
}

// FlowCollector represents a flow data source (MVP-2).
type FlowCollector struct {
	ID               string    `json:"id"`
	Type             string    `json:"type"` // sflow | netflow
	Listen           string    `json:"listen"`
	Sources          []string  `json:"sources"`
	SamplingOverride int       `json:"sampling_override"`
	ForceSampling    bool      `json:"force_sampling"`
	Enabled          bool      `json:"enabled"`
	CreatedAt        time.Time `json:"created_at"`
	UpdatedAt        time.Time `json:"updated_at"`
}

// StatPoint is a single time-series data point for ts_stats.
// DecoderPPS is indexed by shared/decoder constants.
// Standard decoders (0-4) are written to ts_stats fixed columns;
// extra decoders (5+) go to extra_decoder_pps JSONB (future).
type StatPoint struct {
	Time       time.Time
	NodeID     string
	DstIP      *string // nil = prefix aggregate
	Prefix     *string
	Direction  string  // "receives" | "sends" (v2.11 Phase 3)
	PPS        int64
	BPS        int64
	DecoderPPS [decoder.MaxDecoders]int32 // indexed by decoder.TCP=0, decoder.TCPSyn=1, etc.
	DecoderBPS [decoder.MaxDecoders]int64 // indexed by decoder.TCP=0, etc. (per-decoder bits/sec)
}

// FlowLog is a single flow log entry for the flow_logs table.
type FlowLog struct {
	Time     time.Time `json:"time"`
	NodeID   string    `json:"node_id"`
	Prefix   *string   `json:"prefix"` // CIDR, nil if unmatched
	SrcIP    string    `json:"src_ip"`
	DstIP    string    `json:"dst_ip"`
	SrcPort  int       `json:"src_port"`
	DstPort  int       `json:"dst_port"`
	Protocol int       `json:"protocol"`
	TCPFlags int       `json:"tcp_flags"`
	Packets  int64     `json:"packets"`
	Bytes    int64     `json:"bytes"`
}

// v3.0: FlowListener represents a UDP listener for flow data collection.
type FlowListener struct {
	ID            int       `json:"id"`
	NodeID        string    `json:"node_id"`
	ListenAddress string    `json:"listen_address"`
	ProtocolMode  string    `json:"protocol_mode"` // "auto" | "sflow" | "netflow" | "ipfix"
	Enabled       bool      `json:"enabled"`
	Description   string    `json:"description"`
	CreatedAt     time.Time `json:"created_at"`
}

// v3.0: FlowSource represents an exporter device sending flow data to a listener.
type FlowSource struct {
	ID          int       `json:"id"`
	ListenerID  int       `json:"listener_id"`
	Name        string    `json:"name"`
	DeviceIP    string    `json:"device_ip"`
	SampleMode  string    `json:"sample_mode"` // "auto" | "force" | "none"
	SampleRate  int       `json:"sample_rate"`
	Description string    `json:"description"`
	Enabled     bool      `json:"enabled"`
	CreatedAt   time.Time `json:"created_at"`
}

// FlowLogFilter for querying flow_logs.
type FlowLogFilter struct {
	DstIP string
	From  time.Time
	To    time.Time
	Limit int
}

// AttackFilter for querying attacks.
type AttackFilter struct {
	Status    string // "active" | "expired" | "" (all)
	Direction string // "receives" | "sends" | "" (all)
	PrefixID  *int
	TimeFrom  *time.Time
	TimeTo    *time.Time
	Limit     int
	Offset    int
}

// AuditFilter for querying audit logs.
type AuditFilter struct {
	EntityType string
	UserID     *int
	TimeFrom   *time.Time
	TimeTo     *time.Time
	Limit      int
	Offset     int
}
