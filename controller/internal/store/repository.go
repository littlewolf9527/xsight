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
	TCPBPS    int64     `json:"tcp_bps"`
	UDPBPS    int64     `json:"udp_bps"`
	ICMPBPS   int64     `json:"icmp_bps"`
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
