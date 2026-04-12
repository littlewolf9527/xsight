// Package postgres implements the store.Store interface using PostgreSQL + TimescaleDB.
package postgres

import (
	"context"
	"fmt"
	"log"
	"strings"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/littlewolf9527/xsight/controller/internal/store"
)

// PGStore implements store.Store backed by PostgreSQL.
type PGStore struct {
	pool *pgxpool.Pool

	nodes      *nodeRepo
	prefixes   *prefixRepo
	templates  *templateRepo
	thresholds *thresholdRepo
	responses  *responseRepo
	attacks    *attackRepo
	actionsLog *actionsLogRepo
	users      *userRepo
	webhooks   *webhookRepo
	auditLog   *auditLogRepo
	stats      *statsRepo
	dynDetect  *dynDetectRepo

	// Response System v2 connectors
	webhookConnectors *webhookConnectorRepo
	xdropConnectors   *xdropConnectorRepo
	shellConnectors   *shellConnectorRepo
	actionExecLog     *actionExecLogRepo
	xdropTargets      *xdropTargetRepo
	preconditions     *preconditionRepo
	flowLogs          *flowLogRepo
	flowListeners     *flowListenerRepo
	flowSources       *flowSourceRepo
	bgpConnectors     *bgpConnectorRepo
	hasTimescale bool // true if TimescaleDB extension is available
}

func New(ctx context.Context, dsn string) (*PGStore, error) {
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return nil, fmt.Errorf("pgxpool: %w", err)
	}

	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("pg ping: %w", err)
	}

	s := &PGStore{pool: pool}
	s.nodes = &nodeRepo{pool: pool}
	s.prefixes = &prefixRepo{pool: pool}
	s.templates = &templateRepo{pool: pool}
	s.thresholds = &thresholdRepo{pool: pool}
	s.responses = &responseRepo{pool: pool}
	s.attacks = &attackRepo{pool: pool}
	s.actionsLog = &actionsLogRepo{pool: pool}
	s.users = &userRepo{pool: pool}
	s.webhooks = &webhookRepo{pool: pool}
	s.auditLog = &auditLogRepo{pool: pool}
	s.stats = &statsRepo{pool: pool}
	s.dynDetect = &dynDetectRepo{pool: pool}
	s.webhookConnectors = &webhookConnectorRepo{pool: pool}
	s.xdropConnectors = &xdropConnectorRepo{pool: pool}
	s.shellConnectors = &shellConnectorRepo{pool: pool}
	s.actionExecLog = &actionExecLogRepo{pool: pool}
	s.xdropTargets = &xdropTargetRepo{pool: pool}
	s.preconditions = &preconditionRepo{pool: pool}
	s.flowLogs = &flowLogRepo{pool: pool}
	s.flowListeners = &flowListenerRepo{pool: pool}
	s.flowSources = &flowSourceRepo{pool: pool}
	s.bgpConnectors = &bgpConnectorRepo{pool: pool}
	return s, nil
}

func (s *PGStore) Nodes() store.NodeRepo           { return s.nodes }
func (s *PGStore) Prefixes() store.PrefixRepo       { return s.prefixes }
func (s *PGStore) ThresholdTemplates() store.ThresholdTemplateRepo { return s.templates }
func (s *PGStore) Thresholds() store.ThresholdRepo                { return s.thresholds }
func (s *PGStore) Responses() store.ResponseRepo     { return s.responses }
func (s *PGStore) Attacks() store.AttackRepo         { return s.attacks }
func (s *PGStore) ActionsLog() store.ActionsLogRepo  { return s.actionsLog }
func (s *PGStore) Users() store.UserRepo             { return s.users }
func (s *PGStore) Webhooks() store.WebhookRepo       { return s.webhooks }
func (s *PGStore) AuditLog() store.AuditLogRepo      { return s.auditLog }
func (s *PGStore) Stats() store.StatsRepo            { return s.stats }
func (s *PGStore) DynDetect() store.DynDetectRepo    { return s.dynDetect }
// Response System v2 connectors
func (s *PGStore) WebhookConnectors() store.WebhookConnectorRepo { return s.webhookConnectors }
func (s *PGStore) XDropConnectors() store.XDropConnectorRepo     { return s.xdropConnectors }
func (s *PGStore) ShellConnectors() store.ShellConnectorRepo     { return s.shellConnectors }
func (s *PGStore) ActionExecLog() store.ActionExecLogRepo        { return s.actionExecLog }
func (s *PGStore) XDropTargets() store.XDropTargetRepo           { return s.xdropTargets }
func (s *PGStore) Preconditions() store.PreconditionRepo         { return s.preconditions }
func (s *PGStore) FlowLogs() store.FlowLogRepo                  { return s.flowLogs }
func (s *PGStore) FlowListeners() store.FlowListenerRepo        { return s.flowListeners }
func (s *PGStore) FlowSources() store.FlowSourceRepo            { return s.flowSources }
func (s *PGStore) BGPConnectors() store.BGPConnectorRepo         { return s.bgpConnectors }
func (s *PGStore) Close()                                        { s.pool.Close() }

// Pool exposes the underlying pgxpool for advanced operations (e.g. CopyFrom).
func (s *PGStore) Pool() *pgxpool.Pool { return s.pool }

// HasTimescale returns true if the TimescaleDB extension was successfully loaded.
// Used by the retention cleaner to skip row-level DELETEs on hypertables
// (TimescaleDB manages their lifecycle via chunk retention/compression policies).
func (s *PGStore) HasTimescale() bool { return s.hasTimescale }

// RetentionConfig holds retention and compression intervals for TimescaleDB policies.
type RetentionConfig struct {
	TSStatsDays          int // ts_stats retention (default 7)
	TSStatsCompressDays  int // ts_stats compression (default 1)
	TSStatsCaggDays      int // ts_stats_5min cagg retention (default 90)
	FlowLogsDays         int // flow_logs retention (default 7)
	FlowLogsCompressDays int // flow_logs compression (default 1)
}

// AutoMigrate creates all tables if they don't exist.
func (s *PGStore) AutoMigrate(ctx context.Context, ret RetentionConfig) error {
	// Try to enable TimescaleDB (non-fatal if not installed)
	_, err := s.pool.Exec(ctx, "CREATE EXTENSION IF NOT EXISTS timescaledb CASCADE")
	if err != nil {
		log.Printf("WARNING: TimescaleDB not available: %v (ts_stats will be a plain table)", err)
		s.hasTimescale = false
	} else {
		s.hasTimescale = true
	}

	for i, ddl := range migrations {
		if _, err := s.pool.Exec(ctx, ddl); err != nil {
			return fmt.Errorf("migration %d: %w\n  SQL: %s", i, err, firstLine(ddl))
		}
	}

	// TimescaleDB-specific DDL (non-fatal)
	for _, ddl := range timescaleMigrations {
		if _, err := s.pool.Exec(ctx, ddl); err != nil {
			log.Printf("WARNING: timescale DDL skipped: %v", err)
		}
	}

	// Continuous aggregate: ensure ts_stats_5min has all protocol columns.
	// If old cagg exists but lacks protocol columns, drop and recreate.
	s.ensureCagg(ctx)

	// Apply retention + compression policies from config (update if already exists)
	if ret.TSStatsDays > 0 {
		s.applyRetentionPolicy(ctx, "ts_stats", ret.TSStatsDays)
	}
	if ret.TSStatsCompressDays > 0 {
		s.applyCompressionPolicy(ctx, "ts_stats", ret.TSStatsCompressDays)
	}
	if ret.FlowLogsDays > 0 {
		s.applyRetentionPolicy(ctx, "flow_logs", ret.FlowLogsDays)
	}
	if ret.FlowLogsCompressDays > 0 {
		s.applyCompressionPolicy(ctx, "flow_logs", ret.FlowLogsCompressDays)
	}

	// Continuous aggregate refresh policy: keep last 12h materialized, refresh every 5min
	_, _ = s.pool.Exec(ctx, `SELECT remove_continuous_aggregate_policy('ts_stats_5min', if_exists => TRUE)`)
	_, err = s.pool.Exec(ctx, `SELECT add_continuous_aggregate_policy('ts_stats_5min',
		start_offset => INTERVAL '12 hours',
		end_offset   => INTERVAL '1 minute',
		schedule_interval => INTERVAL '5 minutes',
		if_not_exists => TRUE)`)
	if err != nil {
		log.Printf("WARNING: cagg refresh policy: %v", err)
	} else {
		log.Printf("cagg refresh policy: ts_stats_5min = 5min interval, 12h lookback")
	}

	// Continuous aggregate retention policy (separate from raw ts_stats retention)
	if ret.TSStatsCaggDays > 0 {
		s.applyRetentionPolicy(ctx, "ts_stats_5min", ret.TSStatsCaggDays)
	} else {
		// 0 = keep forever: explicitly remove any existing policy
		_, _ = s.pool.Exec(ctx, "SELECT remove_retention_policy('ts_stats_5min', if_exists => TRUE)")
	}

	return nil
}

// applyRetentionPolicy creates or updates a TimescaleDB retention policy.
func (s *PGStore) applyRetentionPolicy(ctx context.Context, table string, days int) {
	interval := fmt.Sprintf("%d days", days)
	// Remove existing policy first, then re-add with new interval
	_, _ = s.pool.Exec(ctx, fmt.Sprintf("SELECT remove_retention_policy('%s', if_exists => TRUE)", table))
	_, err := s.pool.Exec(ctx, fmt.Sprintf("SELECT add_retention_policy('%s', INTERVAL '%s', if_not_exists => TRUE)", table, interval))
	if err != nil {
		log.Printf("WARNING: retention policy for %s: %v", table, err)
	} else {
		log.Printf("retention policy: %s = %s", table, interval)
	}
}

// applyCompressionPolicy creates or updates a TimescaleDB compression policy.
func (s *PGStore) applyCompressionPolicy(ctx context.Context, table string, days int) {
	interval := fmt.Sprintf("%d days", days)
	_, _ = s.pool.Exec(ctx, fmt.Sprintf("SELECT remove_compression_policy('%s', if_exists => TRUE)", table))
	_, err := s.pool.Exec(ctx, fmt.Sprintf("SELECT add_compression_policy('%s', INTERVAL '%s', if_not_exists => TRUE)", table, interval))
	if err != nil {
		log.Printf("WARNING: compression policy for %s: %v", table, err)
	} else {
		log.Printf("compression policy: %s = %s", table, interval)
	}
}

// ensureCagg creates or upgrades the ts_stats_5min continuous aggregate.
// Must run outside DO $$ blocks because TimescaleDB forbids CREATE MATERIALIZED VIEW inside functions.
//
// Version history:
//   v1/v2: PPS only
//   v3: PPS + BPS protocol columns
//   v4: PPS + BPS + direction dimension (Phase 3)
func (s *PGStore) ensureCagg(ctx context.Context) {
	// Probe current cagg version by checking for specific columns
	var hasDirection bool
	err := s.pool.QueryRow(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM information_schema.columns
			WHERE table_name = 'ts_stats_5min' AND column_name = 'direction'
		)`).Scan(&hasDirection)
	if err != nil {
		log.Printf("WARNING: cagg check failed: %v", err)
		return
	}
	if hasDirection {
		return // cagg already v4 (with direction)
	}

	// Check if we need v3→v4 upgrade or fresh creation
	var hasBPS bool
	_ = s.pool.QueryRow(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM information_schema.columns
			WHERE table_name = 'ts_stats_5min' AND column_name = 'avg_tcp_bps'
		)`).Scan(&hasBPS)

	if hasBPS {
		log.Printf("cagg: upgrading ts_stats_5min from v3 to v4 (adding direction)")
	} else {
		log.Printf("cagg: creating ts_stats_5min v4 (fresh)")
	}

	// Drop old cagg and recreate with direction dimension
	// NOTE: this permanently loses cagg history beyond raw retention (7 days).
	// Accepted tradeoff — old cagg has no direction info anyway.
	_, _ = s.pool.Exec(ctx, `DROP MATERIALIZED VIEW IF EXISTS ts_stats_5min CASCADE`)

	// Create v4 cagg: prefix-only (WHERE dst_ip IS NULL) + direction dimension
	_, err = s.pool.Exec(ctx, `
		CREATE MATERIALIZED VIEW ts_stats_5min
		WITH (timescaledb.continuous) AS
		SELECT time_bucket('5 minutes', time) AS bucket,
			   node_id, prefix, direction,
			   avg(pps)::BIGINT AS avg_pps,
			   avg(bps)::BIGINT AS avg_bps,
			   avg(tcp_pps)::INT AS avg_tcp_pps,
			   avg(tcp_syn_pps)::INT AS avg_tcp_syn_pps,
			   avg(udp_pps)::INT AS avg_udp_pps,
			   avg(icmp_pps)::INT AS avg_icmp_pps,
			   avg(tcp_bps)::BIGINT AS avg_tcp_bps,
			   avg(udp_bps)::BIGINT AS avg_udp_bps,
			   avg(icmp_bps)::BIGINT AS avg_icmp_bps
		FROM ts_stats
		WHERE dst_ip IS NULL
		GROUP BY bucket, node_id, prefix, direction
		WITH NO DATA
	`)
	if err != nil {
		log.Printf("WARNING: cagg v4 create failed: %v", err)
		return
	}
	log.Printf("cagg: created ts_stats_5min v4 with direction dimension")

	// Synchronous backfill last 7 days (= raw retention window)
	_, err = s.pool.Exec(ctx, `CALL refresh_continuous_aggregate('ts_stats_5min', now() - INTERVAL '7 days', now() + INTERVAL '1 hour')`)
	if err != nil {
		log.Printf("cagg: backfill warning (non-fatal): %v", err)
	} else {
		log.Printf("cagg: backfilled last 7 days")
	}
}

func firstLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '\n'); i > 0 {
		return s[:i]
	}
	if len(s) > 80 {
		return s[:80] + "..."
	}
	return s
}

// Core table DDL — executed in order, idempotent (IF NOT EXISTS).
var migrations = []string{
	// Users
	`CREATE TABLE IF NOT EXISTS users (
		id          SERIAL PRIMARY KEY,
		username    TEXT NOT NULL UNIQUE,
		password    TEXT NOT NULL,
		role        TEXT NOT NULL DEFAULT 'viewer',
		enabled     BOOLEAN DEFAULT true,
		created_at  TIMESTAMPTZ DEFAULT now(),
		updated_at  TIMESTAMPTZ DEFAULT now()
	)`,

	// Nodes (XDP Node only, no type column — brainstorm decision)
	`CREATE TABLE IF NOT EXISTS nodes (
		id          TEXT PRIMARY KEY,
		api_key     TEXT NOT NULL,
		description TEXT DEFAULT '',
		enabled     BOOLEAN DEFAULT true,
		delivery_version_current  BIGINT DEFAULT 0,
		delivery_version_applied  BIGINT DEFAULT 0,
		config_status             TEXT DEFAULT 'pending',
		last_ack_at               TIMESTAMPTZ,
		created_at  TIMESTAMPTZ DEFAULT now(),
		updated_at  TIMESTAMPTZ DEFAULT now()
	)`,

	// Flow Collectors (MVP-2, separate table from nodes)
	`CREATE TABLE IF NOT EXISTS flow_collectors (
		id          TEXT PRIMARY KEY,
		type        TEXT NOT NULL,
		listen      TEXT NOT NULL,
		sources     TEXT[],
		sampling_override INTEGER DEFAULT 0,
		force_sampling    BOOLEAN DEFAULT false,
		enabled     BOOLEAN DEFAULT true,
		created_at  TIMESTAMPTZ DEFAULT now(),
		updated_at  TIMESTAMPTZ DEFAULT now()
	)`,

	// Responses (must be created before thresholds due to FK)
	`CREATE TABLE IF NOT EXISTS responses (
		id          SERIAL PRIMARY KEY,
		name        TEXT NOT NULL,
		description TEXT DEFAULT '',
		created_at  TIMESTAMPTZ DEFAULT now()
	)`,

	// Threshold Templates (borrowing Wanguard Threshold Template concept)
	`CREATE TABLE IF NOT EXISTS threshold_templates (
		id          SERIAL PRIMARY KEY,
		name        TEXT NOT NULL UNIQUE,
		description TEXT DEFAULT '',
		created_at  TIMESTAMPTZ DEFAULT now(),
		updated_at  TIMESTAMPTZ DEFAULT now()
	)`,

	// Watch Prefixes
	`CREATE TABLE IF NOT EXISTS watch_prefixes (
		id          SERIAL PRIMARY KEY,
		prefix      CIDR NOT NULL,
		parent_id   INTEGER REFERENCES watch_prefixes(id) ON DELETE SET NULL,
		threshold_template_id INTEGER REFERENCES threshold_templates(id) ON DELETE RESTRICT,
		name        TEXT DEFAULT '',
		ip_group    TEXT DEFAULT '',
		enabled     BOOLEAN DEFAULT true,
		created_at  TIMESTAMPTZ DEFAULT now()
	)`,

	// Thresholds — belong to either a template OR a prefix (XOR)
	`CREATE TABLE IF NOT EXISTS thresholds (
		id          SERIAL PRIMARY KEY,
		template_id INTEGER REFERENCES threshold_templates(id) ON DELETE CASCADE,
		prefix_id   INTEGER REFERENCES watch_prefixes(id) ON DELETE CASCADE,
		domain      TEXT NOT NULL,
		direction   TEXT NOT NULL DEFAULT 'receives',
		decoder     TEXT NOT NULL,
		unit        TEXT NOT NULL,
		comparison  TEXT NOT NULL DEFAULT 'over',
		value       BIGINT NOT NULL,
		inheritable BOOLEAN DEFAULT true,
		response_id INTEGER REFERENCES responses(id) ON DELETE SET NULL,
		enabled     BOOLEAN DEFAULT true,
		created_at  TIMESTAMPTZ DEFAULT now()
	)`,
	// Incremental migration: add template_id to existing thresholds table
	`DO $$ BEGIN
		ALTER TABLE thresholds ADD COLUMN template_id INTEGER REFERENCES threshold_templates(id) ON DELETE CASCADE;
	EXCEPTION WHEN duplicate_column THEN NULL; END $$`,
	// Make prefix_id nullable (was NOT NULL implicitly in original CREATE)
	`ALTER TABLE thresholds ALTER COLUMN prefix_id DROP NOT NULL`,
	// XOR constraint: template_id and prefix_id exactly one non-NULL
	`DO $$ BEGIN
		ALTER TABLE thresholds ADD CONSTRAINT thresholds_owner_xor
			CHECK ((template_id IS NOT NULL) != (prefix_id IS NOT NULL));
	EXCEPTION WHEN duplicate_object THEN NULL; END $$`,
	// Incremental: add threshold_template_id to watch_prefixes
	`DO $$ BEGIN
		ALTER TABLE watch_prefixes ADD COLUMN threshold_template_id INTEGER REFERENCES threshold_templates(id) ON DELETE RESTRICT;
	EXCEPTION WHEN duplicate_column THEN NULL; END $$`,

	// Response Actions
	`CREATE TABLE IF NOT EXISTS response_actions (
		id               SERIAL PRIMARY KEY,
		response_id      INTEGER REFERENCES responses(id) ON DELETE CASCADE,
		action_type      TEXT NOT NULL,
		execution_policy TEXT NOT NULL DEFAULT 'once_on_enter',
		priority         INTEGER DEFAULT 0,
		config           JSONB NOT NULL DEFAULT '{}',
		preconditions    JSONB,
		enabled          BOOLEAN DEFAULT true
	)`,

	// Webhooks
	`CREATE TABLE IF NOT EXISTS webhooks (
		id          SERIAL PRIMARY KEY,
		url         TEXT NOT NULL,
		events      TEXT[] NOT NULL DEFAULT '{}',
		headers     JSONB,
		enabled     BOOLEAN DEFAULT true
	)`,

	// Attacks
	`CREATE TABLE IF NOT EXISTS attacks (
		id              SERIAL PRIMARY KEY,
		dst_ip          INET NOT NULL,
		prefix_id       INTEGER REFERENCES watch_prefixes(id) ON DELETE SET NULL,
		direction       TEXT NOT NULL DEFAULT 'receives',
		decoder_family  TEXT NOT NULL,
		attack_type     TEXT DEFAULT '',
		severity        TEXT DEFAULT '',
		confidence      REAL DEFAULT 0,
		peak_pps        BIGINT DEFAULT 0,
		peak_bps        BIGINT DEFAULT 0,
		reason_codes    TEXT[] DEFAULT '{}',
		node_sources    TEXT[] DEFAULT '{}',
		response_id     INTEGER REFERENCES responses(id) ON DELETE SET NULL,
		started_at      TIMESTAMPTZ NOT NULL,
		ended_at        TIMESTAMPTZ,
		created_at      TIMESTAMPTZ DEFAULT now()
	)`,

	// Actions Log
	`CREATE TABLE IF NOT EXISTS actions_log (
		id              SERIAL PRIMARY KEY,
		attack_id       INTEGER REFERENCES attacks(id) ON DELETE CASCADE,
		action_id       INTEGER REFERENCES response_actions(id) ON DELETE SET NULL,
		execution_policy TEXT NOT NULL,
		status          TEXT NOT NULL,
		external_id     TEXT DEFAULT '',
		first_attempt_at TIMESTAMPTZ NOT NULL,
		last_attempt_at  TIMESTAMPTZ NOT NULL,
		last_result     TEXT DEFAULT '',
		retry_count     INTEGER DEFAULT 0,
		created_at      TIMESTAMPTZ DEFAULT now()
	)`,

	// Time-series stats (plain table; TimescaleDB hypertable applied separately)
	`CREATE TABLE IF NOT EXISTS ts_stats (
		time        TIMESTAMPTZ NOT NULL,
		node_id     TEXT NOT NULL,
		dst_ip      INET,
		prefix      CIDR,
		pps         BIGINT DEFAULT 0,
		bps         BIGINT DEFAULT 0,
		tcp_pps     INTEGER DEFAULT 0,
		tcp_syn_pps INTEGER DEFAULT 0,
		udp_pps     INTEGER DEFAULT 0,
		icmp_pps    INTEGER DEFAULT 0,
		frag_pps    INTEGER DEFAULT 0,
		tcp_bps     BIGINT DEFAULT 0,
		udp_bps     BIGINT DEFAULT 0,
		icmp_bps    BIGINT DEFAULT 0
	)`,

	// Per-decoder BPS columns (v2.10.x)
	`DO $$ BEGIN ALTER TABLE ts_stats ADD COLUMN tcp_bps BIGINT DEFAULT 0; EXCEPTION WHEN duplicate_column THEN NULL; END $$`,
	`DO $$ BEGIN ALTER TABLE ts_stats ADD COLUMN udp_bps BIGINT DEFAULT 0; EXCEPTION WHEN duplicate_column THEN NULL; END $$`,
	`DO $$ BEGIN ALTER TABLE ts_stats ADD COLUMN icmp_bps BIGINT DEFAULT 0; EXCEPTION WHEN duplicate_column THEN NULL; END $$`,

	// v2.11 Phase 3: direction column for bidirectional time series
	`DO $$ BEGIN ALTER TABLE ts_stats ADD COLUMN direction TEXT NOT NULL DEFAULT 'receives'; EXCEPTION WHEN duplicate_column THEN NULL; END $$`,

	// Config audit log
	`CREATE TABLE IF NOT EXISTS config_audit_log (
		id              SERIAL PRIMARY KEY,
		user_id         INTEGER REFERENCES users(id) ON DELETE SET NULL,
		entity_type     TEXT NOT NULL,
		entity_id       TEXT NOT NULL,
		action          TEXT NOT NULL,
		diff            JSONB,
		delivery_version BIGINT,
		created_at      TIMESTAMPTZ DEFAULT now()
	)`,

	// Dynamic detection config (singleton row)
	`CREATE TABLE IF NOT EXISTS dynamic_detection_config (
		id                INT PRIMARY KEY DEFAULT 1 CHECK (id = 1),
		enabled           BOOLEAN DEFAULT false,
		deviation_min     INT DEFAULT 100,
		deviation_max     INT DEFAULT 200,
		stable_weeks      INT DEFAULT 4,
		min_pps           BIGINT DEFAULT 100000,
		min_bps           BIGINT DEFAULT 1000000000,
		ewma_alpha        REAL DEFAULT 0.3,
		updated_at        TIMESTAMPTZ DEFAULT now()
	)`,
	`INSERT INTO dynamic_detection_config (id) VALUES (1) ON CONFLICT DO NOTHING`,

	// Prefix traffic profiles (per node, prefix, time slot)
	`CREATE TABLE IF NOT EXISTS prefix_profiles (
		node_id          TEXT NOT NULL,
		prefix           CIDR NOT NULL,
		slot_index       INT NOT NULL,
		expected_pps     BIGINT DEFAULT 0,
		expected_bps     BIGINT DEFAULT 0,
		sample_weeks     INT DEFAULT 0,
		last_sample_yw   INT DEFAULT 0,
		updated_at       TIMESTAMPTZ DEFAULT now(),
		PRIMARY KEY (node_id, prefix, slot_index)
	)`,

	// Responses: add enabled column
	`DO $$ BEGIN
		ALTER TABLE responses ADD COLUMN enabled BOOLEAN DEFAULT true;
	EXCEPTION WHEN duplicate_column THEN NULL; END $$`,

	// ──────────────── Response System v2 (connector tables) ────────────────

	// Webhook Connectors (replaces old webhooks table for response-bound usage)
	`CREATE TABLE IF NOT EXISTS webhook_connectors (
		id          SERIAL PRIMARY KEY,
		name        TEXT NOT NULL UNIQUE,
		url         TEXT NOT NULL,
		method      TEXT DEFAULT 'POST',
		headers     JSONB DEFAULT '{}',
		timeout_ms  INT DEFAULT 5000,
		global      BOOLEAN DEFAULT false,
		enabled     BOOLEAN DEFAULT true,
		created_at  TIMESTAMPTZ DEFAULT now(),
		updated_at  TIMESTAMPTZ DEFAULT now()
	)`,

	// xDrop Connectors
	`CREATE TABLE IF NOT EXISTS xdrop_connectors (
		id          SERIAL PRIMARY KEY,
		name        TEXT NOT NULL UNIQUE,
		api_url     TEXT NOT NULL,
		api_key     TEXT NOT NULL,
		timeout_ms  INT DEFAULT 5000,
		enabled     BOOLEAN DEFAULT true,
		created_at  TIMESTAMPTZ DEFAULT now(),
		updated_at  TIMESTAMPTZ DEFAULT now()
	)`,

	// Shell Connectors
	`CREATE TABLE IF NOT EXISTS shell_connectors (
		id              SERIAL PRIMARY KEY,
		name            TEXT NOT NULL UNIQUE,
		command         TEXT NOT NULL,
		default_args    TEXT DEFAULT '',
		timeout_ms      INT DEFAULT 30000,
		pass_stdin      BOOLEAN DEFAULT true,
		enabled         BOOLEAN DEFAULT true,
		created_at      TIMESTAMPTZ DEFAULT now(),
		updated_at      TIMESTAMPTZ DEFAULT now()
	)`,

	// Response Actions v2: typed connector FKs + trigger_phase + run_mode
	`DO $$ BEGIN
		ALTER TABLE response_actions ADD COLUMN trigger_phase TEXT NOT NULL DEFAULT 'on_detected';
	EXCEPTION WHEN duplicate_column THEN NULL; END $$`,
	`DO $$ BEGIN
		ALTER TABLE response_actions ADD COLUMN run_mode TEXT NOT NULL DEFAULT 'once';
	EXCEPTION WHEN duplicate_column THEN NULL; END $$`,
	`DO $$ BEGIN
		ALTER TABLE response_actions ADD COLUMN period_seconds INT DEFAULT 0;
	EXCEPTION WHEN duplicate_column THEN NULL; END $$`,
	`DO $$ BEGIN
		ALTER TABLE response_actions ADD COLUMN execution TEXT DEFAULT 'automatic';
	EXCEPTION WHEN duplicate_column THEN NULL; END $$`,
	`DO $$ BEGIN
		ALTER TABLE response_actions ADD COLUMN webhook_connector_id INT REFERENCES webhook_connectors(id);
	EXCEPTION WHEN duplicate_column THEN NULL; END $$`,
	`DO $$ BEGIN
		ALTER TABLE response_actions ADD COLUMN shell_connector_id INT REFERENCES shell_connectors(id);
	EXCEPTION WHEN duplicate_column THEN NULL; END $$`,
	`DO $$ BEGIN
		ALTER TABLE response_actions ADD COLUMN xdrop_action TEXT DEFAULT '';
	EXCEPTION WHEN duplicate_column THEN NULL; END $$`,
	`DO $$ BEGIN
		ALTER TABLE response_actions ADD COLUMN xdrop_custom_payload JSONB;
	EXCEPTION WHEN duplicate_column THEN NULL; END $$`,
	`DO $$ BEGIN
		ALTER TABLE response_actions ADD COLUMN shell_extra_args TEXT DEFAULT '';
	EXCEPTION WHEN duplicate_column THEN NULL; END $$`,

	// Action Preconditions (structured, replaces old JSONB preconditions)
	`CREATE TABLE IF NOT EXISTS action_preconditions (
		id              SERIAL PRIMARY KEY,
		action_id       INT NOT NULL REFERENCES response_actions(id) ON DELETE CASCADE,
		attribute       TEXT NOT NULL,
		operator        TEXT NOT NULL,
		value           TEXT NOT NULL,
		created_at      TIMESTAMPTZ DEFAULT now()
	)`,

	// Connector integrity: for NEW v2 actions with connector FKs set.
	// Legacy rows (both FKs NULL, using old config JSONB) are allowed.
	`DO $$ BEGIN
		ALTER TABLE response_actions ADD CONSTRAINT connector_integrity CHECK (
			CASE action_type
				WHEN 'xdrop' THEN webhook_connector_id IS NULL AND shell_connector_id IS NULL
				ELSE num_nonnulls(webhook_connector_id, shell_connector_id) <= 1
			END
		);
	EXCEPTION WHEN duplicate_object THEN NULL; END $$`,

	// Unblock delay (v2.10.1): extra delay before executing unblock action
	`DO $$ BEGIN
		ALTER TABLE response_actions ADD COLUMN unblock_delay_minutes INT DEFAULT 0;
	EXCEPTION WHEN duplicate_column THEN NULL; END $$`,
	`DO $$ BEGIN
		ALTER TABLE response_actions ADD CONSTRAINT unblock_delay_range CHECK (unblock_delay_minutes >= 0 AND unblock_delay_minutes <= 1440);
	EXCEPTION WHEN duplicate_object THEN NULL; END $$`,

	// xDrop Action targets (many-to-many join table)
	`CREATE TABLE IF NOT EXISTS response_action_xdrop_targets (
		action_id       INT NOT NULL REFERENCES response_actions(id) ON DELETE CASCADE,
		connector_id    INT NOT NULL REFERENCES xdrop_connectors(id) ON DELETE CASCADE,
		PRIMARY KEY (action_id, connector_id)
	)`,

	// Action Execution Log v2 (replaces actions_log)
	`CREATE TABLE IF NOT EXISTS action_execution_log (
		id              SERIAL PRIMARY KEY,
		attack_id       INT NOT NULL,
		action_id       INT NOT NULL,
		response_name   TEXT,
		action_type     TEXT,
		connector_name  TEXT,
		trigger_phase   TEXT,
		status          TEXT NOT NULL,
		status_code     INT,
		error_message   TEXT,
		request_body    TEXT,
		response_body   TEXT,
		external_rule_id TEXT,
		duration_ms     INT,
		executed_at     TIMESTAMPTZ DEFAULT now()
	)`,

	// Connector ID on action_execution_log (v2.10.x): bind xDrop rules to specific connector
	`DO $$ BEGIN
		ALTER TABLE action_execution_log ADD COLUMN connector_id INT;
	EXCEPTION WHEN duplicate_column THEN NULL; END $$`,

	// Thresholds: add per-rule response binding
	`DO $$ BEGIN
		ALTER TABLE thresholds ADD COLUMN response_id INTEGER REFERENCES responses(id) ON DELETE SET NULL;
	EXCEPTION WHEN duplicate_column THEN NULL; END $$`,

	// Attacks: track which threshold rule triggered the attack
	`DO $$ BEGIN
		ALTER TABLE attacks ADD COLUMN threshold_rule_id INTEGER REFERENCES thresholds(id) ON DELETE SET NULL;
	EXCEPTION WHEN duplicate_column THEN NULL; END $$`,

	// Threshold templates: add default response binding
	`DO $$ BEGIN
		ALTER TABLE threshold_templates ADD COLUMN response_id INTEGER REFERENCES responses(id) ON DELETE SET NULL;
	EXCEPTION WHEN duplicate_column THEN NULL; END $$`,

	// Migrate old global webhooks to webhook_connectors
	`INSERT INTO webhook_connectors (name, url, global, enabled)
	 SELECT 'legacy-webhook-' || id, url, true, enabled FROM webhooks
	 WHERE NOT EXISTS (SELECT 1 FROM webhook_connectors WHERE name = 'legacy-webhook-' || webhooks.id)
	 ON CONFLICT DO NOTHING`,

	// Flow logs (top-N flow samples per tick, high volume)
	`CREATE TABLE IF NOT EXISTS flow_logs (
		time        TIMESTAMPTZ NOT NULL,
		node_id     TEXT NOT NULL,
		prefix      CIDR,
		src_ip      INET NOT NULL,
		dst_ip      INET NOT NULL,
		src_port    INT,
		dst_port    INT,
		protocol    SMALLINT,
		tcp_flags   SMALLINT,
		packets     BIGINT,
		bytes       BIGINT
	)`,
	`CREATE INDEX IF NOT EXISTS idx_flow_logs_time ON flow_logs (time)`,
	`CREATE INDEX IF NOT EXISTS idx_flow_logs_dst_ip ON flow_logs (dst_ip)`,
	`CREATE INDEX IF NOT EXISTS idx_flow_logs_src_ip ON flow_logs (src_ip)`,

	// Indexes
	`CREATE INDEX IF NOT EXISTS idx_attacks_active ON attacks (started_at) WHERE ended_at IS NULL`,
	`CREATE INDEX IF NOT EXISTS idx_attacks_dst_ip ON attacks (dst_ip)`,
	`CREATE INDEX IF NOT EXISTS idx_ts_stats_time ON ts_stats (time)`,
	`CREATE INDEX IF NOT EXISTS idx_ts_stats_prefix_gist ON ts_stats USING gist (prefix inet_ops)`,
	`CREATE INDEX IF NOT EXISTS idx_ts_stats_time_prefix_only ON ts_stats (time) WHERE dst_ip IS NULL`,
	`CREATE INDEX IF NOT EXISTS idx_thresholds_prefix ON thresholds (prefix_id)`,
	`CREATE INDEX IF NOT EXISTS idx_thresholds_template ON thresholds (template_id) WHERE template_id IS NOT NULL`,
	`CREATE UNIQUE INDEX IF NOT EXISTS idx_thresholds_template_key ON thresholds (template_id, decoder, unit, direction, domain) WHERE template_id IS NOT NULL`,
	`CREATE UNIQUE INDEX IF NOT EXISTS idx_thresholds_prefix_key ON thresholds (prefix_id, decoder, unit, direction, domain) WHERE prefix_id IS NOT NULL`,
	`CREATE INDEX IF NOT EXISTS idx_prefixes_template ON watch_prefixes (threshold_template_id) WHERE threshold_template_id IS NOT NULL`,
	`CREATE INDEX IF NOT EXISTS idx_config_audit_log_entity ON config_audit_log (entity_type, entity_id)`,
	`CREATE INDEX IF NOT EXISTS idx_config_audit_log_time ON config_audit_log (created_at)`,

	// v3.0: Flow listeners + sources (two-layer model)
	`CREATE TABLE IF NOT EXISTS flow_listeners (
		id              SERIAL PRIMARY KEY,
		node_id         TEXT NOT NULL,
		listen_address  TEXT NOT NULL,
		protocol_mode   TEXT NOT NULL DEFAULT 'auto',
		enabled         BOOLEAN DEFAULT true,
		description     TEXT DEFAULT '',
		created_at      TIMESTAMPTZ DEFAULT now(),
		UNIQUE(node_id, listen_address)
	)`,
	`CREATE TABLE IF NOT EXISTS flow_sources (
		id              SERIAL PRIMARY KEY,
		listener_id     INT NOT NULL REFERENCES flow_listeners(id) ON DELETE CASCADE,
		name            TEXT NOT NULL,
		device_ip       INET NOT NULL,
		sample_mode     TEXT NOT NULL DEFAULT 'auto',
		sample_rate     INT DEFAULT 0,
		description     TEXT DEFAULT '',
		enabled         BOOLEAN DEFAULT true,
		created_at      TIMESTAMPTZ DEFAULT now(),
		UNIQUE(listener_id, device_ip)
	)`,
	// v3.0: add mode column to nodes (xdp default, backward compatible)
	`ALTER TABLE nodes ADD COLUMN IF NOT EXISTS mode TEXT NOT NULL DEFAULT 'xdp'`,
	`DO $$ BEGIN
		ALTER TABLE nodes ADD CONSTRAINT chk_node_mode CHECK (mode IN ('xdp','flow'));
	EXCEPTION WHEN duplicate_object THEN NULL;
	END $$`,

	`CREATE INDEX IF NOT EXISTS idx_flow_listeners_node ON flow_listeners (node_id)`,
	`CREATE INDEX IF NOT EXISTS idx_flow_sources_listener ON flow_sources (listener_id)`,

	// v3.1: BGP Connectors
	`CREATE TABLE IF NOT EXISTS bgp_connectors (
		id              SERIAL PRIMARY KEY,
		name            TEXT NOT NULL UNIQUE,
		vtysh_path      TEXT NOT NULL DEFAULT '/usr/bin/vtysh',
		bgp_asn         INT NOT NULL,
		address_family  TEXT NOT NULL DEFAULT 'auto',
		enabled         BOOLEAN DEFAULT true,
		description     TEXT DEFAULT '',
		created_at      TIMESTAMPTZ DEFAULT now(),
		updated_at      TIMESTAMPTZ DEFAULT now()
	)`,
	// BGP action fields on response_actions
	`DO $$ BEGIN ALTER TABLE response_actions ADD COLUMN bgp_connector_id INT REFERENCES bgp_connectors(id) ON DELETE SET NULL; EXCEPTION WHEN duplicate_column THEN NULL; END $$`,
	`DO $$ BEGIN ALTER TABLE response_actions ADD COLUMN bgp_route_map TEXT NOT NULL DEFAULT ''; EXCEPTION WHEN duplicate_column THEN NULL; END $$`,
	// Update connector_integrity constraint to include bgp
	`ALTER TABLE response_actions DROP CONSTRAINT IF EXISTS connector_integrity`,
	`DO $$ BEGIN
		ALTER TABLE response_actions ADD CONSTRAINT connector_integrity CHECK (
			CASE action_type
				WHEN 'xdrop' THEN webhook_connector_id IS NULL AND shell_connector_id IS NULL AND bgp_connector_id IS NULL
				WHEN 'bgp' THEN webhook_connector_id IS NULL AND shell_connector_id IS NULL
				ELSE num_nonnulls(webhook_connector_id, shell_connector_id, bgp_connector_id) <= 1
			END
		);
	EXCEPTION WHEN duplicate_object THEN NULL; END $$`,

	// Attacks: snapshot template_name and rule_summary at detection time
	`DO $$ BEGIN ALTER TABLE attacks ADD COLUMN template_name TEXT; EXCEPTION WHEN duplicate_column THEN NULL; END $$`,
	`DO $$ BEGIN ALTER TABLE attacks ADD COLUMN rule_summary TEXT; EXCEPTION WHEN duplicate_column THEN NULL; END $$`,

	// v1.1: Auto-paired actions — single-direction parent→child link
	`DO $$ BEGIN ALTER TABLE response_actions ADD COLUMN paired_with INT REFERENCES response_actions(id) ON DELETE SET NULL; EXCEPTION WHEN duplicate_column THEN NULL; END $$`,
	`DO $$ BEGIN ALTER TABLE response_actions ADD COLUMN auto_generated BOOLEAN NOT NULL DEFAULT false; EXCEPTION WHEN duplicate_column THEN NULL; END $$`,

	// v1.1: BGP withdraw delay (same semantics as xDrop unblock_delay_minutes)
	`DO $$ BEGIN ALTER TABLE response_actions ADD COLUMN bgp_withdraw_delay_minutes INT NOT NULL DEFAULT 0; EXCEPTION WHEN duplicate_column THEN NULL; END $$`,
	`DO $$ BEGIN
		ALTER TABLE response_actions ADD CONSTRAINT bgp_withdraw_delay_range CHECK (bgp_withdraw_delay_minutes >= 0 AND bgp_withdraw_delay_minutes <= 1440);
	EXCEPTION WHEN duplicate_object THEN NULL; END $$`,

	// v1.1: Delayed action scheduling timestamp for UI countdown + startup recovery
	`DO $$ BEGIN ALTER TABLE action_execution_log ADD COLUMN scheduled_for TIMESTAMPTZ; EXCEPTION WHEN duplicate_column THEN NULL; END $$`,
}

// TimescaleDB-specific DDL — non-fatal if TimescaleDB is not available.
var timescaleMigrations = []string{
	// Convert ts_stats to hypertable
	`SELECT create_hypertable('ts_stats', 'time', if_not_exists => TRUE)`,

	// NOTE: Continuous aggregate migration is handled in AutoMigrate() Go code
	// because TimescaleDB cannot CREATE MATERIALIZED VIEW inside DO $$ blocks.

	// Enable compression on the hypertable (must be done before adding compression policy)
	`ALTER TABLE ts_stats SET (
		timescaledb.compress,
		timescaledb.compress_segmentby = 'node_id,prefix,direction'
	)`,

	// Compression policy is now applied dynamically from config in AutoMigrate()

	// Retention policies are now applied dynamically from config in AutoMigrate()

	// flow_logs hypertable (high volume, compressed)
	`SELECT create_hypertable('flow_logs', 'time', if_not_exists => TRUE)`,

	// Enable compression on flow_logs
	`ALTER TABLE flow_logs SET (
		timescaledb.compress,
		timescaledb.compress_segmentby = 'dst_ip',
		timescaledb.compress_orderby = 'time DESC'
	)`,
}
