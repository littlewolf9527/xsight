// Package retention implements automatic cleanup of historical data.
package retention

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Config mirrors the retention section of the controller config.
type Config struct {
	TSStatsDays   int
	FlowLogsDays  int
	AttacksDays   int
	AuditLogDays  int
	IntervalHours int
	HasTimescale  bool // if true, skip row-delete on hypertables (ts_stats, flow_logs) — TimescaleDB policies own their lifecycle
}

// Cleaner periodically deletes old data from the database.
type Cleaner struct {
	pool *pgxpool.Pool
	cfg  Config
}

func New(pool *pgxpool.Pool, cfg Config) *Cleaner {
	if cfg.IntervalHours <= 0 {
		cfg.IntervalHours = 24
	}
	return &Cleaner{pool: pool, cfg: cfg}
}

// Run starts the periodic cleanup loop. Blocks until ctx is cancelled.
func (c *Cleaner) Run(ctx context.Context) {
	// Run once on startup (after a short delay to let other services stabilize)
	select {
	case <-time.After(30 * time.Second):
		c.cleanup(ctx)
	case <-ctx.Done():
		return
	}

	ticker := time.NewTicker(time.Duration(c.cfg.IntervalHours) * time.Hour)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			c.cleanup(ctx)
		}
	}
}

func (c *Cleaner) cleanup(ctx context.Context) {
	log.Println("retention: starting cleanup")
	total := int64(0)

	// ts_stats: skip row-delete when TimescaleDB manages retention via chunk policies
	if c.cfg.TSStatsDays > 0 && !c.cfg.HasTimescale {
		n, err := c.deleteOld(ctx, "ts_stats", "time", c.cfg.TSStatsDays)
		if err != nil {
			log.Printf("retention: ts_stats cleanup error: %v", err)
		} else if n > 0 {
			log.Printf("retention: ts_stats deleted %d rows older than %d days", n, c.cfg.TSStatsDays)
			total += n
		}
	}

	if c.cfg.AttacksDays > 0 {
		// Only delete ended attacks (active attacks have ended_at IS NULL)
		n, err := c.deleteOldAttacks(ctx, c.cfg.AttacksDays)
		if err != nil {
			log.Printf("retention: attacks cleanup error: %v", err)
		} else if n > 0 {
			log.Printf("retention: attacks deleted %d rows older than %d days", n, c.cfg.AttacksDays)
			total += n
		}
	}

	if c.cfg.AuditLogDays > 0 {
		n, err := c.deleteOld(ctx, "config_audit_log", "created_at", c.cfg.AuditLogDays)
		if err != nil {
			log.Printf("retention: audit_log cleanup error: %v", err)
		} else if n > 0 {
			log.Printf("retention: audit_log deleted %d rows older than %d days", n, c.cfg.AuditLogDays)
			total += n
		}
	}

	// flow_logs: skip row-delete when TimescaleDB manages retention via chunk policies
	if c.cfg.FlowLogsDays > 0 && !c.cfg.HasTimescale {
		n, err := c.deleteOld(ctx, "flow_logs", "time", c.cfg.FlowLogsDays)
		if err != nil {
			log.Printf("retention: flow_logs cleanup error: %v", err)
		} else if n > 0 {
			log.Printf("retention: flow_logs deleted %d rows older than %d days", n, c.cfg.FlowLogsDays)
			total += n
		}
	}

	if total == 0 {
		log.Println("retention: cleanup complete, nothing to delete")
	} else {
		log.Printf("retention: cleanup complete, %d total rows deleted", total)
	}
}

func (c *Cleaner) deleteOld(ctx context.Context, table, timeCol string, days int) (int64, error) {
	cutoff := time.Now().Add(-time.Duration(days) * 24 * time.Hour)
	q := fmt.Sprintf("DELETE FROM %s WHERE %s < $1", table, timeCol)
	tag, err := c.pool.Exec(ctx, q, cutoff)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}

func (c *Cleaner) deleteOldAttacks(ctx context.Context, days int) (int64, error) {
	cutoff := time.Now().Add(-time.Duration(days) * 24 * time.Hour)
	tx, err := c.pool.Begin(ctx)
	if err != nil {
		return 0, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback(ctx)

	// Delete actions_log for old attacks first (FK constraint)
	if _, err := tx.Exec(ctx,
		"DELETE FROM actions_log WHERE attack_id IN (SELECT id FROM attacks WHERE ended_at IS NOT NULL AND ended_at < $1)", cutoff); err != nil {
		return 0, fmt.Errorf("delete actions_log: %w", err)
	}
	// Then delete the attacks themselves (only ended ones)
	tag, err := tx.Exec(ctx,
		"DELETE FROM attacks WHERE ended_at IS NOT NULL AND ended_at < $1", cutoff)
	if err != nil {
		return 0, fmt.Errorf("delete attacks: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return 0, fmt.Errorf("commit: %w", err)
	}
	return tag.RowsAffected(), nil
}
