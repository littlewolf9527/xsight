package postgres

// v1.2 PR-5: bgp_announcements repo — refcount-based BGP route lifecycle.
//
// All write operations wrap their SQL in a short transaction with SELECT ...
// FOR UPDATE on the announcement row, so concurrent Attach/Detach on the
// same business key serialize without racing. vtysh side effects are
// compensating updates outside the transaction — the `announcing` and
// `withdrawing` statuses serve as crash-recovery landmarks.

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/littlewolf9527/xsight/controller/internal/store"
)

type bgpAnnouncementRepo struct{ pool *pgxpool.Pool }

const bgpAnnouncementCols = `id, prefix, route_map, connector_id, first_action_id,
	status, refcount, announced_at, delay_started_at, delay_minutes, withdrawn_at,
	COALESCE(error_message, ''), created_at`

func (r *bgpAnnouncementRepo) scanOne(row pgx.Row) (*store.BGPAnnouncement, error) {
	var a store.BGPAnnouncement
	err := row.Scan(&a.ID, &a.Prefix, &a.RouteMap, &a.ConnectorID, &a.FirstActionID,
		&a.Status, &a.Refcount, &a.AnnouncedAt, &a.DelayStartedAt, &a.DelayMinutes,
		&a.WithdrawnAt, &a.ErrorMessage, &a.CreatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	return &a, nil
}

func (r *bgpAnnouncementRepo) Get(ctx context.Context, id int) (*store.BGPAnnouncement, error) {
	row := r.pool.QueryRow(ctx,
		`SELECT `+bgpAnnouncementCols+` FROM bgp_announcements WHERE id=$1`, id)
	return r.scanOne(row)
}

func (r *bgpAnnouncementRepo) FindByBusinessKey(ctx context.Context, prefix, routeMap string, connectorID int) (*store.BGPAnnouncement, error) {
	row := r.pool.QueryRow(ctx,
		`SELECT `+bgpAnnouncementCols+`
		 FROM bgp_announcements
		 WHERE prefix=$1 AND route_map=$2 AND connector_id=$3`,
		prefix, routeMap, connectorID)
	return r.scanOne(row)
}

// Attach creates or updates an announcement atomically. See interface comment
// for the exact state-machine semantics.
func (r *bgpAnnouncementRepo) Attach(ctx context.Context, p store.BGPAttachParams) (store.BGPAttachResult, error) {
	var result store.BGPAttachResult
	err := pgx.BeginFunc(ctx, r.pool, func(tx pgx.Tx) error {
		// Lock the existing row (if any) — SELECT ... FOR UPDATE serializes
		// concurrent Attach/Detach on the same business key.
		var (
			annID     int
			status    string
			refcount  int
			existing  bool
		)
		err := tx.QueryRow(ctx,
			`SELECT id, status, refcount FROM bgp_announcements
			 WHERE prefix=$1 AND route_map=$2 AND connector_id=$3
			 FOR UPDATE`,
			p.Prefix, p.RouteMap, p.ConnectorID).Scan(&annID, &status, &refcount)
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("lock announcement: %w", err)
		}
		existing = err == nil

		if !existing {
			// No prior announcement — INSERT as announcing, refcount=1, caller will run vtysh.
			if err := tx.QueryRow(ctx,
				`INSERT INTO bgp_announcements
				 (prefix, route_map, connector_id, first_action_id, status, refcount, delay_minutes)
				 VALUES ($1, $2, $3, $4, 'announcing', 1, $5)
				 RETURNING id`,
				p.Prefix, p.RouteMap, p.ConnectorID, p.ActionID, p.DelayMinutes).Scan(&annID); err != nil {
				return fmt.Errorf("insert announcement: %w", err)
			}
			if _, err := tx.Exec(ctx,
				`INSERT INTO bgp_announcement_attacks
				 (announcement_id, attack_id, action_id, response_name, delay_minutes)
				 VALUES ($1, $2, $3, $4, $5)
				 ON CONFLICT (announcement_id, attack_id) DO UPDATE
				 SET detached_at = NULL, action_id = EXCLUDED.action_id,
				     response_name = EXCLUDED.response_name,
				     delay_minutes = EXCLUDED.delay_minutes`,
				annID, p.AttackID, p.ActionID, p.ResponseName, p.DelayMinutes); err != nil {
				return fmt.Errorf("insert attack attach: %w", err)
			}
			if _, err := tx.Exec(ctx,
				`INSERT INTO bgp_announcement_events (announcement_id, event_type, attack_id, detail)
				 VALUES ($1, 'attack_attached', $2, 'initial attach')`,
				annID, p.AttackID); err != nil {
				return err
			}
			result = store.BGPAttachResult{AnnouncementID: annID, NeedAnnounce: true}
			return nil
		}

		// Existing row — decide whether to reuse or resurrect.
		switch status {
		case "announcing", "active":
			// Normal reuse: refcount++, no vtysh
			if _, err := tx.Exec(ctx,
				`UPDATE bgp_announcements SET refcount = refcount + 1 WHERE id = $1`,
				annID); err != nil {
				return err
			}
			if _, err := tx.Exec(ctx,
				`INSERT INTO bgp_announcement_attacks
				 (announcement_id, attack_id, action_id, response_name, delay_minutes)
				 VALUES ($1, $2, $3, $4, $5)
				 ON CONFLICT (announcement_id, attack_id) DO UPDATE
				 SET detached_at = NULL, action_id = EXCLUDED.action_id,
				     response_name = EXCLUDED.response_name,
				     delay_minutes = EXCLUDED.delay_minutes`,
				annID, p.AttackID, p.ActionID, p.ResponseName, p.DelayMinutes); err != nil {
				return err
			}
			if err := recomputeDelayMinutes(ctx, tx, annID); err != nil {
				return err
			}
			if _, err := tx.Exec(ctx,
				`INSERT INTO bgp_announcement_events (announcement_id, event_type, attack_id, detail)
				 VALUES ($1, 'attack_attached', $2, $3)`,
				annID, p.AttackID, fmt.Sprintf("shared (refcount=%d)", refcount+1)); err != nil {
				return err
			}
			result = store.BGPAttachResult{AnnouncementID: annID, NeedAnnounce: false}
			return nil

		case "delayed":
			// Cancel the delay, transition back to active (or announcing if stale).
			// refcount was 0 in delayed; now ++ to 1.
			if _, err := tx.Exec(ctx,
				`UPDATE bgp_announcements
				 SET refcount = refcount + 1, status = 'active',
				     delay_started_at = NULL
				 WHERE id = $1`, annID); err != nil {
				return err
			}
			if _, err := tx.Exec(ctx,
				`INSERT INTO bgp_announcement_attacks
				 (announcement_id, attack_id, action_id, response_name, delay_minutes)
				 VALUES ($1, $2, $3, $4, $5)
				 ON CONFLICT (announcement_id, attack_id) DO UPDATE
				 SET detached_at = NULL, action_id = EXCLUDED.action_id,
				     response_name = EXCLUDED.response_name,
				     delay_minutes = EXCLUDED.delay_minutes`,
				annID, p.AttackID, p.ActionID, p.ResponseName, p.DelayMinutes); err != nil {
				return err
			}
			if err := recomputeDelayMinutes(ctx, tx, annID); err != nil {
				return err
			}
			if _, err := tx.Exec(ctx,
				`INSERT INTO bgp_announcement_events (announcement_id, event_type, attack_id, detail)
				 VALUES ($1, 'delay_cancelled', $2, 'new attack attached during delay')`,
				annID, p.AttackID); err != nil {
				return err
			}
			result = store.BGPAttachResult{AnnouncementID: annID, NeedAnnounce: false}
			return nil

		case "withdrawn", "failed":
			// Row exists but the route isn't in FRR any more — treat as fresh announce.
			// Reset delay_minutes so the new cycle's sticky MAX starts from the
			// incoming attack's delay (previous cycle's peak is no longer relevant).
			if _, err := tx.Exec(ctx,
				`UPDATE bgp_announcements
				 SET status = 'announcing', refcount = 1,
				     announced_at = now(), withdrawn_at = NULL,
				     delay_started_at = NULL, error_message = '',
				     delay_minutes = 0
				 WHERE id = $1`, annID); err != nil {
				return err
			}
			if _, err := tx.Exec(ctx,
				`INSERT INTO bgp_announcement_attacks
				 (announcement_id, attack_id, action_id, response_name, delay_minutes)
				 VALUES ($1, $2, $3, $4, $5)
				 ON CONFLICT (announcement_id, attack_id) DO UPDATE
				 SET detached_at = NULL, action_id = EXCLUDED.action_id,
				     response_name = EXCLUDED.response_name,
				     delay_minutes = EXCLUDED.delay_minutes`,
				annID, p.AttackID, p.ActionID, p.ResponseName, p.DelayMinutes); err != nil {
				return err
			}
			if err := recomputeDelayMinutes(ctx, tx, annID); err != nil {
				return err
			}
			if _, err := tx.Exec(ctx,
				`INSERT INTO bgp_announcement_events (announcement_id, event_type, attack_id, detail)
				 VALUES ($1, 'attack_attached', $2, 'resurrect from ' || $3)`,
				annID, p.AttackID, status); err != nil {
				return err
			}
			result = store.BGPAttachResult{AnnouncementID: annID, NeedAnnounce: true}
			return nil

		case "withdrawing", "orphan", "dismissed", "dismissed_on_upgrade":
			// These are transient / operator-owned states — refuse attach and
			// return an error. Caller should retry later (after reconcile
			// transitions withdrawing out, or after operator handles orphan).
			return fmt.Errorf("cannot attach to announcement %d in status %s", annID, status)
		}
		return fmt.Errorf("unknown announcement status: %s", status)
	})
	return result, err
}

// Detach atomically records attack detachment and recomputes the lifecycle.
func (r *bgpAnnouncementRepo) Detach(ctx context.Context, attackID int, prefix, routeMap string, connectorID int) (store.BGPDetachResult, error) {
	var result store.BGPDetachResult
	err := pgx.BeginFunc(ctx, r.pool, func(tx pgx.Tx) error {
		var annID int
		var status string
		err := tx.QueryRow(ctx,
			`SELECT id, status FROM bgp_announcements
			 WHERE prefix=$1 AND route_map=$2 AND connector_id=$3
			 FOR UPDATE`,
			prefix, routeMap, connectorID).Scan(&annID, &status)
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				// No announcement — nothing to detach. Silently succeed (idempotent).
				return nil
			}
			return fmt.Errorf("lock announcement for detach: %w", err)
		}

		// Mark this attack's row detached (if it was attached).
		tag, err := tx.Exec(ctx,
			`UPDATE bgp_announcement_attacks
			 SET detached_at = now()
			 WHERE announcement_id=$1 AND attack_id=$2 AND detached_at IS NULL`,
			annID, attackID)
		if err != nil {
			return fmt.Errorf("detach attack row: %w", err)
		}
		if tag.RowsAffected() == 0 {
			// Attack wasn't attached — idempotent success.
			result.AnnouncementID = annID
			return nil
		}

		if _, err := tx.Exec(ctx,
			`UPDATE bgp_announcements SET refcount = GREATEST(refcount - 1, 0) WHERE id = $1`,
			annID); err != nil {
			return fmt.Errorf("decrement refcount: %w", err)
		}
		// Recompute delay_minutes from still-attached rows (MAX).
		if err := recomputeDelayMinutes(ctx, tx, annID); err != nil {
			return err
		}

		// Re-read refcount + delay_minutes (both may have changed).
		var refcount, delayMin int
		if err := tx.QueryRow(ctx,
			`SELECT refcount, delay_minutes FROM bgp_announcements WHERE id=$1`, annID).
			Scan(&refcount, &delayMin); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx,
			`INSERT INTO bgp_announcement_events (announcement_id, event_type, attack_id, detail)
			 VALUES ($1, 'attack_detached', $2, $3)`,
			annID, attackID, fmt.Sprintf("refcount=%d", refcount)); err != nil {
			return err
		}

		result.AnnouncementID = annID
		result.RefcountAfter = refcount

		if refcount > 0 {
			// Still in use — no side effect.
			return nil
		}

		if delayMin > 0 {
			// Enter delayed state.
			if _, err := tx.Exec(ctx,
				`UPDATE bgp_announcements
				 SET status = 'delayed', delay_started_at = now()
				 WHERE id = $1 AND status IN ('active', 'announcing')`,
				annID); err != nil {
				return err
			}
			if _, err := tx.Exec(ctx,
				`INSERT INTO bgp_announcement_events (announcement_id, event_type, attack_id, detail)
				 VALUES ($1, 'delay_started', $2, $3)`,
				annID, attackID, fmt.Sprintf("delay_minutes=%d", delayMin)); err != nil {
				return err
			}
			result.Delayed = true
			result.DelayMinutes = delayMin
			return nil
		}

		// refcount=0 + delay=0 → withdraw immediately.
		if _, err := tx.Exec(ctx,
			`UPDATE bgp_announcements
			 SET status = 'withdrawing'
			 WHERE id = $1 AND status IN ('active', 'announcing', 'delayed')`,
			annID); err != nil {
			return err
		}
		result.NeedWithdraw = true
		return nil
	})
	return result, err
}

// recomputeDelayMinutes refreshes announcement.delay_minutes with cycle-sticky
// MAX semantics: delay_minutes only increases during a cycle (from announce
// to withdraw), never decreases. Specifically:
//   - On attach: take GREATEST(current delay_minutes, MAX over currently
//     attached). This lets a higher-delay attack bump the value up, but a
//     lower-delay one doesn't drop it.
//   - On detach: same expression — if the detaching attack had the peak
//     delay, the current value is preserved (doesn't regress to a lower
//     remaining-attack delay).
//   - On resurrect (withdrawn/failed → announcing): the caller resets
//     delay_minutes=0 in the UPDATE SET clause first; recompute then picks
//     up the newly-attached attack's delay.
//
// This semantic matches operator intent: once an attack with delay=N has
// attached to this cycle, the announcement's post-detach tail is at least
// N minutes, regardless of which attack detaches first.
//
// Called inside a transaction.
func recomputeDelayMinutes(ctx context.Context, tx pgx.Tx, annID int) error {
	_, err := tx.Exec(ctx,
		`UPDATE bgp_announcements
		 SET delay_minutes = GREATEST(
		   delay_minutes,
		   COALESCE((
		     SELECT MAX(delay_minutes) FROM bgp_announcement_attacks
		     WHERE announcement_id = $1 AND detached_at IS NULL
		   ), 0)
		 )
		 WHERE id = $1`, annID)
	if err != nil {
		return fmt.Errorf("recompute delay_minutes: %w", err)
	}
	return nil
}

func (r *bgpAnnouncementRepo) MarkAnnounced(ctx context.Context, id int) error {
	_, err := r.pool.Exec(ctx,
		`UPDATE bgp_announcements SET status='active' WHERE id=$1 AND status='announcing'`, id)
	if err != nil {
		return fmt.Errorf("mark announced %d: %w", id, err)
	}
	r.appendEventIgnore(ctx, id, store.BGPEventAnnounced, nil, "vtysh announce succeeded")
	return nil
}

func (r *bgpAnnouncementRepo) MarkWithdrawing(ctx context.Context, id int) (bool, error) {
	tag, err := r.pool.Exec(ctx,
		`UPDATE bgp_announcements SET status='withdrawing'
		 WHERE id=$1 AND status IN ('active','delayed')`, id)
	if err != nil {
		return false, fmt.Errorf("mark withdrawing %d: %w", id, err)
	}
	return tag.RowsAffected() > 0, nil
}

func (r *bgpAnnouncementRepo) MarkWithdrawn(ctx context.Context, id int) error {
	_, err := r.pool.Exec(ctx,
		`UPDATE bgp_announcements SET status='withdrawn', withdrawn_at=now()
		 WHERE id=$1`, id)
	if err != nil {
		return err
	}
	r.appendEventIgnore(ctx, id, store.BGPEventWithdrawn, nil, "vtysh withdraw succeeded")
	return nil
}

// MarkFailedAnnounce compensates an announce failure. If refcount=1 (no
// concurrent attach raced in), safe to delete the row. Otherwise set status
// =failed, preserving the attack attachments for operator inspection.
func (r *bgpAnnouncementRepo) MarkFailedAnnounce(ctx context.Context, id int, errMsg string) error {
	return pgx.BeginFunc(ctx, r.pool, func(tx pgx.Tx) error {
		var refcount int
		if err := tx.QueryRow(ctx,
			`SELECT refcount FROM bgp_announcements WHERE id=$1 FOR UPDATE`, id).Scan(&refcount); err != nil {
			return err
		}
		if refcount == 1 {
			// Safe to DELETE — no concurrent attach.
			if _, err := tx.Exec(ctx, `DELETE FROM bgp_announcements WHERE id=$1`, id); err != nil {
				return err
			}
			// Note: CASCADE deletes bgp_announcement_attacks and events rows.
			return nil
		}
		// Concurrent attach raced in; preserve row with status=failed.
		if _, err := tx.Exec(ctx,
			`UPDATE bgp_announcements
			 SET status='failed', error_message=$2
			 WHERE id=$1`, id, errMsg); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx,
			`INSERT INTO bgp_announcement_events (announcement_id, event_type, detail)
			 VALUES ($1, $2, $3)`, id, store.BGPEventAnnounceFailed, errMsg); err != nil {
			return err
		}
		return nil
	})
}

func (r *bgpAnnouncementRepo) MarkFailedWithdraw(ctx context.Context, id int, errMsg string) error {
	_, err := r.pool.Exec(ctx,
		`UPDATE bgp_announcements SET status='failed', error_message=$2 WHERE id=$1`,
		id, errMsg)
	if err != nil {
		return err
	}
	r.appendEventIgnore(ctx, id, store.BGPEventWithdrawFailed, nil, errMsg)
	return nil
}

func (r *bgpAnnouncementRepo) ForceWithdraw(ctx context.Context, id int) error {
	return pgx.BeginFunc(ctx, r.pool, func(tx pgx.Tx) error {
		// Lock + transition to withdrawing, detach all attacks.
		var status string
		if err := tx.QueryRow(ctx,
			`SELECT status FROM bgp_announcements WHERE id=$1 FOR UPDATE`, id).Scan(&status); err != nil {
			return err
		}
		if status == "withdrawn" || status == "dismissed" {
			return nil // already done
		}
		if _, err := tx.Exec(ctx,
			`UPDATE bgp_announcements SET status='withdrawing', refcount=0 WHERE id=$1`, id); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx,
			`UPDATE bgp_announcement_attacks SET detached_at=now()
			 WHERE announcement_id=$1 AND detached_at IS NULL`, id); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx,
			`INSERT INTO bgp_announcement_events (announcement_id, event_type, detail)
			 VALUES ($1, 'attack_detached', 'force withdraw by operator')`, id); err != nil {
			return err
		}
		return nil
	})
}

func (r *bgpAnnouncementRepo) Dismiss(ctx context.Context, id int) error {
	_, err := r.pool.Exec(ctx,
		`UPDATE bgp_announcements SET status='dismissed' WHERE id=$1 AND status='orphan'`, id)
	if err != nil {
		return err
	}
	r.appendEventIgnore(ctx, id, store.BGPEventDismissed, nil, "orphan dismissed by operator")
	return nil
}

func (r *bgpAnnouncementRepo) Undismiss(ctx context.Context, id int) error {
	_, err := r.pool.Exec(ctx,
		`UPDATE bgp_announcements SET status='orphan'
		 WHERE id=$1 AND status IN ('dismissed','dismissed_on_upgrade')`, id)
	if err != nil {
		return err
	}
	r.appendEventIgnore(ctx, id, store.BGPEventUndismissed, nil, "dismissed orphan re-surfaced by operator")
	return nil
}

// CountByStatus returns status → row count for all current
// bgp_announcements. Used by the Prometheus xsight_bgp_announcements
// gauge collector. One SELECT ... GROUP BY query per scrape.
func (r *bgpAnnouncementRepo) CountByStatus(ctx context.Context) (map[string]int, error) {
	rows, err := r.pool.Query(ctx,
		`SELECT status, COUNT(*) FROM bgp_announcements GROUP BY status`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make(map[string]int)
	for rows.Next() {
		var status string
		var n int
		if err := rows.Scan(&status, &n); err != nil {
			return nil, err
		}
		out[status] = n
	}
	return out, rows.Err()
}

// HasOperationalHistory returns true if any row exists with a status other
// than `orphan` / `dismissed_on_upgrade`. These two statuses are the only
// ones the bootstrap scan itself produces, so their absence means this
// controller has never processed a real attack-driven announcement.
//
// Caller (bgp_bootstrap.go) uses the inverse: no history → first-time boot
// → newly-discovered FRR routes go into `dismissed_on_upgrade` (silent,
// to avoid scaring operators upgrading from v1.1 with pre-existing state).
func (r *bgpAnnouncementRepo) HasOperationalHistory(ctx context.Context) (bool, error) {
	var exists bool
	err := r.pool.QueryRow(ctx,
		`SELECT EXISTS (
		    SELECT 1 FROM bgp_announcements
		    WHERE status NOT IN ('orphan','dismissed_on_upgrade')
		)`).Scan(&exists)
	return exists, err
}

// UpsertOrphan inserts an orphan marker row, or upgrades a pre-existing
// `withdrawn` row to the caller's status. The ON CONFLICT guard keeps this
// safe to call on every bootstrap — operator-dismissed rows and currently-
// active announcements are never touched.
//
// Returns created=true when a row was actually INSERTed or UPDATEd (either
// branch of the UPSERT took effect), so the caller can log + write a
// timeline event. created=false = pre-existing row in a state the WHERE
// clause of DO UPDATE filters out (i.e., non-withdrawn).
//
// The detection of "WHERE filtered → no-op" relies on the ON CONFLICT DO
// UPDATE ... WHERE ... RETURNING pattern: when the UPDATE's WHERE is false,
// PG suppresses the UPDATE and RETURNING yields zero rows → pgx.ErrNoRows.
// Distinguishing INSERT vs UPDATE is not needed by current callers, so we
// keep the SQL minimal.
func (r *bgpAnnouncementRepo) UpsertOrphan(ctx context.Context, prefix, routeMap string, connectorID int, status string) (bool, error) {
	var id int
	err := r.pool.QueryRow(ctx, `
		INSERT INTO bgp_announcements (prefix, route_map, connector_id, status, refcount)
		VALUES ($1, $2, $3, $4, 0)
		ON CONFLICT (prefix, route_map, connector_id) DO UPDATE
		  SET status = EXCLUDED.status
		  WHERE bgp_announcements.status = 'withdrawn'
		RETURNING id
	`, prefix, routeMap, connectorID, status).Scan(&id)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			// Row existed in a non-withdrawn state; leave it alone.
			return false, nil
		}
		return false, err
	}
	r.appendEventIgnore(ctx, id, store.BGPEventOrphanDetected, nil,
		fmt.Sprintf("bootstrap scan marked %s route-map=%s as %s", prefix, routeMap, status))
	return true, nil
}

func (r *bgpAnnouncementRepo) ListActive(ctx context.Context) ([]store.BGPAnnouncement, error) {
	return r.list(ctx,
		`WHERE status IN ('announcing','active','delayed','withdrawing','failed','orphan')`)
}

func (r *bgpAnnouncementRepo) ListDismissed(ctx context.Context) ([]store.BGPAnnouncement, error) {
	return r.list(ctx, `WHERE status IN ('dismissed','dismissed_on_upgrade')`)
}

func (r *bgpAnnouncementRepo) ListByStatus(ctx context.Context, status string) ([]store.BGPAnnouncement, error) {
	return r.list(ctx, `WHERE status=$1`, status)
}

func (r *bgpAnnouncementRepo) list(ctx context.Context, where string, args ...any) ([]store.BGPAnnouncement, error) {
	rows, err := r.pool.Query(ctx,
		`SELECT `+bgpAnnouncementCols+` FROM bgp_announcements `+where+` ORDER BY announced_at DESC`,
		args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []store.BGPAnnouncement
	for rows.Next() {
		var a store.BGPAnnouncement
		if err := rows.Scan(&a.ID, &a.Prefix, &a.RouteMap, &a.ConnectorID, &a.FirstActionID,
			&a.Status, &a.Refcount, &a.AnnouncedAt, &a.DelayStartedAt, &a.DelayMinutes,
			&a.WithdrawnAt, &a.ErrorMessage, &a.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

func (r *bgpAnnouncementRepo) ListAttacks(ctx context.Context, announcementID int) ([]store.BGPAnnouncementAttack, error) {
	rows, err := r.pool.Query(ctx,
		`SELECT announcement_id, attack_id, action_id, COALESCE(response_name, ''),
		        delay_minutes, attached_at, detached_at
		 FROM bgp_announcement_attacks
		 WHERE announcement_id=$1
		 ORDER BY attached_at DESC`, announcementID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []store.BGPAnnouncementAttack
	for rows.Next() {
		var a store.BGPAnnouncementAttack
		if err := rows.Scan(&a.AnnouncementID, &a.AttackID, &a.ActionID,
			&a.ResponseName, &a.DelayMinutes, &a.AttachedAt, &a.DetachedAt); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// ListAttachmentsForAttack returns every bgp_announcement_attacks row for an
// attack regardless of detach state, ordered by attached_at ASC.
// mitigation-summary uses this to enumerate which announcements an attack
// touched (current cycle + past cycles for audit).
func (r *bgpAnnouncementRepo) ListAttachmentsForAttack(ctx context.Context, attackID int) ([]store.BGPAnnouncementAttack, error) {
	rows, err := r.pool.Query(ctx,
		`SELECT announcement_id, attack_id, action_id, COALESCE(response_name, ''),
		        delay_minutes, attached_at, detached_at
		 FROM bgp_announcement_attacks
		 WHERE attack_id=$1
		 ORDER BY attached_at ASC`, attackID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []store.BGPAnnouncementAttack
	for rows.Next() {
		var a store.BGPAnnouncementAttack
		if err := rows.Scan(&a.AnnouncementID, &a.AttackID, &a.ActionID,
			&a.ResponseName, &a.DelayMinutes, &a.AttachedAt, &a.DetachedAt); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

func (r *bgpAnnouncementRepo) AppendEvent(ctx context.Context, announcementID int, eventType string, attackID *int, detail string) error {
	_, err := r.pool.Exec(ctx,
		`INSERT INTO bgp_announcement_events (announcement_id, event_type, attack_id, detail)
		 VALUES ($1, $2, $3, $4)`, announcementID, eventType, attackID, detail)
	return err
}

func (r *bgpAnnouncementRepo) appendEventIgnore(ctx context.Context, announcementID int, eventType string, attackID *int, detail string) {
	if err := r.AppendEvent(ctx, announcementID, eventType, attackID, detail); err != nil {
		// Non-fatal: timeline entry missing, but state is authoritative.
		_ = err
	}
}

func (r *bgpAnnouncementRepo) ListEvents(ctx context.Context, announcementID int) ([]store.BGPAnnouncementEvent, error) {
	rows, err := r.pool.Query(ctx,
		`SELECT id, announcement_id, event_type, attack_id, COALESCE(detail, ''), created_at
		 FROM bgp_announcement_events
		 WHERE announcement_id=$1
		 ORDER BY created_at ASC, id ASC`, announcementID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []store.BGPAnnouncementEvent
	for rows.Next() {
		var e store.BGPAnnouncementEvent
		if err := rows.Scan(&e.ID, &e.AnnouncementID, &e.EventType, &e.AttackID, &e.Detail, &e.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}
