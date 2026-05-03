package postgres

// Invariant tests for the scheduled_actions partial unique indexes and the
// Schedule() ON CONFLICT clauses.  String-based assertions that always run
// (no live DB needed), plus an opt-in Postgres roundtrip test gated behind
// XSIGHT_TEST_DSN.
//
// See fix-plan-xdrop-port-bgp-schedule-2026-05-02.md §Bug 2.

import (
	"context"
	"crypto/rand"
	"fmt"
	"math/big"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/littlewolf9527/xsight/controller/internal/store"
)

// ---------- string invariant tests (always run) ----------

// TestMigrations_ArtifactIndexNarrowed verifies that the artifact pending index
// includes the "announcement_id IS NULL" predicate so BGP announcement-scoped
// rows are excluded.
func TestMigrations_ArtifactIndexNarrowed(t *testing.T) {
	var found string
	for _, m := range migrations {
		if strings.Contains(m, "uq_scheduled_artifact_pending") &&
			strings.Contains(m, "CREATE") {
			found = m
			break
		}
	}
	if found == "" {
		t.Fatal("uq_scheduled_artifact_pending CREATE not found in migrations")
	}
	if !strings.Contains(found, "announcement_id IS NULL") {
		t.Errorf("uq_scheduled_artifact_pending missing 'announcement_id IS NULL' predicate — "+
			"BGP rows will collide with artifact rows.\nindex DDL: %s", found)
	}
}

// TestMigrations_AnnouncementIndexExists verifies that the announcement
// pending index exists and uses the correct predicate.
func TestMigrations_AnnouncementIndexExists(t *testing.T) {
	var found string
	for _, m := range migrations {
		if strings.Contains(m, "uq_scheduled_announcement_pending") &&
			strings.Contains(m, "CREATE") {
			found = m
			break
		}
	}
	if found == "" {
		t.Fatal("uq_scheduled_announcement_pending CREATE not found in migrations")
	}
	if !strings.Contains(found, "announcement_id IS NOT NULL") {
		t.Errorf("uq_scheduled_announcement_pending missing 'announcement_id IS NOT NULL' predicate.\nindex DDL: %s", found)
	}
	if !strings.Contains(found, "action_type") || !strings.Contains(found, "announcement_id") {
		t.Errorf("uq_scheduled_announcement_pending should index (action_type, announcement_id).\nindex DDL: %s", found)
	}
}

// TestMigrations_ConditionalDrop verifies the old index is dropped conditionally,
// not unconditionally, and uses schema-scoped catalog queries.
func TestMigrations_ConditionalDrop(t *testing.T) {
	for _, m := range migrations {
		lower := strings.ToLower(m)
		// Catch a raw "DROP INDEX ... uq_scheduled_artifact_pending" outside a DO block.
		if strings.Contains(lower, "drop index") &&
			strings.Contains(m, "uq_scheduled_artifact_pending") &&
			!strings.Contains(m, "DO $$") {
			t.Errorf("unconditional DROP INDEX for uq_scheduled_artifact_pending found — "+
				"must be inside a conditional DO $$ block.\nmigration: %s", m)
		}
		// Verify schema-scoped guard uses pg_class/pg_namespace, not pg_indexes.
		if strings.Contains(m, "DO $$") &&
			strings.Contains(m, "uq_scheduled_artifact_pending") {
			if strings.Contains(m, "pg_indexes") {
				t.Errorf("index-upgrade guard uses pg_indexes (not schema-scoped) — "+
					"should use pg_class + pg_namespace + current_schema().\nmigration: %s", m)
			}
			if !strings.Contains(m, "current_schema()") {
				t.Errorf("index-upgrade guard missing current_schema() filter.\nmigration: %s", m)
			}
		}
	}
}

// ---------- live Postgres roundtrip test (opt-in) ----------

// scheduledActionsMigrations returns only the migrations needed for the
// scheduled_actions table and its indexes, in order. This avoids running the
// full migration set (which references unrelated tables) inside the temp schema.
func scheduledActionsMigrations() []string {
	var out []string
	for _, m := range migrations {
		lower := strings.ToLower(m)
		if strings.Contains(lower, "scheduled_actions") {
			out = append(out, m)
		}
	}
	return out
}

// randomSchemaName returns a unique schema name using crypto/rand.
func randomSchemaName() string {
	n, err := rand.Int(rand.Reader, big.NewInt(1<<48))
	if err != nil {
		panic(fmt.Sprintf("crypto/rand: %v", err))
	}
	return fmt.Sprintf("xsight_test_%d", n.Int64())
}

// TestScheduleIdentity_Postgres exercises the actual ON CONFLICT + partial
// unique index behavior against a real Postgres instance.
//
// Safety:
//   - Creates a random temporary schema with a crypto/rand name.
//   - Opens a dedicated pool with AfterConnect that sets search_path on EVERY
//     connection, so no pooled connection can escape to the default schema.
//   - t.Cleanup drops the schema CASCADE.
//   - Never touches the public/default schema or any shared tables.
//
// Skip unless XSIGHT_TEST_DSN is set (e.g.
// "postgres://user:pass@localhost:5432/xsight_test").
func TestScheduleIdentity_Postgres(t *testing.T) {
	dsn := os.Getenv("XSIGHT_TEST_DSN")
	if dsn == "" {
		t.Skip("XSIGHT_TEST_DSN not set — skipping live Postgres roundtrip test")
	}

	ctx := context.Background()

	// Admin pool — used only to create/drop the temp schema.
	// Must stay open until after t.Cleanup drops the schema, so Close() is
	// inside the cleanup callback (not a defer — defers run before t.Cleanup).
	adminPool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("admin connect: %v", err)
	}

	schema := randomSchemaName()
	quotedSchema := pgx.Identifier{schema}.Sanitize()

	if _, err := adminPool.Exec(ctx, fmt.Sprintf("CREATE SCHEMA %s", quotedSchema)); err != nil {
		t.Fatalf("create temp schema: %v", err)
	}
	t.Cleanup(func() {
		if _, err := adminPool.Exec(context.Background(), fmt.Sprintf("DROP SCHEMA %s CASCADE", quotedSchema)); err != nil {
			t.Logf("drop temp schema %s: %v", schema, err)
		}
		adminPool.Close()
	})

	// Test pool — AfterConnect sets search_path on every connection, so
	// all DDL/DML is guaranteed to land in the temp schema regardless of
	// which pooled connection executes it.
	poolCfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatalf("parse dsn: %v", err)
	}
	poolCfg.AfterConnect = func(ctx context.Context, conn *pgx.Conn) error {
		_, err := conn.Exec(ctx, fmt.Sprintf("SET search_path TO %s", quotedSchema))
		return err
	}
	pool, err := pgxpool.NewWithConfig(ctx, poolCfg)
	if err != nil {
		t.Fatalf("test pool connect: %v", err)
	}
	defer pool.Close()

	// Run only the scheduled_actions migrations.
	for _, m := range scheduledActionsMigrations() {
		if _, err := pool.Exec(ctx, m); err != nil {
			t.Fatalf("migration failed: %v\n  sql: %.200s", err, m)
		}
	}

	repo := &scheduledActionRepo{pool: pool}
	future := time.Now().Add(10 * time.Minute)

	// --- assertion 1: two different announcement IDs → different row IDs ---
	ann1 := 90001
	ann2 := 90002
	id1, err := repo.Schedule(ctx, &store.ScheduledAction{
		ActionType:     "bgp_withdraw",
		AnnouncementID: &ann1,
		ScheduledFor:   future,
	})
	if err != nil {
		t.Fatalf("schedule ann1: %v", err)
	}
	id2, err := repo.Schedule(ctx, &store.ScheduledAction{
		ActionType:     "bgp_withdraw",
		AnnouncementID: &ann2,
		ScheduledFor:   future,
	})
	if err != nil {
		t.Fatalf("schedule ann2: %v", err)
	}
	if id1 == id2 {
		t.Errorf("two announcements (90001, 90002) got same ID=%d", id1)
	}

	// --- assertion 2: same announcement → same ID (idempotent), updated scheduled_for ---
	future2 := future.Add(5 * time.Minute)
	id1b, err := repo.Schedule(ctx, &store.ScheduledAction{
		ActionType:     "bgp_withdraw",
		AnnouncementID: &ann1,
		ScheduledFor:   future2,
	})
	if err != nil {
		t.Fatalf("re-schedule ann1: %v", err)
	}
	if id1b != id1 {
		t.Errorf("same announcement got different IDs: %d vs %d", id1, id1b)
	}

	// --- assertion 3: artifact row and announcement row with same action_type coexist ---
	idArt, err := repo.Schedule(ctx, &store.ScheduledAction{
		ActionType:     "bgp_withdraw",
		AttackID:       -1,
		ActionID:       -1,
		ConnectorID:    -1,
		ExternalRuleID: "test-artifact",
		ScheduledFor:   future,
	})
	if err != nil {
		t.Fatalf("schedule artifact: %v", err)
	}
	if idArt == id1 || idArt == id2 {
		t.Errorf("artifact row collided with announcement row: art=%d ann1=%d ann2=%d", idArt, id1, id2)
	}

	// --- assertion 4: after terminal state, new schedule for same announcement → fresh row ---
	if err := repo.MarkExecuting(ctx, id1); err != nil {
		t.Fatalf("mark executing: %v", err)
	}
	if err := repo.Complete(ctx, id1); err != nil {
		t.Fatalf("complete: %v", err)
	}
	id1c, err := repo.Schedule(ctx, &store.ScheduledAction{
		ActionType:     "bgp_withdraw",
		AnnouncementID: &ann1,
		ScheduledFor:   future.Add(20 * time.Minute),
	})
	if err != nil {
		t.Fatalf("schedule after complete: %v", err)
	}
	if id1c == id1 {
		t.Errorf("after completion, same announcement got same ID=%d — expected fresh row", id1)
	}

	// --- assertion 5: verify index predicates in catalog (schema-scoped) ---
	var artPred, annPred string
	err = pool.QueryRow(ctx,
		`SELECT pg_get_expr(i.indpred, i.indrelid)
		 FROM pg_index i
		 JOIN pg_class c ON c.oid = i.indexrelid
		 JOIN pg_namespace n ON n.oid = c.relnamespace
		 WHERE c.relname = 'uq_scheduled_artifact_pending'
		   AND n.nspname = current_schema()`).Scan(&artPred)
	if err != nil {
		t.Fatalf("lookup artifact index predicate: %v", err)
	}
	if !strings.Contains(artPred, "announcement_id IS NULL") {
		t.Errorf("artifact index predicate missing 'announcement_id IS NULL': %s", artPred)
	}

	err = pool.QueryRow(ctx,
		`SELECT pg_get_expr(i.indpred, i.indrelid)
		 FROM pg_index i
		 JOIN pg_class c ON c.oid = i.indexrelid
		 JOIN pg_namespace n ON n.oid = c.relnamespace
		 WHERE c.relname = 'uq_scheduled_announcement_pending'
		   AND n.nspname = current_schema()`).Scan(&annPred)
	if err != nil {
		t.Fatalf("lookup announcement index predicate: %v", err)
	}
	if !strings.Contains(annPred, "announcement_id IS NOT NULL") {
		t.Errorf("announcement index predicate missing 'announcement_id IS NOT NULL': %s", annPred)
	}

	t.Logf("roundtrip OK: ann1=%d ann2=%d art=%d ann1_after_complete=%d", id1, id2, idArt, id1c)
	t.Logf("artifact predicate: %s", artPred)
	t.Logf("announcement predicate: %s", annPred)
	// Cleanup happens via t.Cleanup → DROP SCHEMA CASCADE.
}
