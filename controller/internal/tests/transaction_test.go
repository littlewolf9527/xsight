package tests

// Tests U29-U30: transactional rollback behaviour for auto-paired actions.
//
// Authentication: uses makeTestToken / testJWTSecret from active_actions_test.go.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/littlewolf9527/xsight/controller/internal/api"
	"github.com/littlewolf9527/xsight/controller/internal/store"
)

// ── failableResponseRepo ──────────────────────────────────────────────────────
//
// failableResponseRepo wraps mockResponseRepo and delegates every method
// transparently.  It can be configured to inject an error on the Nth call to
// CreateAction or UpdateAction (1-based; 0 = never fail).  This lets tests
// exercise the partial-write rollback paths in createAction / updateAction
// without touching the real database.

type failableResponseRepo struct {
	inner *mockResponseRepo

	failCreateOnCall int
	createCallCount  int
	createErr        error

	failUpdateOnCall int
	updateCallCount  int
	updateErr        error
}

func (r *failableResponseRepo) List(ctx context.Context) ([]store.Response, error) {
	return r.inner.List(ctx)
}
func (r *failableResponseRepo) Get(ctx context.Context, id int) (*store.Response, error) {
	return r.inner.Get(ctx, id)
}
func (r *failableResponseRepo) Create(ctx context.Context, resp *store.Response) (int, error) {
	return r.inner.Create(ctx, resp)
}
func (r *failableResponseRepo) Update(ctx context.Context, resp *store.Response) error {
	return r.inner.Update(ctx, resp)
}
func (r *failableResponseRepo) Delete(ctx context.Context, id int) error {
	return r.inner.Delete(ctx, id)
}
func (r *failableResponseRepo) ListActions(ctx context.Context, responseID int) ([]store.ResponseAction, error) {
	return r.inner.ListActions(ctx, responseID)
}
func (r *failableResponseRepo) GetAction(ctx context.Context, id int) (*store.ResponseAction, error) {
	return r.inner.GetAction(ctx, id)
}
func (r *failableResponseRepo) CreateAction(ctx context.Context, a *store.ResponseAction) (int, error) {
	r.createCallCount++
	if r.failCreateOnCall > 0 && r.createCallCount == r.failCreateOnCall {
		return 0, r.createErr
	}
	return r.inner.CreateAction(ctx, a)
}
func (r *failableResponseRepo) UpdateAction(ctx context.Context, a *store.ResponseAction) error {
	r.updateCallCount++
	if r.failUpdateOnCall > 0 && r.updateCallCount == r.failUpdateOnCall {
		return r.updateErr
	}
	return r.inner.UpdateAction(ctx, a)
}
func (r *failableResponseRepo) DeleteAction(ctx context.Context, id int) error {
	return r.inner.DeleteAction(ctx, id)
}
func (r *failableResponseRepo) SetPairedWith(ctx context.Context, actionID int, pairedID *int) error {
	return r.inner.SetPairedWith(ctx, actionID, pairedID)
}
func (r *failableResponseRepo) CountActionsByWebhookConnector(ctx context.Context, id int) (int, error) {
	return r.inner.CountActionsByWebhookConnector(ctx, id)
}
func (r *failableResponseRepo) CountActionsByShellConnector(ctx context.Context, id int) (int, error) {
	return r.inner.CountActionsByShellConnector(ctx, id)
}
func (r *failableResponseRepo) CountActionsByBGPConnector(ctx context.Context, id int) (int, error) {
	return r.inner.CountActionsByBGPConnector(ctx, id)
}

// ── failingResponseStore ──────────────────────────────────────────────────────
//
// failingResponseStore embeds *MockStore but overrides Responses() with the
// failable wrapper.  All other repos (XDropTargets, etc.) are shared with the
// embedded MockStore so that state mutations are visible to both the handler
// and post-call assertions.

type failingResponseStore struct {
	*MockStore
	failRepo *failableResponseRepo
}

func (s *failingResponseStore) Responses() store.ResponseRepo {
	return s.failRepo
}

func newFailingStore(ms *MockStore, failRepo *failableResponseRepo) *failingResponseStore {
	return &failingResponseStore{MockStore: ms, failRepo: failRepo}
}

// ── HTTP helpers ──────────────────────────────────────────────────────────────

func setupTransactionRouter(s store.Store) *gin.Engine {
	gin.SetMode(gin.TestMode)
	deps := api.Dependencies{
		Store:     s,
		JWTSecret: testJWTSecret,
		APIKey:    "test-api-key",
	}
	return api.NewRouter(deps)
}

// postActionRaw posts to /api/responses/{respID}/actions and returns the recorder.
func postActionRaw(t *testing.T, r *gin.Engine, respID int, body map[string]any) *httptest.ResponseRecorder {
	t.Helper()
	raw, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, fmt.Sprintf("/api/responses/%d/actions", respID), bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+makeTestToken(t))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

// putActionRaw calls PUT /api/actions/{id} and returns the recorder.
func putActionRaw(t *testing.T, r *gin.Engine, actionID int, body map[string]any) *httptest.ResponseRecorder {
	t.Helper()
	raw, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPut, fmt.Sprintf("/api/actions/%d", actionID), bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+makeTestToken(t))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

// ── U29: create is transactional — child failure rolls back parent ────────────

// TestAutoPair_CreateIsTransactional verifies that when the auto-generated
// on_expired (child) CreateAction call fails, the already-written parent action
// is deleted (rolled back), leaving zero actions in the store.
func TestAutoPair_CreateIsTransactional(t *testing.T) {
	ms := NewMockStore()

	// Call 1 = parent CreateAction (succeeds)
	// Call 2 = child CreateAction  (injected failure)
	// Handler must then delete the parent → rollback.
	failRepo := &failableResponseRepo{
		inner:            ms.responses,
		failCreateOnCall: 2,
		createErr:        errors.New("injected child create failure"),
	}
	fs := newFailingStore(ms, failRepo)
	r := setupTransactionRouter(fs)

	w := postActionRaw(t, r, 1, xDropFilterBody(nil))
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500 on child create failure, got %d: %s", w.Code, w.Body.String())
	}

	// Parent must have been rolled back — no actions should remain.
	actions, err := ms.responses.ListActions(context.Background(), 1)
	if err != nil {
		t.Fatalf("ListActions after rollback: %v", err)
	}
	if len(actions) != 0 {
		t.Errorf("rollback failed: %d action(s) remain in store after child create failure", len(actions))
		for _, a := range actions {
			t.Logf("  leftover: id=%d type=%s phase=%s auto=%v",
				a.ID, a.ActionType, a.TriggerPhase, a.AutoGenerated)
		}
	}
}

// ── U30: update sync is transactional — child update failure rolls back parent ─

// TestAutoPair_UpdateSyncIsTransactional verifies that when syncPairedOnExpired
// fails (child UpdateAction returns an error), the handler rolls the parent back
// to its original state.
func TestAutoPair_UpdateSyncIsTransactional(t *testing.T) {
	// Phase 1: create a healthy paired pair using the normal store.
	ms := NewMockStore()
	r := setupAutoPairRouter(ms)

	parentID := postAction(t, r, 1, xDropFilterBody(map[string]any{
		"unblock_delay_minutes": 5,
	}))

	// Confirm initial state.
	actions := listResponseActions(t, r, 1)
	if len(actions) != 2 {
		t.Fatalf("precondition: expected 2 actions, got %d", len(actions))
	}
	parentBefore := findActionByPhase(actions, "on_detected")
	if parentBefore == nil {
		t.Fatal("precondition: on_detected not found")
	}
	if parentBefore.UnblockDelayMinutes != 5 {
		t.Fatalf("precondition: initial parent delay = %d, want 5", parentBefore.UnblockDelayMinutes)
	}

	// Phase 2: wrap the same store with a failable repo that fails on the
	// second UpdateAction call:
	//   call 1 = parent UpdateAction  (succeeds)
	//   call 2 = child UpdateAction   (injected failure)
	//   call 3 = rollback parent      (UpdateAction, succeeds)
	failRepo := &failableResponseRepo{
		inner:            ms.responses,
		failUpdateOnCall: 2,
		updateErr:        errors.New("injected child update failure"),
	}
	fs := newFailingStore(ms, failRepo)
	r2 := setupTransactionRouter(fs)

	w := putActionRaw(t, r2, parentID, xDropFilterBody(map[string]any{
		"unblock_delay_minutes": 10,
	}))
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500 on child update failure, got %d: %s", w.Code, w.Body.String())
	}

	// Parent must be at the original delay=5 after rollback.
	parentAfter, err := ms.responses.GetAction(context.Background(), parentID)
	if err != nil || parentAfter == nil {
		t.Fatalf("parent action %d not found after rollback: %v", parentID, err)
	}
	if parentAfter.UnblockDelayMinutes != 5 {
		t.Errorf("parent not rolled back: delay = %d, want 5", parentAfter.UnblockDelayMinutes)
	}
}
