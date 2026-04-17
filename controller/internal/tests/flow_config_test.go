package tests

// Tests for the defensive fix in flow_config.go: PUT /flow-listeners/:id and
// PUT /flow-sources/:id must not silently reset Enabled to false when the
// request body omits the "enabled" field.
//
// Regression: the earlier code used c.ShouldBindJSON(&req) into a struct whose
// zero value for Enabled is false, so any PUT that forgot to include enabled
// would overwrite the stored row with enabled=false. This broke production
// when the flow-source edit form didn't carry the enabled field.

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

// ── recordable mocks ──────────────────────────────────────────────────────────

type recListenerRepo struct {
	stored    *store.FlowListener
	lastWrite *store.FlowListener
}

func (r *recListenerRepo) List(_ context.Context, _ string) ([]store.FlowListener, error) {
	return nil, nil
}
func (r *recListenerRepo) Get(_ context.Context, id int) (*store.FlowListener, error) {
	if r.stored == nil || r.stored.ID != id {
		return nil, errors.New("not found")
	}
	cp := *r.stored
	return &cp, nil
}
func (r *recListenerRepo) Create(_ context.Context, _ *store.FlowListener) (int, error) {
	return 0, nil
}
func (r *recListenerRepo) Update(_ context.Context, l *store.FlowListener) error {
	cp := *l
	r.lastWrite = &cp
	return nil
}
func (r *recListenerRepo) Delete(_ context.Context, _ int) error { return nil }

type recSourceRepo struct {
	stored    *store.FlowSource
	lastWrite *store.FlowSource
	listener  *store.FlowListener // referenced by ListenerID for foreign key check
}

func (r *recSourceRepo) List(_ context.Context, _ int) ([]store.FlowSource, error) {
	return nil, nil
}
func (r *recSourceRepo) Get(_ context.Context, id int) (*store.FlowSource, error) {
	if r.stored == nil || r.stored.ID != id {
		return nil, errors.New("not found")
	}
	cp := *r.stored
	return &cp, nil
}
func (r *recSourceRepo) Create(_ context.Context, _ *store.FlowSource) (int, error) {
	return 0, nil
}
func (r *recSourceRepo) Update(_ context.Context, s *store.FlowSource) error {
	cp := *s
	r.lastWrite = &cp
	return nil
}
func (r *recSourceRepo) Delete(_ context.Context, _ int) error { return nil }

// flowStore embeds MockStore and replaces the two relevant repos with recorders.
type flowStore struct {
	*MockStore
	listeners *recListenerRepo
	sources   *recSourceRepo
}

func (s *flowStore) FlowListeners() store.FlowListenerRepo { return s.listeners }
func (s *flowStore) FlowSources() store.FlowSourceRepo    { return s.sources }

func newFlowStore(listener *store.FlowListener, source *store.FlowSource) *flowStore {
	ms := &MockStore{}
	lr := &recListenerRepo{stored: listener}
	sr := &recSourceRepo{stored: source, listener: listener}
	return &flowStore{MockStore: ms, listeners: lr, sources: sr}
}

func setupFlowRouter(s store.Store) *gin.Engine {
	gin.SetMode(gin.TestMode)
	deps := api.Dependencies{
		Store:     s,
		JWTSecret: testJWTSecret,
		APIKey:    "test-api-key",
	}
	return api.NewRouter(deps)
}

// putJSON sends a PUT with the given raw JSON body.
func putJSON(t *testing.T, r *gin.Engine, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPut, path, bytes.NewReader([]byte(body)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+makeTestToken(t))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

// ── FlowListener tests ────────────────────────────────────────────────────────

// Regression: editing a listener without carrying the enabled field must NOT
// flip Enabled to false in the database.
func TestUpdateFlowListener_OmittedEnabled_PreservesOldValue(t *testing.T) {
	old := &store.FlowListener{
		ID:            1,
		NodeID:        "node-a",
		ListenAddress: "10.0.0.1:6343",
		ProtocolMode:  "sflow",
		Enabled:       true,
		Description:   "orig",
	}
	st := newFlowStore(old, nil)
	r := setupFlowRouter(st)

	// Body omits "enabled" — simulates the frontend edit form that forgot to
	// carry it.
	body := `{"listen_address":"10.0.0.1:6343","protocol_mode":"sflow","description":"edited"}`
	w := putJSON(t, r, "/api/flow-listeners/1", body)
	if w.Code != http.StatusOK {
		t.Fatalf("PUT: want 200, got %d: %s", w.Code, w.Body.String())
	}
	if st.listeners.lastWrite == nil {
		t.Fatalf("Update was not called")
	}
	if !st.listeners.lastWrite.Enabled {
		t.Errorf("Enabled got flipped to false even though body omitted the field")
	}
	if st.listeners.lastWrite.Description != "edited" {
		t.Errorf("Description not updated: %q", st.listeners.lastWrite.Description)
	}
}

// Positive: explicit enabled=false must still take effect (the toggle-off path).
func TestUpdateFlowListener_ExplicitEnabledFalse_AppliesNewValue(t *testing.T) {
	old := &store.FlowListener{
		ID:            1,
		NodeID:        "node-a",
		ListenAddress: "10.0.0.1:6343",
		ProtocolMode:  "sflow",
		Enabled:       true,
		Description:   "orig",
	}
	st := newFlowStore(old, nil)
	r := setupFlowRouter(st)

	body := `{"listen_address":"10.0.0.1:6343","protocol_mode":"sflow","description":"orig","enabled":false}`
	w := putJSON(t, r, "/api/flow-listeners/1", body)
	if w.Code != http.StatusOK {
		t.Fatalf("PUT: want 200, got %d: %s", w.Code, w.Body.String())
	}
	if st.listeners.lastWrite.Enabled {
		t.Errorf("Enabled=false from body was ignored, still true")
	}
}

// Positive: explicit enabled=true from a disabled row re-enables.
func TestUpdateFlowListener_ExplicitEnabledTrue_FromDisabled(t *testing.T) {
	old := &store.FlowListener{
		ID: 1, NodeID: "node-a", ListenAddress: "10.0.0.1:6343",
		ProtocolMode: "sflow", Enabled: false, Description: "orig",
	}
	st := newFlowStore(old, nil)
	r := setupFlowRouter(st)

	body := `{"listen_address":"10.0.0.1:6343","protocol_mode":"sflow","description":"orig","enabled":true}`
	w := putJSON(t, r, "/api/flow-listeners/1", body)
	if w.Code != http.StatusOK {
		t.Fatalf("PUT: want 200, got %d: %s", w.Code, w.Body.String())
	}
	if !st.listeners.lastWrite.Enabled {
		t.Errorf("Enabled=true from body was not applied")
	}
}

// ── FlowSource tests ──────────────────────────────────────────────────────────

// Regression: this is exactly the production bug we fixed — editing a
// source's device_ip must not silently flip enabled to false.
func TestUpdateFlowSource_OmittedEnabled_PreservesOldValue(t *testing.T) {
	listener := &store.FlowListener{ID: 1, NodeID: "node-a", ListenAddress: "10.0.0.1:6343", ProtocolMode: "sflow", Enabled: true}
	old := &store.FlowSource{
		ID:          1,
		ListenerID:  1,
		Name:        "arista-e1-38",
		DeviceIP:    "192.0.2.10",
		SampleMode:  "auto",
		SampleRate:  1000,
		Description: "orig",
		Enabled:     true,
	}
	st := newFlowStore(listener, old)
	r := setupFlowRouter(st)

	// Simulate WebUI edit: update device_ip but omit enabled.
	body := fmt.Sprintf(`{"name":"arista-e1-38","device_ip":"198.51.100.10","sample_mode":"auto","sample_rate":1000,"description":"orig"}`)
	w := putJSON(t, r, "/api/flow-sources/1", body)
	if w.Code != http.StatusOK {
		t.Fatalf("PUT: want 200, got %d: %s", w.Code, w.Body.String())
	}
	if st.sources.lastWrite == nil {
		t.Fatalf("Update was not called")
	}
	if !st.sources.lastWrite.Enabled {
		t.Errorf("Enabled got flipped to false even though body omitted the field — this is the regression that took production offline")
	}
	if st.sources.lastWrite.DeviceIP != "198.51.100.10" {
		t.Errorf("DeviceIP not updated: %q", st.sources.lastWrite.DeviceIP)
	}
}

func TestUpdateFlowSource_ExplicitEnabledFalse_AppliesNewValue(t *testing.T) {
	listener := &store.FlowListener{ID: 1, NodeID: "node-a", ListenAddress: "10.0.0.1:6343", ProtocolMode: "sflow", Enabled: true}
	old := &store.FlowSource{
		ID: 1, ListenerID: 1, Name: "arista-e1-38", DeviceIP: "192.0.2.10",
		SampleMode: "auto", SampleRate: 1000, Enabled: true,
	}
	st := newFlowStore(listener, old)
	r := setupFlowRouter(st)

	body := `{"name":"arista-e1-38","device_ip":"192.0.2.10","sample_mode":"auto","sample_rate":1000,"description":"","enabled":false}`
	w := putJSON(t, r, "/api/flow-sources/1", body)
	if w.Code != http.StatusOK {
		t.Fatalf("PUT: want 200, got %d: %s", w.Code, w.Body.String())
	}
	if st.sources.lastWrite.Enabled {
		t.Errorf("Enabled=false from body was ignored")
	}
}

func TestUpdateFlowSource_ExplicitEnabledTrue_FromDisabled(t *testing.T) {
	listener := &store.FlowListener{ID: 1, NodeID: "node-a", ListenAddress: "10.0.0.1:6343", ProtocolMode: "sflow", Enabled: true}
	old := &store.FlowSource{
		ID: 1, ListenerID: 1, Name: "arista-e1-38", DeviceIP: "192.0.2.10",
		SampleMode: "auto", SampleRate: 1000, Enabled: false,
	}
	st := newFlowStore(listener, old)
	r := setupFlowRouter(st)

	body := `{"name":"arista-e1-38","device_ip":"192.0.2.10","sample_mode":"auto","sample_rate":1000,"description":"","enabled":true}`
	w := putJSON(t, r, "/api/flow-sources/1", body)
	if w.Code != http.StatusOK {
		t.Fatalf("PUT: want 200, got %d: %s", w.Code, w.Body.String())
	}
	if !st.sources.lastWrite.Enabled {
		t.Errorf("Enabled=true from body was not applied")
	}
}

// Sanity: invalid JSON still rejected.
func TestUpdateFlowSource_InvalidJSON_Returns400(t *testing.T) {
	listener := &store.FlowListener{ID: 1, NodeID: "node-a", ListenAddress: "10.0.0.1:6343", ProtocolMode: "sflow", Enabled: true}
	old := &store.FlowSource{ID: 1, ListenerID: 1, Name: "x", DeviceIP: "192.0.2.10", SampleMode: "auto", Enabled: true}
	st := newFlowStore(listener, old)
	r := setupFlowRouter(st)

	w := putJSON(t, r, "/api/flow-sources/1", `{not json`)
	if w.Code != http.StatusBadRequest {
		t.Errorf("want 400, got %d", w.Code)
	}
}

// Suppress unused import warning when json isn't used directly in this file.
var _ = json.Marshal
