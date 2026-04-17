package action

// Regression tests for webhook header handling.

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/littlewolf9527/xsight/controller/internal/store"
)

// Regression: previously `json.Unmarshal(headersJSON, &headers)` discarded the
// error. When a user configured a webhook connector with malformed headers
// JSON, the unmarshal failed silently and the request was sent with no custom
// headers (not even a log line). v1.1.6 logs the error explicitly.
func TestPostWebhookWithFA_MalformedHeaders_StillDeliversAndLogs(t *testing.T) {
	var received http.Header
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received = r.Header.Clone()
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	// Capture log output to assert the warning was emitted.
	var logBuf bytes.Buffer
	origOut := log.Writer()
	log.SetOutput(&logBuf)
	defer log.SetOutput(origOut)

	attack := &store.Attack{ID: 1, DstIP: "192.0.2.1", DecoderFamily: "ip"}
	body, err := postWebhookWithFA(context.Background(), srv.URL, json.RawMessage(`{not valid json`), attack, "on_detected", nil)
	if err != nil {
		t.Fatalf("postWebhookWithFA returned error despite bad headers: %v", err)
	}
	if received == nil {
		t.Fatal("request never reached server")
	}
	if !bytes.Contains(logBuf.Bytes(), []byte("malformed headers JSON")) {
		t.Errorf("expected log warning about malformed headers, got: %s", logBuf.String())
	}
	// Response body should be non-empty success string
	if body == "" {
		t.Error("expected non-empty response body")
	}
}

// Positive: valid headers JSON must still be delivered as custom headers.
func TestPostWebhookWithFA_ValidHeaders_AppliedToRequest(t *testing.T) {
	var received http.Header
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received = r.Header.Clone()
		io.Copy(io.Discard, r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	attack := &store.Attack{ID: 1, DstIP: "192.0.2.1", DecoderFamily: "ip"}
	_, err := postWebhookWithFA(context.Background(), srv.URL,
		json.RawMessage(`{"X-Auth-Token":"secret123","X-Env":"prod"}`),
		attack, "on_detected", nil)
	if err != nil {
		t.Fatalf("postWebhookWithFA: %v", err)
	}
	if got := received.Get("X-Auth-Token"); got != "secret123" {
		t.Errorf("X-Auth-Token not delivered: got %q", got)
	}
	if got := received.Get("X-Env"); got != "prod" {
		t.Errorf("X-Env not delivered: got %q", got)
	}
}
