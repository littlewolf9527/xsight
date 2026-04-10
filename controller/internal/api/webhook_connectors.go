package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/littlewolf9527/xsight/controller/internal/store"
)

// --- Webhook Connectors (Response System v2) ---

func listWebhookConnectors(deps Dependencies) gin.HandlerFunc {
	return func(c *gin.Context) {
		connectors, err := deps.Store.WebhookConnectors().List(c)
		if err != nil {
			errResponse(c, http.StatusInternalServerError, err.Error())
			return
		}
		ok(c, connectors)
	}
}

func createWebhookConnector(deps Dependencies) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req store.WebhookConnector
		if err := c.ShouldBindJSON(&req); err != nil {
			errResponse(c, http.StatusBadRequest, err.Error())
			return
		}
		if req.Name == "" {
			errResponse(c, http.StatusBadRequest, "name is required")
			return
		}
		if req.URL == "" {
			errResponse(c, http.StatusBadRequest, "url is required")
			return
		}
		if req.Method == "" {
			req.Method = "POST"
		}
		if req.TimeoutMs == 0 {
			req.TimeoutMs = 10000
		}
		req.Enabled = true

		id, err := deps.Store.WebhookConnectors().Create(c, &req)
		if err != nil {
			errResponse(c, http.StatusInternalServerError, err.Error())
			return
		}
		req.ID = id
		publishAfterChange(c, deps, "webhook_connector", strconv.Itoa(id), "create", makeDiff(nil, req))
		created(c, gin.H{"id": id})
	}
}

func getWebhookConnector(deps Dependencies) gin.HandlerFunc {
	return func(c *gin.Context) {
		id, _ := strconv.Atoi(c.Param("id"))
		conn, err := deps.Store.WebhookConnectors().Get(c, id)
		if err != nil {
			errResponse(c, http.StatusNotFound, "webhook connector not found")
			return
		}
		ok(c, conn)
	}
}

func updateWebhookConnector(deps Dependencies) gin.HandlerFunc {
	return func(c *gin.Context) {
		id, _ := strconv.Atoi(c.Param("id"))
		old, err := deps.Store.WebhookConnectors().Get(c, id)
		if err != nil {
			errResponse(c, http.StatusNotFound, "webhook connector not found")
			return
		}
		var req store.WebhookConnector
		if err := c.ShouldBindJSON(&req); err != nil {
			errResponse(c, http.StatusBadRequest, err.Error())
			return
		}
		req.ID = id
		if err := deps.Store.WebhookConnectors().Update(c, &req); err != nil {
			errResponse(c, http.StatusInternalServerError, err.Error())
			return
		}
		publishAfterChange(c, deps, "webhook_connector", strconv.Itoa(id), "update", makeDiff(old, req))
		ok(c, gin.H{"ok": true})
	}
}

func deleteWebhookConnector(deps Dependencies) gin.HandlerFunc {
	return func(c *gin.Context) {
		id, _ := strconv.Atoi(c.Param("id"))
		// Check if any action references this webhook connector (fail closed on error)
		count, err := deps.Store.Responses().CountActionsByWebhookConnector(c, id)
		if err != nil {
			errResponse(c, http.StatusInternalServerError, "failed to check connector usage: "+err.Error())
			return
		}
		if count > 0 {
			errResponse(c, http.StatusConflict,
				fmt.Sprintf("webhook connector in use by %d action(s)", count))
			return
		}
		old, _ := deps.Store.WebhookConnectors().Get(c, id)
		if err := deps.Store.WebhookConnectors().Delete(c, id); err != nil {
			errResponse(c, http.StatusInternalServerError, err.Error())
			return
		}
		publishAfterChange(c, deps, "webhook_connector", strconv.Itoa(id), "delete", makeDiff(old, nil))
		ok(c, gin.H{"ok": true})
	}
}

func testWebhookConnector(deps Dependencies) gin.HandlerFunc {
	return func(c *gin.Context) {
		id, _ := strconv.Atoi(c.Param("id"))
		conn, err := deps.Store.WebhookConnectors().Get(c, id)
		if err != nil {
			errResponse(c, http.StatusNotFound, "webhook connector not found")
			return
		}

		// Build test payload
		testPayload := map[string]any{
			"event": "test",
			"message": fmt.Sprintf("Test webhook from xSight to connector %q", conn.Name),
			"timestamp": time.Now().UTC().Format(time.RFC3339),
		}
		body, _ := json.Marshal(testPayload)

		req, err := http.NewRequestWithContext(c, conn.Method, conn.URL, bytes.NewReader(body))
		if err != nil {
			errResponse(c, http.StatusBadRequest, "invalid connector URL: "+err.Error())
			return
		}
		req.Header.Set("Content-Type", "application/json")

		// Apply custom headers
		if len(conn.Headers) > 0 {
			var headers map[string]string
			if err := json.Unmarshal(conn.Headers, &headers); err == nil {
				for k, v := range headers {
					req.Header.Set(k, v)
				}
			}
		}

		timeout := time.Duration(conn.TimeoutMs) * time.Millisecond
		if timeout == 0 {
			timeout = 10 * time.Second
		}
		client := &http.Client{Timeout: timeout}

		resp, err := client.Do(req)
		if err != nil {
			ok(c, gin.H{"success": false, "error": err.Error()})
			return
		}
		defer resp.Body.Close()

		ok(c, gin.H{
			"success":     resp.StatusCode >= 200 && resp.StatusCode < 300,
			"status_code": resp.StatusCode,
		})
	}
}
