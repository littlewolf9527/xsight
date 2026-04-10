package api

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/littlewolf9527/xsight/controller/internal/store"
)

// --- xDrop Connectors (Response System v2) ---

// maskAPIKey returns the last 4 characters prefixed with "***",
// or "***" if the key is too short.
func maskAPIKey(key string) string {
	if len(key) <= 4 {
		return "***"
	}
	return "***" + key[len(key)-4:]
}

// xDropConnectorView is a JSON-safe view with the API key masked.
type xDropConnectorView struct {
	ID           int       `json:"id"`
	Name         string    `json:"name"`
	APIURL       string    `json:"api_url"`
	APIKeyMasked string    `json:"api_key"`
	TimeoutMs    int       `json:"timeout_ms"`
	Enabled      bool      `json:"enabled"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

func toXDropView(c *store.XDropConnector) xDropConnectorView {
	return xDropConnectorView{
		ID:           c.ID,
		Name:         c.Name,
		APIURL:       c.APIURL,
		APIKeyMasked: maskAPIKey(c.APIKey),
		TimeoutMs:    c.TimeoutMs,
		Enabled:      c.Enabled,
		CreatedAt:    c.CreatedAt,
		UpdatedAt:    c.UpdatedAt,
	}
}

func listXDropConnectors(deps Dependencies) gin.HandlerFunc {
	return func(c *gin.Context) {
		connectors, err := deps.Store.XDropConnectors().List(c)
		if err != nil {
			errResponse(c, http.StatusInternalServerError, err.Error())
			return
		}
		views := make([]xDropConnectorView, len(connectors))
		for i := range connectors {
			views[i] = toXDropView(&connectors[i])
		}
		ok(c, views)
	}
}

func createXDropConnector(deps Dependencies) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req struct {
			Name      string `json:"name"`
			APIURL    string `json:"api_url"`
			APIKey    string `json:"api_key"`
			TimeoutMs int    `json:"timeout_ms"`
		}
		if err := c.ShouldBindJSON(&req); err != nil {
			errResponse(c, http.StatusBadRequest, err.Error())
			return
		}
		if req.Name == "" {
			errResponse(c, http.StatusBadRequest, "name is required")
			return
		}
		if req.APIURL == "" {
			errResponse(c, http.StatusBadRequest, "api_url is required")
			return
		}
		if req.APIKey == "" {
			errResponse(c, http.StatusBadRequest, "api_key is required")
			return
		}
		if req.TimeoutMs == 0 {
			req.TimeoutMs = 10000
		}

		conn := &store.XDropConnector{
			Name:      req.Name,
			APIURL:    strings.TrimRight(req.APIURL, "/"),
			APIKey:    req.APIKey,
			TimeoutMs: req.TimeoutMs,
			Enabled:   true,
		}
		id, err := deps.Store.XDropConnectors().Create(c, conn)
		if err != nil {
			errResponse(c, http.StatusInternalServerError, err.Error())
			return
		}
		conn.ID = id
		publishAfterChange(c, deps, "xdrop_connector", strconv.Itoa(id), "create", makeDiff(nil, toXDropView(conn)))
		created(c, gin.H{"id": id})
	}
}

func getXDropConnector(deps Dependencies) gin.HandlerFunc {
	return func(c *gin.Context) {
		id, _ := strconv.Atoi(c.Param("id"))
		conn, err := deps.Store.XDropConnectors().Get(c, id)
		if err != nil {
			errResponse(c, http.StatusNotFound, "xdrop connector not found")
			return
		}
		ok(c, toXDropView(conn))
	}
}

func updateXDropConnector(deps Dependencies) gin.HandlerFunc {
	return func(c *gin.Context) {
		id, _ := strconv.Atoi(c.Param("id"))
		old, err := deps.Store.XDropConnectors().Get(c, id)
		if err != nil {
			errResponse(c, http.StatusNotFound, "xdrop connector not found")
			return
		}

		var req struct {
			Name      string `json:"name"`
			APIURL    string `json:"api_url"`
			APIKey    string `json:"api_key"`
			TimeoutMs int    `json:"timeout_ms"`
			Enabled   bool   `json:"enabled"`
		}
		if err := c.ShouldBindJSON(&req); err != nil {
			errResponse(c, http.StatusBadRequest, err.Error())
			return
		}

		conn := &store.XDropConnector{
			ID:        id,
			Name:      req.Name,
			APIURL:    strings.TrimRight(req.APIURL, "/"),
			APIKey:    req.APIKey,
			TimeoutMs: req.TimeoutMs,
			Enabled:   req.Enabled,
		}
		// If no new API key provided, keep the old one
		if conn.APIKey == "" {
			conn.APIKey = old.APIKey
		}

		if err := deps.Store.XDropConnectors().Update(c, conn); err != nil {
			errResponse(c, http.StatusInternalServerError, err.Error())
			return
		}
		publishAfterChange(c, deps, "xdrop_connector", strconv.Itoa(id), "update", makeDiff(toXDropView(old), toXDropView(conn)))
		ok(c, gin.H{"ok": true})
	}
}

func deleteXDropConnector(deps Dependencies) gin.HandlerFunc {
	return func(c *gin.Context) {
		id, _ := strconv.Atoi(c.Param("id"))
		// Check if any action targets this connector (fail closed on error)
		count, err := deps.Store.XDropTargets().CountByConnector(c, id)
		if err != nil {
			errResponse(c, http.StatusInternalServerError, "failed to check connector usage: "+err.Error())
			return
		}
		if count > 0 {
			errResponse(c, http.StatusConflict,
				fmt.Sprintf("xDrop connector in use by %d action(s)", count))
			return
		}
		old, _ := deps.Store.XDropConnectors().Get(c, id)
		if err := deps.Store.XDropConnectors().Delete(c, id); err != nil {
			errResponse(c, http.StatusInternalServerError, err.Error())
			return
		}
		var diff interface{}
		if old != nil {
			diff = toXDropView(old)
		}
		publishAfterChange(c, deps, "xdrop_connector", strconv.Itoa(id), "delete", makeDiff(diff, nil))
		ok(c, gin.H{"ok": true})
	}
}

func testXDropConnector(deps Dependencies) gin.HandlerFunc {
	return func(c *gin.Context) {
		id, _ := strconv.Atoi(c.Param("id"))
		conn, err := deps.Store.XDropConnectors().Get(c, id)
		if err != nil {
			errResponse(c, http.StatusNotFound, "xdrop connector not found")
			return
		}

		// Test by calling GET {api_url}/health on the xDrop endpoint.
		// api_url is the versioned API base (e.g. http://host:8000/api/v1),
		// consistent with runtime execution which appends /rules.
		healthURL := strings.TrimRight(conn.APIURL, "/") + "/health"
		req, err := http.NewRequestWithContext(c, http.MethodGet, healthURL, nil)
		if err != nil {
			errResponse(c, http.StatusBadRequest, "invalid connector URL: "+err.Error())
			return
		}
		req.Header.Set("X-API-Key", conn.APIKey)

		timeout := time.Duration(conn.TimeoutMs) * time.Millisecond
		if timeout == 0 {
			timeout = 10 * time.Second
		}
		client := &http.Client{Timeout: timeout}

		resp, err := client.Do(req)
		if err != nil {
			ok(c, gin.H{"success": false, "error": fmt.Sprintf("health check failed: %v", err)})
			return
		}
		defer resp.Body.Close()

		ok(c, gin.H{
			"success":     resp.StatusCode >= 200 && resp.StatusCode < 300,
			"status_code": resp.StatusCode,
		})
	}
}
