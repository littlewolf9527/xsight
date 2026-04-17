package api

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/littlewolf9527/xsight/controller/internal/store"
)

// --- Flow Listeners ---

func listFlowListeners(deps Dependencies) gin.HandlerFunc {
	return func(c *gin.Context) {
		nodeID := c.Query("node_id")
		if nodeID == "" {
			errResponse(c, http.StatusBadRequest, "node_id is required")
			return
		}
		list, err := deps.Store.FlowListeners().List(c, nodeID)
		if err != nil {
			errResponse(c, http.StatusInternalServerError, err.Error())
			return
		}
		if list == nil {
			list = []store.FlowListener{}
		}
		ok(c, list)
	}
}

func getFlowListener(deps Dependencies) gin.HandlerFunc {
	return func(c *gin.Context) {
		id, _ := strconv.Atoi(c.Param("id"))
		l, err := deps.Store.FlowListeners().Get(c, id)
		if err != nil {
			errResponse(c, http.StatusNotFound, "flow listener not found")
			return
		}
		// Include sources
		sources, err := deps.Store.FlowSources().List(c, id)
		if err != nil {
			errResponse(c, http.StatusInternalServerError, "failed to load sources: "+err.Error())
			return
		}
		if sources == nil {
			sources = []store.FlowSource{}
		}
		ok(c, gin.H{"listener": l, "sources": sources})
	}
}

func createFlowListener(deps Dependencies) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req store.FlowListener
		if err := c.ShouldBindJSON(&req); err != nil {
			errResponse(c, http.StatusBadRequest, err.Error())
			return
		}
		if err := validateFlowListener(&req); err != nil {
			errResponse(c, http.StatusBadRequest, err.Error())
			return
		}
		// Verify node exists and is flow mode
		node, err := deps.Store.Nodes().Get(c, req.NodeID)
		if err != nil {
			errResponse(c, http.StatusBadRequest, "node_id not found: "+req.NodeID)
			return
		}
		if node.Mode != "flow" {
			errResponse(c, http.StatusBadRequest, fmt.Sprintf("node %s is mode=%s, flow listeners require mode=flow", req.NodeID, node.Mode))
			return
		}
		req.Enabled = true
		id, err := deps.Store.FlowListeners().Create(c, &req)
		if err != nil {
			errResponse(c, http.StatusInternalServerError, err.Error())
			return
		}
		publishAfterChange(c, deps, "flow_listener", strconv.Itoa(id), "create", makeDiff(nil, req))
		created(c, gin.H{"id": id})
	}
}

func updateFlowListener(deps Dependencies) gin.HandlerFunc {
	return func(c *gin.Context) {
		id, _ := strconv.Atoi(c.Param("id"))
		old, err := deps.Store.FlowListeners().Get(c, id)
		if err != nil {
			errResponse(c, http.StatusNotFound, "flow listener not found")
			return
		}
		body, _ := io.ReadAll(c.Request.Body)
		var req store.FlowListener
		if err := json.Unmarshal(body, &req); err != nil {
			errResponse(c, http.StatusBadRequest, err.Error())
			return
		}
		// Preserve fields not present in request body (defense against partial updates)
		var raw map[string]json.RawMessage
		_ = json.Unmarshal(body, &raw)
		if _, ok := raw["enabled"]; !ok {
			req.Enabled = old.Enabled
		}
		req.ID = id
		req.NodeID = old.NodeID // node_id is immutable
		if err := validateFlowListener(&req); err != nil {
			errResponse(c, http.StatusBadRequest, err.Error())
			return
		}
		if err := deps.Store.FlowListeners().Update(c, &req); err != nil {
			errResponse(c, http.StatusInternalServerError, err.Error())
			return
		}
		publishAfterChange(c, deps, "flow_listener", strconv.Itoa(id), "update", makeDiff(old, req))
		ok(c, gin.H{"ok": true})
	}
}

func deleteFlowListener(deps Dependencies) gin.HandlerFunc {
	return func(c *gin.Context) {
		id, _ := strconv.Atoi(c.Param("id"))
		old, _ := deps.Store.FlowListeners().Get(c, id)
		if err := deps.Store.FlowListeners().Delete(c, id); err != nil {
			errResponse(c, http.StatusInternalServerError, err.Error())
			return
		}
		publishAfterChange(c, deps, "flow_listener", strconv.Itoa(id), "delete", makeDiff(old, nil))
		ok(c, gin.H{"ok": true})
	}
}

// --- Flow Sources ---

func listFlowSources(deps Dependencies) gin.HandlerFunc {
	return func(c *gin.Context) {
		listenerID, err := strconv.Atoi(c.Query("listener_id"))
		if err != nil {
			errResponse(c, http.StatusBadRequest, "listener_id is required")
			return
		}
		list, err := deps.Store.FlowSources().List(c, listenerID)
		if err != nil {
			errResponse(c, http.StatusInternalServerError, err.Error())
			return
		}
		if list == nil {
			list = []store.FlowSource{}
		}
		ok(c, list)
	}
}

func getFlowSource(deps Dependencies) gin.HandlerFunc {
	return func(c *gin.Context) {
		id, _ := strconv.Atoi(c.Param("id"))
		s, err := deps.Store.FlowSources().Get(c, id)
		if err != nil {
			errResponse(c, http.StatusNotFound, "flow source not found")
			return
		}
		ok(c, s)
	}
}

func createFlowSource(deps Dependencies) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req store.FlowSource
		if err := c.ShouldBindJSON(&req); err != nil {
			errResponse(c, http.StatusBadRequest, err.Error())
			return
		}
		if err := validateFlowSource(&req); err != nil {
			errResponse(c, http.StatusBadRequest, err.Error())
			return
		}
		// Verify listener exists
		if _, err := deps.Store.FlowListeners().Get(c, req.ListenerID); err != nil {
			errResponse(c, http.StatusBadRequest, "listener_id not found")
			return
		}
		req.Enabled = true
		id, err := deps.Store.FlowSources().Create(c, &req)
		if err != nil {
			errResponse(c, http.StatusInternalServerError, err.Error())
			return
		}
		publishAfterChange(c, deps, "flow_source", strconv.Itoa(id), "create", makeDiff(nil, req))
		created(c, gin.H{"id": id})
	}
}

func updateFlowSource(deps Dependencies) gin.HandlerFunc {
	return func(c *gin.Context) {
		id, _ := strconv.Atoi(c.Param("id"))
		old, err := deps.Store.FlowSources().Get(c, id)
		if err != nil {
			errResponse(c, http.StatusNotFound, "flow source not found")
			return
		}
		body, _ := io.ReadAll(c.Request.Body)
		var req store.FlowSource
		if err := json.Unmarshal(body, &req); err != nil {
			errResponse(c, http.StatusBadRequest, err.Error())
			return
		}
		// Preserve fields not present in request body (defense against partial updates)
		var raw map[string]json.RawMessage
		_ = json.Unmarshal(body, &raw)
		if _, ok := raw["enabled"]; !ok {
			req.Enabled = old.Enabled
		}
		req.ID = id
		req.ListenerID = old.ListenerID // listener_id is immutable
		if err := validateFlowSource(&req); err != nil {
			errResponse(c, http.StatusBadRequest, err.Error())
			return
		}
		if err := deps.Store.FlowSources().Update(c, &req); err != nil {
			errResponse(c, http.StatusInternalServerError, err.Error())
			return
		}
		publishAfterChange(c, deps, "flow_source", strconv.Itoa(id), "update", makeDiff(old, req))
		ok(c, gin.H{"ok": true})
	}
}

func deleteFlowSource(deps Dependencies) gin.HandlerFunc {
	return func(c *gin.Context) {
		id, _ := strconv.Atoi(c.Param("id"))
		old, _ := deps.Store.FlowSources().Get(c, id)
		if err := deps.Store.FlowSources().Delete(c, id); err != nil {
			errResponse(c, http.StatusInternalServerError, err.Error())
			return
		}
		publishAfterChange(c, deps, "flow_source", strconv.Itoa(id), "delete", makeDiff(old, nil))
		ok(c, gin.H{"ok": true})
	}
}

// --- Validation ---

var validProtocolModes = map[string]bool{"auto": true, "sflow": true, "netflow": true, "ipfix": true}
var validSampleModes = map[string]bool{"auto": true, "force": true, "none": true}

func validateFlowListener(l *store.FlowListener) error {
	if l.NodeID == "" {
		return fmt.Errorf("node_id is required")
	}
	if l.ListenAddress == "" {
		return fmt.Errorf("listen_address is required")
	}
	// Validate listen_address format: ":port" or "host:port"
	_, portStr, err := net.SplitHostPort(l.ListenAddress)
	if err != nil {
		// Try ":port" format
		if !strings.HasPrefix(l.ListenAddress, ":") {
			return fmt.Errorf("listen_address must be :port or host:port format")
		}
		portStr = l.ListenAddress[1:]
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 {
		return fmt.Errorf("listen_address port must be 1-65535")
	}
	if !validProtocolModes[l.ProtocolMode] {
		return fmt.Errorf("protocol_mode must be 'auto', 'sflow', 'netflow', or 'ipfix'")
	}
	return nil
}

func validateFlowSource(s *store.FlowSource) error {
	if s.Name == "" {
		return fmt.Errorf("name is required")
	}
	if s.DeviceIP == "" {
		return fmt.Errorf("device_ip is required")
	}
	if net.ParseIP(s.DeviceIP) == nil {
		return fmt.Errorf("device_ip must be a valid IPv4 or IPv6 address")
	}
	if !validSampleModes[s.SampleMode] {
		return fmt.Errorf("sample_mode must be 'auto', 'force', or 'none'")
	}
	if s.SampleMode == "force" && s.SampleRate <= 0 {
		return fmt.Errorf("sample_rate must be > 0 when sample_mode is 'force'")
	}
	return nil
}
