package api

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/littlewolf9527/xsight/controller/internal/store"
)

func listNodes(deps Dependencies) gin.HandlerFunc {
	return func(c *gin.Context) {
		nodes, err := deps.Store.Nodes().List(c)
		if err != nil {
			errResponse(c, http.StatusInternalServerError, err.Error())
			return
		}
		// Enrich with online status
		type nodeWithStatus struct {
			store.Node
			Online bool `json:"online"`
		}
		var result []nodeWithStatus
		for _, n := range nodes {
			result = append(result, nodeWithStatus{
				Node:   n,
				Online: deps.NodeState.IsOnline(n.ID),
			})
		}
		ok(c, result)
	}
}

func createNode(deps Dependencies) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req struct {
			ID          string `json:"id" binding:"required"`
			APIKey      string `json:"api_key" binding:"required"`
			Description string `json:"description"`
			Mode        string `json:"mode"` // "xdp" (default) | "flow"
		}
		if err := c.ShouldBindJSON(&req); err != nil {
			errResponse(c, http.StatusBadRequest, err.Error())
			return
		}
		if req.Mode == "" {
			req.Mode = "xdp"
		}
		if req.Mode != "xdp" && req.Mode != "flow" {
			errResponse(c, http.StatusBadRequest, "mode must be 'xdp' or 'flow'")
			return
		}
		if err := deps.Store.Nodes().Create(c, &store.Node{
			ID: req.ID, APIKey: req.APIKey, Description: req.Description, Mode: req.Mode, Enabled: true,
		}); err != nil {
			errResponse(c, http.StatusInternalServerError, err.Error())
			return
		}
		created(c, gin.H{"id": req.ID})
	}
}

func getNode(deps Dependencies) gin.HandlerFunc {
	return func(c *gin.Context) {
		node, err := deps.Store.Nodes().Get(c, c.Param("id"))
		if err != nil {
			errResponse(c, http.StatusNotFound, "node not found")
			return
		}
		ok(c, node)
	}
}

func updateNode(deps Dependencies) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req struct {
			Description string `json:"description"`
			Mode        string `json:"mode"`
			Enabled     *bool  `json:"enabled"`
		}
		if err := c.ShouldBindJSON(&req); err != nil {
			errResponse(c, http.StatusBadRequest, err.Error())
			return
		}
		if req.Mode != "" && req.Mode != "xdp" && req.Mode != "flow" {
			errResponse(c, http.StatusBadRequest, "mode must be 'xdp' or 'flow'")
			return
		}
		node, err := deps.Store.Nodes().Get(c, c.Param("id"))
		if err != nil {
			errResponse(c, http.StatusNotFound, "node not found")
			return
		}
		if req.Description != "" {
			node.Description = req.Description
		}
		if req.Mode != "" {
			node.Mode = req.Mode
		}
		if req.Enabled != nil {
			node.Enabled = *req.Enabled
		}
		if err := deps.Store.Nodes().Update(c, node); err != nil {
			errResponse(c, http.StatusInternalServerError, err.Error())
			return
		}
		ok(c, gin.H{"ok": true})
	}
}

func deleteNode(deps Dependencies) gin.HandlerFunc {
	return func(c *gin.Context) {
		nodeID := c.Param("id")
		// Cascade: delete flow listeners (sources cascade via FK) before deleting node
		listeners, err := deps.Store.FlowListeners().List(c, nodeID)
		if err != nil {
			errResponse(c, http.StatusInternalServerError, "failed to list flow listeners: "+err.Error())
			return
		}
		for _, l := range listeners {
			if err := deps.Store.FlowListeners().Delete(c, l.ID); err != nil {
				errResponse(c, http.StatusInternalServerError, "failed to delete flow listener: "+err.Error())
				return
			}
		}
		if err := deps.Store.Nodes().Delete(c, nodeID); err != nil {
			errResponse(c, http.StatusInternalServerError, err.Error())
			return
		}
		ok(c, gin.H{"ok": true})
	}
}

func getNodeStatus(deps Dependencies) gin.HandlerFunc {
	return func(c *gin.Context) {
		node, err := deps.Store.Nodes().Get(c, c.Param("id"))
		if err != nil {
			errResponse(c, http.StatusNotFound, "node not found")
			return
		}
		online := deps.NodeState.IsOnline(node.ID)
		lastStats := deps.NodeState.LastStatsAt(node.ID)
		drift := node.DeliveryVersionCurrent - node.DeliveryVersionApplied

		status := gin.H{
			"id":                       node.ID,
			"mode":                     node.Mode,
			"online":                   online,
			"config_status":            node.ConfigStatus,
			"delivery_version_current": node.DeliveryVersionCurrent,
			"delivery_version_applied": node.DeliveryVersionApplied,
			"drift":                    drift,
			"last_ack_at":              node.LastACKAt,
		}
		if !lastStats.IsZero() {
			status["last_stats_at"] = lastStats
			status["stats_age_seconds"] = int(time.Since(lastStats).Seconds())
		}
		connAt := deps.NodeState.ConnectedAt(node.ID)
		if !connAt.IsZero() {
			status["connected_at"] = connAt
			status["uptime_seconds"] = int(time.Since(connAt).Seconds())
		}
		// Flow node metrics (decode errors, unknown exporter, template misses)
		if fm := deps.NodeState.GetFlowMetrics(node.ID); fm != nil {
			status["flow_metrics"] = fm
		}
		if ss := deps.NodeState.GetSourceStatuses(node.ID); len(ss) > 0 {
			status["source_statuses"] = ss
		}
		if ls := deps.NodeState.GetListenerStatuses(node.ID); len(ls) > 0 {
			status["listener_statuses"] = ls
		}
		ok(c, status)
	}
}
