// Package api implements the REST API for the xSight Controller.
package api

import (
	"net/http"

	"github.com/gin-contrib/gzip"
	"github.com/gin-gonic/gin"
	"github.com/littlewolf9527/xsight/controller/internal/configpub"
	"github.com/littlewolf9527/xsight/controller/internal/engine/baseline"
	"github.com/littlewolf9527/xsight/controller/internal/engine/threshold"
	"github.com/littlewolf9527/xsight/controller/internal/ingestion"
	"github.com/littlewolf9527/xsight/controller/internal/store"
	"github.com/littlewolf9527/xsight/controller/internal/tracker"
)

// Dependencies holds all dependencies injected into the API layer.
type Dependencies struct {
	Store         store.Store
	ConfigPub     *configpub.Publisher
	NodeState     *ingestion.NodeState
	ThreshTree    *threshold.Tree
	Tracker       *tracker.Tracker
	BaselineCalc  *baseline.Calculator
	ProfileEngine *baseline.ProfileEngine
	APIKey        string
	JWTSecret     string
	FlowLogsDays  int // flow_logs retention days, exposed to API for expired hint
}

// NewRouter creates and returns a configured gin.Engine.
func NewRouter(deps Dependencies) *gin.Engine {
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	// Disable trailing-slash redirects — they conflict with SPA client-side routing
	// (e.g. /settings/xdrop-connectors → 301 → /settings/ → redirect loop)
	r.RedirectTrailingSlash = false
	r.RedirectFixedPath = false
	r.Use(gin.Recovery())
	r.Use(gzip.Gzip(gzip.DefaultCompression))

	// Public endpoints
	r.POST("/api/login", loginHandler(deps))

	// API group — requires auth
	api := r.Group("/api")
	api.Use(authMiddleware(deps.APIKey, deps.JWTSecret))
	{
		// Users
		api.GET("/users", listUsers(deps))
		api.POST("/users", createUser(deps))
		api.PUT("/users/:id", updateUser(deps))
		api.DELETE("/users/:id", deleteUser(deps))

		// Nodes
		api.GET("/nodes", listNodes(deps))
		api.POST("/nodes", createNode(deps))
		api.GET("/nodes/:id", getNode(deps))
		api.PUT("/nodes/:id", updateNode(deps))
		api.DELETE("/nodes/:id", deleteNode(deps))
		api.GET("/nodes/:id/status", getNodeStatus(deps))

		// Prefixes
		api.GET("/prefixes", listPrefixes(deps))
		api.POST("/prefixes", createPrefix(deps))
		api.GET("/prefixes/:id", getPrefix(deps))
		api.PUT("/prefixes/:id", updatePrefix(deps))
		api.DELETE("/prefixes/:id", deletePrefix(deps))

		// Threshold Templates
		api.GET("/threshold-templates", listTemplates(deps))
		api.POST("/threshold-templates", createTemplate(deps))
		api.GET("/threshold-templates/:id", getTemplate(deps))
		api.PUT("/threshold-templates/:id", updateTemplate(deps))
		api.DELETE("/threshold-templates/:id", deleteTemplate(deps))
		api.POST("/threshold-templates/:id/duplicate", duplicateTemplate(deps))
		api.GET("/threshold-templates/:id/rules", listTemplateRules(deps))
		api.POST("/threshold-templates/:id/rules", createTemplateRule(deps))

		// Thresholds (per-prefix overrides)
		api.GET("/thresholds", listThresholds(deps))
		api.POST("/thresholds", createThreshold(deps))
		api.GET("/thresholds/:id", getThreshold(deps))
		api.PUT("/thresholds/:id", updateThreshold(deps))
		api.DELETE("/thresholds/:id", deleteThreshold(deps))
		// Also used for template rule edit/delete
		api.PUT("/threshold-rules/:id", updateThreshold(deps))
		api.DELETE("/threshold-rules/:id", deleteThreshold(deps))

		// Responses
		api.GET("/responses", listResponses(deps))
		api.POST("/responses", createResponse(deps))
		api.GET("/responses/:id", getResponse(deps))
		api.PUT("/responses/:id", updateResponse(deps))
		api.DELETE("/responses/:id", deleteResponse(deps))

		// Response Actions
		api.GET("/responses/:id/actions", listActions(deps))
		api.POST("/responses/:id/actions", createAction(deps))
		api.PUT("/actions/:id", updateAction(deps))
		api.DELETE("/actions/:id", deleteAction(deps))
		api.GET("/actions/:id/xdrop-targets", getXDropTargets(deps))
		api.PUT("/actions/:id/xdrop-targets", setXDropTargets(deps))
		api.GET("/actions/:id/preconditions", listPreconditions(deps))
		api.PUT("/actions/:id/preconditions", replacePreconditions(deps))

		// Webhooks
		api.GET("/webhooks", listWebhooks(deps))
		api.POST("/webhooks", createWebhook(deps))
		api.PUT("/webhooks/:id", updateWebhook(deps))
		api.DELETE("/webhooks/:id", deleteWebhook(deps))

		// Stats summary (lightweight, for Dashboard)
		api.GET("/stats/summary", statsSummary(deps))

		// Baseline recommendations
		api.GET("/baseline", listBaselines(deps))

		// Time-series data for charts
		api.GET("/stats/timeseries", queryTimeseries(deps))

		// Traffic overview (real-time from ring buffer + total timeseries)
		api.GET("/stats/overview", trafficOverview(deps))
		api.GET("/stats/total-timeseries", totalTimeseries(deps))

		// Attacks
		api.GET("/attacks", listAttacks(deps))
		api.GET("/attacks/active", listActiveAttacks(deps))
		api.GET("/attacks/:id", getAttack(deps))
		api.GET("/attacks/:id/action-log", getAttackActionLog(deps))
		api.GET("/attacks/:id/sensor-logs", getAttackSensorLogs(deps))
		api.POST("/attacks/:id/expire", expireAttack(deps))

		// Audit log
		api.GET("/audit-log", listAuditLog(deps))

		// Dynamic detection
		api.GET("/dynamic-detection/config", getDynDetectConfig(deps))
		api.PUT("/dynamic-detection/config", updateDynDetectConfig(deps))
		api.GET("/dynamic-detection/status", getDynDetectStatus(deps))

		// Settings — Response System v2 Connectors
		settings := api.Group("/settings")
		{
			// Webhook Connectors
			settings.GET("/webhook-connectors", listWebhookConnectors(deps))
			settings.POST("/webhook-connectors", createWebhookConnector(deps))
			settings.GET("/webhook-connectors/:id", getWebhookConnector(deps))
			settings.PUT("/webhook-connectors/:id", updateWebhookConnector(deps))
			settings.DELETE("/webhook-connectors/:id", deleteWebhookConnector(deps))
			settings.POST("/webhook-connectors/:id/test", testWebhookConnector(deps))

			// xDrop Connectors
			settings.GET("/xdrop-connectors", listXDropConnectors(deps))
			settings.POST("/xdrop-connectors", createXDropConnector(deps))
			settings.GET("/xdrop-connectors/:id", getXDropConnector(deps))
			settings.PUT("/xdrop-connectors/:id", updateXDropConnector(deps))
			settings.DELETE("/xdrop-connectors/:id", deleteXDropConnector(deps))
			settings.POST("/xdrop-connectors/:id/test", testXDropConnector(deps))

			// Shell Connectors
			settings.GET("/shell-connectors", listShellConnectors(deps))
			settings.POST("/shell-connectors", createShellConnector(deps))
			settings.GET("/shell-connectors/:id", getShellConnector(deps))
			settings.PUT("/shell-connectors/:id", updateShellConnector(deps))
			settings.DELETE("/shell-connectors/:id", deleteShellConnector(deps))

			// BGP Connectors (v3.1)
			settings.GET("/bgp-connectors", listBGPConnectors(deps))
			settings.POST("/bgp-connectors", createBGPConnector(deps))
			settings.GET("/bgp-connectors/:id", getBGPConnector(deps))
			settings.PUT("/bgp-connectors/:id", updateBGPConnector(deps))
			settings.DELETE("/bgp-connectors/:id", deleteBGPConnector(deps))
			settings.POST("/bgp-connectors/:id/test", testBGPConnector(deps))
			settings.GET("/bgp-connectors/:id/routes", listBGPRoutes(deps))
		}

		// v3.0: Flow Listeners + Sources
		api.GET("/flow-listeners", listFlowListeners(deps))
		api.POST("/flow-listeners", createFlowListener(deps))
		api.GET("/flow-listeners/:id", getFlowListener(deps))
		api.PUT("/flow-listeners/:id", updateFlowListener(deps))
		api.DELETE("/flow-listeners/:id", deleteFlowListener(deps))

		api.GET("/flow-sources", listFlowSources(deps))
		api.POST("/flow-sources", createFlowSource(deps))
		api.GET("/flow-sources/:id", getFlowSource(deps))
		api.PUT("/flow-sources/:id", updateFlowSource(deps))
		api.DELETE("/flow-sources/:id", deleteFlowSource(deps))
	}

	// SPA fallback: non-/api/ paths serve frontend (Phase 8)
	r.NoRoute(func(c *gin.Context) {
		c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
	})

	return r
}

// JSON response helpers
func ok(c *gin.Context, data any) {
	c.JSON(http.StatusOK, data)
}

func created(c *gin.Context, data any) {
	c.JSON(http.StatusCreated, data)
}

func errResponse(c *gin.Context, code int, msg string) {
	c.JSON(code, gin.H{"error": msg})
}
