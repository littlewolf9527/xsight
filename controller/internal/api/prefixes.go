package api

import (
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/littlewolf9527/xsight/controller/internal/store"
)

func listPrefixes(deps Dependencies) gin.HandlerFunc {
	return func(c *gin.Context) {
		prefixes, err := deps.Store.Prefixes().ListTree(c)
		if err != nil {
			errResponse(c, http.StatusInternalServerError, err.Error())
			return
		}
		ok(c, prefixes)
	}
}

func createPrefix(deps Dependencies) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req struct {
			Prefix              string `json:"prefix" binding:"required"`
			ParentID            *int   `json:"parent_id"`
			ThresholdTemplateID *int   `json:"threshold_template_id"`
			Name                string `json:"name"`
			IPGroup             string `json:"ip_group"`
		}
		if err := c.ShouldBindJSON(&req); err != nil {
			errResponse(c, http.StatusBadRequest, err.Error())
			return
		}
		// ::/0 is not allowed — use 0.0.0.0/0 for global threshold (covers both IPv4 and IPv6)
		if req.Prefix == "::/0" {
			errResponse(c, http.StatusBadRequest, "Use 0.0.0.0/0 for global threshold (covers both IPv4 and IPv6)")
			return
		}
		id, err := deps.Store.Prefixes().Create(c, &store.WatchPrefix{
			Prefix: req.Prefix, ParentID: req.ParentID, ThresholdTemplateID: req.ThresholdTemplateID,
			Name: req.Name, IPGroup: req.IPGroup, Enabled: true,
		})
		if err != nil {
			errResponse(c, http.StatusInternalServerError, err.Error())
			return
		}
		// Trigger config push to nodes
		publishAfterChange(c, deps, "watch_prefix", strconv.Itoa(id), "create", makeDiff(nil, store.WatchPrefix{
			ID: id, Prefix: req.Prefix, ParentID: req.ParentID, ThresholdTemplateID: req.ThresholdTemplateID,
			Name: req.Name, IPGroup: req.IPGroup, Enabled: true,
		}))
		created(c, gin.H{"id": id})
	}
}

func getPrefix(deps Dependencies) gin.HandlerFunc {
	return func(c *gin.Context) {
		id, _ := strconv.Atoi(c.Param("id"))
		p, err := deps.Store.Prefixes().Get(c, id)
		if err != nil {
			errResponse(c, http.StatusNotFound, "prefix not found")
			return
		}
		ok(c, p)
	}
}

func updatePrefix(deps Dependencies) gin.HandlerFunc {
	return func(c *gin.Context) {
		id, _ := strconv.Atoi(c.Param("id"))
		// Use a map to detect which fields were actually sent
		var raw map[string]any
		if err := c.ShouldBindJSON(&raw); err != nil {
			errResponse(c, http.StatusBadRequest, err.Error())
			return
		}
		p, err := deps.Store.Prefixes().Get(c, id)
		if err != nil {
			errResponse(c, http.StatusNotFound, "prefix not found")
			return
		}
		oldP := *p // snapshot before modification
		if v, ok := raw["prefix"]; ok && v != nil {
			if s, ok := v.(string); ok {
				if s == "::/0" {
					errResponse(c, http.StatusBadRequest, "Use 0.0.0.0/0 for global threshold (covers both IPv4 and IPv6)")
					return
				}
				p.Prefix = s
			}
		}
		if v, ok := raw["name"]; ok && v != nil {
			if s, ok := v.(string); ok {
				p.Name = s
			}
		}
		if v, ok := raw["ip_group"]; ok && v != nil {
			if s, ok := v.(string); ok {
				p.IPGroup = s
			}
		}
		if v, ok := raw["parent_id"]; ok {
			if v == nil {
				p.ParentID = nil
			} else if f, ok := v.(float64); ok {
				pid := int(f)
				p.ParentID = &pid
			}
		}
		if v, ok := raw["threshold_template_id"]; ok {
			if v == nil {
				p.ThresholdTemplateID = nil
			} else if f, ok := v.(float64); ok {
				tid := int(f)
				p.ThresholdTemplateID = &tid
			}
		}
		if v, ok := raw["enabled"]; ok && v != nil {
			if b, ok := v.(bool); ok {
				p.Enabled = b
			}
		}
		if err := deps.Store.Prefixes().Update(c, p); err != nil {
			errResponse(c, http.StatusInternalServerError, err.Error())
			return
		}
		publishAfterChange(c, deps, "watch_prefix", strconv.Itoa(id), "update", makeDiff(oldP, p))
		ok(c, gin.H{"ok": true})
	}
}

func deletePrefix(deps Dependencies) gin.HandlerFunc {
	return func(c *gin.Context) {
		id, _ := strconv.Atoi(c.Param("id"))
		old, _ := deps.Store.Prefixes().Get(c, id)
		if err := deps.Store.Prefixes().Delete(c, id); err != nil {
			errResponse(c, http.StatusInternalServerError, err.Error())
			return
		}
		publishAfterChange(c, deps, "watch_prefix", strconv.Itoa(id), "delete", makeDiff(old, nil))
		ok(c, gin.H{"ok": true})
	}
}

// publishAfterChange triggers ConfigPublisher + threshold tree rebuild.
// Extracts user_id from JWT context for audit trail.
// diff is optional JSON describing old/new values.
func publishAfterChange(c *gin.Context, deps Dependencies, entityType, entityID, action string, diff json.RawMessage) {
	if deps.ConfigPub == nil {
		return
	}
	if deps.ThreshTree != nil {
		_ = deps.ThreshTree.Rebuild(c, deps.Store)
	}
	var userID *int
	if uid, exists := c.Get("user_id"); exists {
		id := uid.(int)
		userID = &id
	}
	_, _ = deps.ConfigPub.Publish(c, userID, entityType, entityID, action, diff)
}

// makeDiff creates a JSON diff from old and new values.
func makeDiff(old, new any) json.RawMessage {
	d, _ := json.Marshal(map[string]any{"old": old, "new": new})
	return d
}
