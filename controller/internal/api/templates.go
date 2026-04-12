package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/littlewolf9527/xsight/controller/internal/store"
)

func listTemplates(deps Dependencies) gin.HandlerFunc {
	return func(c *gin.Context) {
		templates, err := deps.Store.ThresholdTemplates().List(c)
		if err != nil {
			errResponse(c, http.StatusInternalServerError, err.Error())
			return
		}
		ok(c, templates)
	}
}

func createTemplate(deps Dependencies) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req struct {
			Name        string `json:"name" binding:"required"`
			Description string `json:"description"`
			ResponseID  *int   `json:"response_id"`
		}
		if err := c.ShouldBindJSON(&req); err != nil {
			errResponse(c, http.StatusBadRequest, err.Error())
			return
		}
		tmpl := &store.ThresholdTemplate{
			Name: req.Name, Description: req.Description,
		}
		if req.ResponseID != nil {
			tmpl.ResponseID = req.ResponseID
		}
		id, err := deps.Store.ThresholdTemplates().Create(c, tmpl)
		if err != nil {
			errResponse(c, http.StatusInternalServerError, err.Error())
			return
		}
		publishAfterChange(c, deps, "threshold_template", strconv.Itoa(id), "create", makeDiff(nil, store.ThresholdTemplate{ID: id, Name: req.Name, Description: req.Description}))
		created(c, gin.H{"id": id})
	}
}

func getTemplate(deps Dependencies) gin.HandlerFunc {
	return func(c *gin.Context) {
		id, _ := strconv.Atoi(c.Param("id"))
		t, err := deps.Store.ThresholdTemplates().Get(c, id)
		if err != nil {
			errResponse(c, http.StatusNotFound, "template not found")
			return
		}
		rules, _ := deps.Store.ThresholdTemplates().ListRules(c, id)
		prefixes, _ := deps.Store.ThresholdTemplates().ListPrefixesUsing(c, id)
		ok(c, gin.H{"template": t, "rules": rules, "prefixes_using": prefixes})
	}
}

func updateTemplate(deps Dependencies) gin.HandlerFunc {
	return func(c *gin.Context) {
		id, _ := strconv.Atoi(c.Param("id"))
		old, err := deps.Store.ThresholdTemplates().Get(c, id)
		if err != nil {
			errResponse(c, http.StatusNotFound, "template not found")
			return
		}
		// Read raw JSON to detect explicit null for response_id
		var raw map[string]json.RawMessage
		bodyBytes, _ := c.GetRawData()
		_ = json.Unmarshal(bodyBytes, &raw)

		// Merge: start from existing row, overwrite only fields present in request.
		merged := *old
		_ = json.Unmarshal(bodyBytes, &merged)
		merged.ID = id

		// Handle explicit response_id: null (clear the default response)
		if rawVal, exists := raw["response_id"]; exists && string(rawVal) == "null" {
			merged.ResponseID = nil
		}

		// Validate template default response constraints
		if merged.ResponseID != nil {
			hasXDrop, err := responseHasXDropOrBGP(c, deps.Store, *merged.ResponseID)
			if err != nil {
				errResponse(c, http.StatusInternalServerError, "failed to check response actions: "+err.Error())
				return
			}
			if hasXDrop {
				// Global prefix: cannot use xDrop/BGP
				prefixes, err := deps.Store.ThresholdTemplates().ListPrefixesUsing(c, id)
				if err != nil {
					errResponse(c, http.StatusInternalServerError, "failed to check template prefix usage: "+err.Error())
					return
				}
				for _, p := range prefixes {
					if isGlobalPrefix(p.Prefix) {
						errResponse(c, http.StatusBadRequest, "Global prefix (0.0.0.0/0) cannot use responses containing xDrop/BGP actions")
						return
					}
				}
				// Sends rules: cannot use xDrop/BGP as template default
				rules, err := deps.Store.ThresholdTemplates().ListRules(c, id)
				if err != nil {
					errResponse(c, http.StatusInternalServerError, "failed to check template rules: "+err.Error())
					return
				}
				for _, r := range rules {
					if r.Direction == "sends" {
						errResponse(c, http.StatusBadRequest, "Template has outbound (sends) rules — cannot use responses containing xDrop/BGP actions as default")
						return
					}
				}
			}
		}
		if err := deps.Store.ThresholdTemplates().Update(c, &merged); err != nil {
			errResponse(c, http.StatusInternalServerError, err.Error())
			return
		}
		publishAfterChange(c, deps, "threshold_template", strconv.Itoa(id), "update", makeDiff(old, merged))
		ok(c, gin.H{"ok": true})
	}
}

func deleteTemplate(deps Dependencies) gin.HandlerFunc {
	return func(c *gin.Context) {
		id, _ := strconv.Atoi(c.Param("id"))
		// Check if in use
		prefixes, _ := deps.Store.ThresholdTemplates().ListPrefixesUsing(c, id)
		if len(prefixes) > 0 {
			names := make([]string, len(prefixes))
			for i, p := range prefixes {
				names[i] = p.Prefix
			}
			errResponse(c, http.StatusConflict, fmt.Sprintf("template in use by %d prefixes: %v", len(prefixes), names))
			return
		}
		old, _ := deps.Store.ThresholdTemplates().Get(c, id)
		if err := deps.Store.ThresholdTemplates().Delete(c, id); err != nil {
			errResponse(c, http.StatusInternalServerError, err.Error())
			return
		}
		publishAfterChange(c, deps, "threshold_template", strconv.Itoa(id), "delete", makeDiff(old, nil))
		ok(c, gin.H{"ok": true})
	}
}

func duplicateTemplate(deps Dependencies) gin.HandlerFunc {
	return func(c *gin.Context) {
		id, _ := strconv.Atoi(c.Param("id"))
		orig, err := deps.Store.ThresholdTemplates().Get(c, id)
		if err != nil {
			errResponse(c, http.StatusNotFound, "template not found")
			return
		}
		newName := orig.Name + " (Copy)"
		// Allow custom name
		var req struct {
			Name string `json:"name"`
		}
		if c.ShouldBindJSON(&req) == nil && req.Name != "" {
			newName = req.Name
		}
		newID, err := deps.Store.ThresholdTemplates().Duplicate(c, id, newName)
		if err != nil {
			errResponse(c, http.StatusInternalServerError, err.Error())
			return
		}
		publishAfterChange(c, deps, "threshold_template", strconv.Itoa(newID), "create",
			makeDiff(nil, map[string]any{"id": newID, "name": newName, "duplicated_from": id}))
		created(c, gin.H{"id": newID, "name": newName})
	}
}

// Template rules CRUD
func strVal(m map[string]any, key, def string) string {
	if v, ok := m[key]; ok && v != nil {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return def
}

func numVal(m map[string]any, key string, def float64) float64 {
	if v, ok := m[key]; ok && v != nil {
		if f, ok := v.(float64); ok {
			return f
		}
	}
	return def
}

func listTemplateRules(deps Dependencies) gin.HandlerFunc {
	return func(c *gin.Context) {
		id, _ := strconv.Atoi(c.Param("id"))
		rules, err := deps.Store.ThresholdTemplates().ListRules(c, id)
		if err != nil {
			errResponse(c, http.StatusInternalServerError, err.Error())
			return
		}
		ok(c, rules)
	}
}

func createTemplateRule(deps Dependencies) gin.HandlerFunc {
	return func(c *gin.Context) {
		templateID, _ := strconv.Atoi(c.Param("id"))

		// Parse with raw map to detect if inheritable was explicitly sent
		var raw map[string]any
		if err := c.ShouldBindJSON(&raw); err != nil {
			errResponse(c, http.StatusBadRequest, err.Error())
			return
		}

		inheritable := true // default for template rules
		if v, ok := raw["inheritable"]; ok && v != nil {
			if b, ok := v.(bool); ok {
				inheritable = b
			}
		}

		decoder := strVal(raw, "decoder", "")
		unit := strVal(raw, "unit", "pps")

		req := store.Threshold{
			TemplateID:  &templateID,
			Domain:      strVal(raw, "domain", "internal_ip"),
			Direction:   strVal(raw, "direction", "receives"),
			Decoder:     decoder,
			Unit:        unit,
			Comparison:  strVal(raw, "comparison", "over"),
			Value:       int64(numVal(raw, "value", 0)),
			Inheritable: inheritable,
			Enabled:     true,
		}
		if err := validateThreshold(&req); err != nil {
			errResponse(c, http.StatusBadRequest, err.Error())
			return
		}
		// Global prefix: reject internal_ip domain + reject xDrop/BGP response
		if err := validateGlobalPrefixConstraints(c, deps.Store, &req); err != nil {
			errResponse(c, http.StatusBadRequest, err.Error())
			return
		}
		id, err := deps.Store.Thresholds().Create(c, &req)
		if err != nil {
			errResponse(c, http.StatusInternalServerError, err.Error())
			return
		}
		req.ID = id
		publishAfterChange(c, deps, "threshold_template_rule", strconv.Itoa(id), "create", makeDiff(nil, req))
		created(c, gin.H{"id": id})
	}
}
