package api

import (
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/littlewolf9527/xsight/controller/internal/store"
	"github.com/littlewolf9527/xsight/shared/decoder"
)

// validThresholdDecoders returns the set of decoder_family values accepted by
// the threshold API. Built from shared/decoder.Names (the canonical registry
// kept in sync with BPF) plus the meta-decoder "ip" — an aggregate over all
// IP traffic that has no dedicated decoder slot but IS a valid threshold
// target (whole-prefix total-pps thresholds). Empty-string entries in the
// registry (reserved slots 14-15) are skipped.
//
// Built at package init so adding a new decoder to the registry auto-extends
// the whitelist (v1.3 shipped with a stale hardcoded list — see codex v1.3.x
// audit).
func validThresholdDecoders() map[string]bool {
	set := map[string]bool{"ip": true}
	for _, n := range decoder.Names {
		if n != "" {
			set[n] = true
		}
	}
	return set
}

// validThresholdDecoderList returns a sorted, human-readable list of accepted
// decoder values for error messages. "ip" is listed first as the conventional
// aggregate default; remaining entries are sorted alphabetically.
func validThresholdDecoderList() string {
	names := make([]string, 0)
	for _, n := range decoder.Names {
		if n != "" {
			names = append(names, n)
		}
	}
	sort.Strings(names)
	return "ip, " + strings.Join(names, ", ")
}

func listThresholds(deps Dependencies) gin.HandlerFunc {
	return func(c *gin.Context) {
		if prefixID := c.Query("prefix_id"); prefixID != "" {
			id, _ := strconv.Atoi(prefixID)
			thresholds, err := deps.Store.Thresholds().ListByPrefix(c, id)
			if err != nil {
				errResponse(c, http.StatusInternalServerError, err.Error())
				return
			}
			ok(c, thresholds)
			return
		}
		thresholds, err := deps.Store.Thresholds().List(c)
		if err != nil {
			errResponse(c, http.StatusInternalServerError, err.Error())
			return
		}
		ok(c, thresholds)
	}
}

func createThreshold(deps Dependencies) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req store.Threshold
		if err := c.ShouldBindJSON(&req); err != nil {
			errResponse(c, http.StatusBadRequest, err.Error())
			return
		}
		req.Enabled = true

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
		publishAfterChange(c, deps, "threshold", strconv.Itoa(id), "create", makeDiff(nil, req))
		created(c, gin.H{"id": id})
	}
}

func getThreshold(deps Dependencies) gin.HandlerFunc {
	return func(c *gin.Context) {
		id, _ := strconv.Atoi(c.Param("id"))
		t, err := deps.Store.Thresholds().Get(c, id)
		if err != nil {
			errResponse(c, http.StatusNotFound, "threshold not found")
			return
		}
		ok(c, t)
	}
}

func updateThreshold(deps Dependencies) gin.HandlerFunc {
	return func(c *gin.Context) {
		id, _ := strconv.Atoi(c.Param("id"))
		old, err := deps.Store.Thresholds().Get(c, id)
		if err != nil {
			errResponse(c, http.StatusNotFound, "threshold not found")
			return
		}
		// Merge: start from existing row, overwrite only fields present in request.
		// This prevents partial updates from clearing unset fields.
		merged := *old
		if err := c.ShouldBindJSON(&merged); err != nil {
			errResponse(c, http.StatusBadRequest, err.Error())
			return
		}
		merged.ID = id
		// Preserve template_id — never allow update to detach from template
		if old.TemplateID != nil {
			merged.TemplateID = old.TemplateID
		}
		if err := validateThreshold(&merged); err != nil {
			errResponse(c, http.StatusBadRequest, err.Error())
			return
		}
		// Global prefix: reject internal_ip domain + reject xDrop/BGP response
		if err := validateGlobalPrefixConstraints(c, deps.Store, &merged); err != nil {
			errResponse(c, http.StatusBadRequest, err.Error())
			return
		}
		if err := deps.Store.Thresholds().Update(c, &merged); err != nil {
			errResponse(c, http.StatusInternalServerError, err.Error())
			return
		}
		publishAfterChange(c, deps, "threshold", strconv.Itoa(id), "update", makeDiff(old, merged))
		ok(c, gin.H{"ok": true})
	}
}

// validateThreshold checks semantic constraints on threshold rules.
func validateThreshold(t *store.Threshold) error {
	// Decoder: must be a valid decoder family (dynamic from shared/decoder.Names + "ip").
	if t.Decoder != "" && !validThresholdDecoders()[t.Decoder] {
		return fmt.Errorf("decoder must be one of: %s; got %q", validThresholdDecoderList(), t.Decoder)
	}
	// Direction: must be receives or sends
	if t.Direction != "" && t.Direction != "receives" && t.Direction != "sends" {
		return fmt.Errorf("direction must be 'receives' or 'sends', got %q", t.Direction)
	}
	// Percentage: decoder=ip is meaningless (always 100%)
	if t.Unit == "pct" && (t.Decoder == "" || t.Decoder == "ip") {
		return fmt.Errorf("percentage thresholds are not meaningful for decoder=ip (always 100%%); use a specific decoder like tcp, udp, icmp")
	}
	// Percentage: value must be 1-100
	if t.Unit == "pct" && (t.Value < 1 || t.Value > 100) {
		return fmt.Errorf("percentage threshold value must be between 1 and 100, got %d", t.Value)
	}
	return nil
}

func deleteThreshold(deps Dependencies) gin.HandlerFunc {
	return func(c *gin.Context) {
		id, _ := strconv.Atoi(c.Param("id"))
		old, _ := deps.Store.Thresholds().Get(c, id)
		if err := deps.Store.Thresholds().Delete(c, id); err != nil {
			errResponse(c, http.StatusInternalServerError, err.Error())
			return
		}
		publishAfterChange(c, deps, "threshold", strconv.Itoa(id), "delete", makeDiff(old, nil))
		ok(c, gin.H{"ok": true})
	}
}
