package api

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/littlewolf9527/xsight/controller/internal/store"
)

// --- Shell Connectors (Response System v2) ---

func listShellConnectors(deps Dependencies) gin.HandlerFunc {
	return func(c *gin.Context) {
		connectors, err := deps.Store.ShellConnectors().List(c)
		if err != nil {
			errResponse(c, http.StatusInternalServerError, err.Error())
			return
		}
		ok(c, connectors)
	}
}

func createShellConnector(deps Dependencies) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req store.ShellConnector
		if err := c.ShouldBindJSON(&req); err != nil {
			errResponse(c, http.StatusBadRequest, err.Error())
			return
		}
		if req.Name == "" {
			errResponse(c, http.StatusBadRequest, "name is required")
			return
		}
		if req.Command == "" {
			errResponse(c, http.StatusBadRequest, "command is required")
			return
		}
		if !strings.HasPrefix(req.Command, "/") {
			errResponse(c, http.StatusBadRequest, "command must be an absolute path (start with /)")
			return
		}
		if req.TimeoutMs == 0 {
			req.TimeoutMs = 30000
		}
		req.Enabled = true

		id, err := deps.Store.ShellConnectors().Create(c, &req)
		if err != nil {
			errResponse(c, http.StatusInternalServerError, err.Error())
			return
		}
		req.ID = id
		publishAfterChange(c, deps, "shell_connector", strconv.Itoa(id), "create", makeDiff(nil, req))
		created(c, gin.H{"id": id})
	}
}

func getShellConnector(deps Dependencies) gin.HandlerFunc {
	return func(c *gin.Context) {
		id, _ := strconv.Atoi(c.Param("id"))
		conn, err := deps.Store.ShellConnectors().Get(c, id)
		if err != nil {
			errResponse(c, http.StatusNotFound, "shell connector not found")
			return
		}
		ok(c, conn)
	}
}

func updateShellConnector(deps Dependencies) gin.HandlerFunc {
	return func(c *gin.Context) {
		id, _ := strconv.Atoi(c.Param("id"))
		old, err := deps.Store.ShellConnectors().Get(c, id)
		if err != nil {
			errResponse(c, http.StatusNotFound, "shell connector not found")
			return
		}
		var req store.ShellConnector
		if err := c.ShouldBindJSON(&req); err != nil {
			errResponse(c, http.StatusBadRequest, err.Error())
			return
		}
		if req.Command != "" && !strings.HasPrefix(req.Command, "/") {
			errResponse(c, http.StatusBadRequest, "command must be an absolute path (start with /)")
			return
		}
		req.ID = id
		if err := deps.Store.ShellConnectors().Update(c, &req); err != nil {
			errResponse(c, http.StatusInternalServerError, err.Error())
			return
		}
		publishAfterChange(c, deps, "shell_connector", strconv.Itoa(id), "update", makeDiff(old, req))
		ok(c, gin.H{"ok": true})
	}
}

func deleteShellConnector(deps Dependencies) gin.HandlerFunc {
	return func(c *gin.Context) {
		id, _ := strconv.Atoi(c.Param("id"))
		// Check if any action references this shell connector (fail closed on error)
		count, err := deps.Store.Responses().CountActionsByShellConnector(c, id)
		if err != nil {
			errResponse(c, http.StatusInternalServerError, "failed to check connector usage: "+err.Error())
			return
		}
		if count > 0 {
			errResponse(c, http.StatusConflict,
				fmt.Sprintf("shell connector in use by %d action(s)", count))
			return
		}
		old, _ := deps.Store.ShellConnectors().Get(c, id)
		if err := deps.Store.ShellConnectors().Delete(c, id); err != nil {
			errResponse(c, http.StatusInternalServerError, err.Error())
			return
		}
		publishAfterChange(c, deps, "shell_connector", strconv.Itoa(id), "delete", makeDiff(old, nil))
		ok(c, gin.H{"ok": true})
	}
}
