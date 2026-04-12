package api

import (
	"fmt"
	"net/http"
	"os/exec"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/littlewolf9527/xsight/controller/internal/store"
)

func listBGPConnectors(deps Dependencies) gin.HandlerFunc {
	return func(c *gin.Context) {
		list, err := deps.Store.BGPConnectors().List(c)
		if err != nil {
			errResponse(c, http.StatusInternalServerError, err.Error())
			return
		}
		ok(c, list)
	}
}

func getBGPConnector(deps Dependencies) gin.HandlerFunc {
	return func(c *gin.Context) {
		id, _ := strconv.Atoi(c.Param("id"))
		conn, err := deps.Store.BGPConnectors().Get(c, id)
		if err != nil {
			errResponse(c, http.StatusNotFound, "bgp connector not found")
			return
		}
		ok(c, conn)
	}
}

func createBGPConnector(deps Dependencies) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req struct {
			Name           string `json:"name" binding:"required"`
			VtyshPath      string `json:"vtysh_path"`
			BGPASN         int    `json:"bgp_asn" binding:"required"`
			AddressFamily  string `json:"address_family"`
			Enabled        *bool  `json:"enabled"`
			Description    string `json:"description"`
		}
		if err := c.ShouldBindJSON(&req); err != nil {
			errResponse(c, http.StatusBadRequest, err.Error())
			return
		}
		if req.VtyshPath == "" {
			req.VtyshPath = "/usr/bin/vtysh"
		}
		// address_family is now auto-detected from the prefix at execution time.
		// Field kept for backward compatibility but not enforced.
		if req.AddressFamily == "" {
			req.AddressFamily = "auto"
		}
		enabled := true
		if req.Enabled != nil {
			enabled = *req.Enabled
		}
		conn := &store.BGPConnector{
			Name:          req.Name,
			VtyshPath:     req.VtyshPath,
			BGPASN:        req.BGPASN,
			AddressFamily: req.AddressFamily,
			Enabled:       enabled,
			Description:   req.Description,
		}
		id, err := deps.Store.BGPConnectors().Create(c, conn)
		if err != nil {
			errResponse(c, http.StatusInternalServerError, err.Error())
			return
		}
		conn.ID = id
		publishAfterChange(c, deps, "bgp_connector", strconv.Itoa(id), "create", makeDiff(nil, conn))
		created(c, gin.H{"id": id})
	}
}

func updateBGPConnector(deps Dependencies) gin.HandlerFunc {
	return func(c *gin.Context) {
		id, _ := strconv.Atoi(c.Param("id"))
		conn, err := deps.Store.BGPConnectors().Get(c, id)
		if err != nil {
			errResponse(c, http.StatusNotFound, "bgp connector not found")
			return
		}
		var req struct {
			Name           string `json:"name"`
			VtyshPath      string `json:"vtysh_path"`
			BGPASN         int    `json:"bgp_asn"`
			AddressFamily  string `json:"address_family"`
			Enabled        *bool  `json:"enabled"`
			Description    string `json:"description"`
		}
		if err := c.ShouldBindJSON(&req); err != nil {
			errResponse(c, http.StatusBadRequest, err.Error())
			return
		}
		old := *conn // snapshot before mutation
		if req.Name != "" {
			conn.Name = req.Name
		}
		if req.VtyshPath != "" {
			conn.VtyshPath = req.VtyshPath
		}
		if req.BGPASN > 0 {
			conn.BGPASN = req.BGPASN
		}
		if req.AddressFamily != "" {
			conn.AddressFamily = req.AddressFamily
		}
		if req.Enabled != nil {
			conn.Enabled = *req.Enabled
		}
		if req.Description != "" {
			conn.Description = req.Description
		}
		if err := deps.Store.BGPConnectors().Update(c, conn); err != nil {
			errResponse(c, http.StatusInternalServerError, err.Error())
			return
		}
		publishAfterChange(c, deps, "bgp_connector", strconv.Itoa(id), "update", makeDiff(old, conn))
		ok(c, gin.H{"ok": true})
	}
}

func deleteBGPConnector(deps Dependencies) gin.HandlerFunc {
	return func(c *gin.Context) {
		id, _ := strconv.Atoi(c.Param("id"))
		// In-use guard: reject if any response action references this connector
		count, err := deps.Store.Responses().CountActionsByBGPConnector(c, id)
		if err != nil {
			errResponse(c, http.StatusInternalServerError, err.Error())
			return
		}
		if count > 0 {
			errResponse(c, http.StatusConflict, fmt.Sprintf("connector in use by %d action(s)", count))
			return
		}
		old, _ := deps.Store.BGPConnectors().Get(c, id)
		if err := deps.Store.BGPConnectors().Delete(c, id); err != nil {
			errResponse(c, http.StatusInternalServerError, err.Error())
			return
		}
		if old != nil {
			publishAfterChange(c, deps, "bgp_connector", strconv.Itoa(id), "delete", makeDiff(old, nil))
		}
		ok(c, gin.H{"ok": true})
	}
}

// listBGPRoutes returns the current BGP RIB for the connector's address family.
func listBGPRoutes(deps Dependencies) gin.HandlerFunc {
	return func(c *gin.Context) {
		id, _ := strconv.Atoi(c.Param("id"))
		conn, err := deps.Store.BGPConnectors().Get(c, id)
		if err != nil {
			errResponse(c, http.StatusNotFound, "bgp connector not found")
			return
		}
		// Show both IPv4 and IPv6 BGP RIB — partial success is OK
		out4, err4 := exec.CommandContext(c, conn.VtyshPath, "-c", "show ip bgp ipv4 unicast").CombinedOutput()
		out6, err6 := exec.CommandContext(c, conn.VtyshPath, "-c", "show ip bgp ipv6 unicast").CombinedOutput()
		if err4 != nil && err6 != nil {
			errResponse(c, http.StatusBadGateway, fmt.Sprintf("vtysh failed: ipv4=%v ipv6=%v", err4, err6))
			return
		}
		var combined string
		if err4 == nil {
			combined += string(out4)
		}
		if err6 == nil && len(out6) > 0 && !strings.Contains(string(out6), "No BGP prefixes displayed") {
			if combined != "" {
				combined += "\n--- IPv6 ---\n"
			}
			combined += string(out6)
		}
		ok(c, gin.H{"output": combined})
	}
}

// testBGPConnector runs "vtysh -c 'show bgp summary'" to verify FRR connectivity.
func testBGPConnector(deps Dependencies) gin.HandlerFunc {
	return func(c *gin.Context) {
		id, _ := strconv.Atoi(c.Param("id"))
		conn, err := deps.Store.BGPConnectors().Get(c, id)
		if err != nil {
			errResponse(c, http.StatusNotFound, "bgp connector not found")
			return
		}
		out, err := exec.CommandContext(c, conn.VtyshPath, "-c", "show bgp summary").CombinedOutput()
		if err != nil {
			errResponse(c, http.StatusBadGateway, fmt.Sprintf("vtysh failed: %v\n%s", err, strings.TrimSpace(string(out))))
			return
		}
		ok(c, gin.H{"ok": true, "output": string(out)})
	}
}
