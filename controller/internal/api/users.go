package api

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/littlewolf9527/xsight/controller/internal/store"
)

func listUsers(deps Dependencies) gin.HandlerFunc {
	return func(c *gin.Context) {
		users, err := deps.Store.Users().List(c)
		if err != nil {
			errResponse(c, http.StatusInternalServerError, err.Error())
			return
		}
		ok(c, users)
	}
}

func createUser(deps Dependencies) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req struct {
			Username string `json:"username" binding:"required"`
			Password string `json:"password" binding:"required"`
			Role     string `json:"role"`
		}
		if err := c.ShouldBindJSON(&req); err != nil {
			errResponse(c, http.StatusBadRequest, err.Error())
			return
		}
		if req.Role == "" {
			req.Role = "viewer"
		}
		hash, err := hashPassword(req.Password)
		if err != nil {
			errResponse(c, http.StatusInternalServerError, "hash failed")
			return
		}
		id, err := deps.Store.Users().Create(c, &store.User{
			Username: req.Username, Password: hash, Role: req.Role, Enabled: true,
		})
		if err != nil {
			errResponse(c, http.StatusInternalServerError, err.Error())
			return
		}
		created(c, gin.H{"id": id})
	}
}

func updateUser(deps Dependencies) gin.HandlerFunc {
	return func(c *gin.Context) {
		id, _ := strconv.Atoi(c.Param("id"))
		var req struct {
			Username string `json:"username"`
			Password string `json:"password"`
			Role     string `json:"role"`
			Enabled  *bool  `json:"enabled"`
		}
		if err := c.ShouldBindJSON(&req); err != nil {
			errResponse(c, http.StatusBadRequest, err.Error())
			return
		}
		user, err := deps.Store.Users().Get(c, id)
		if err != nil {
			errResponse(c, http.StatusNotFound, "user not found")
			return
		}
		if req.Username != "" {
			user.Username = req.Username
		}
		if pw := strings.TrimSpace(req.Password); pw != "" {
			hash, err := hashPassword(pw)
			if err != nil {
				errResponse(c, http.StatusInternalServerError, "hash failed")
				return
			}
			user.Password = hash
		}
		if req.Role != "" {
			user.Role = req.Role
		}
		if req.Enabled != nil {
			user.Enabled = *req.Enabled
		}
		if err := deps.Store.Users().Update(c, user); err != nil {
			errResponse(c, http.StatusInternalServerError, err.Error())
			return
		}
		ok(c, gin.H{"ok": true})
	}
}

func deleteUser(deps Dependencies) gin.HandlerFunc {
	return func(c *gin.Context) {
		id, _ := strconv.Atoi(c.Param("id"))
		if err := deps.Store.Users().Delete(c, id); err != nil {
			errResponse(c, http.StatusInternalServerError, err.Error())
			return
		}
		ok(c, gin.H{"ok": true})
	}
}
