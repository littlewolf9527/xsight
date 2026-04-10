package api

import (
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

// authMiddleware validates either API key or JWT token.
func authMiddleware(apiKey, jwtSecret string) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Check API key first
		if key := c.GetHeader("X-API-Key"); key != "" {
			if key == apiKey {
				c.Set("auth_type", "apikey")
				c.Next()
				return
			}
			errResponse(c, http.StatusUnauthorized, "invalid API key")
			c.Abort()
			return
		}

		// Check JWT
		auth := c.GetHeader("Authorization")
		if auth == "" {
			errResponse(c, http.StatusUnauthorized, "missing authentication")
			c.Abort()
			return
		}
		tokenStr := strings.TrimPrefix(auth, "Bearer ")
		claims := &jwtClaims{}
		token, err := jwt.ParseWithClaims(tokenStr, claims, func(t *jwt.Token) (any, error) {
			return []byte(jwtSecret), nil
		})
		if err != nil || !token.Valid {
			errResponse(c, http.StatusUnauthorized, "invalid token")
			c.Abort()
			return
		}

		c.Set("auth_type", "jwt")
		c.Set("user_id", claims.UserID)
		c.Set("username", claims.Username)
		c.Set("role", claims.Role)
		c.Next()
	}
}

type jwtClaims struct {
	UserID   int    `json:"user_id"`
	Username string `json:"username"`
	Role     string `json:"role"`
	jwt.RegisteredClaims
}

func generateJWT(secret string, userID int, username, role string) (string, error) {
	claims := jwtClaims{
		UserID:   userID,
		Username: username,
		Role:     role,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(24 * time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(secret))
}

func hashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return string(bytes), err
}

func checkPassword(hash, password string) bool {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) == nil
}

// loginHandler authenticates a user and returns a JWT.
func loginHandler(deps Dependencies) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req struct {
			Username string `json:"username" binding:"required"`
			Password string `json:"password" binding:"required"`
		}
		if err := c.ShouldBindJSON(&req); err != nil {
			errResponse(c, http.StatusBadRequest, "username and password required")
			return
		}
		user, err := deps.Store.Users().GetByUsername(c, req.Username)
		if err != nil || user == nil {
			errResponse(c, http.StatusUnauthorized, "invalid credentials")
			return
		}
		if !user.Enabled {
			errResponse(c, http.StatusForbidden, "account disabled")
			return
		}
		if !checkPassword(user.Password, req.Password) {
			errResponse(c, http.StatusUnauthorized, "invalid credentials")
			return
		}
		token, err := generateJWT(deps.JWTSecret, user.ID, user.Username, user.Role)
		if err != nil {
			errResponse(c, http.StatusInternalServerError, "token generation failed")
			return
		}
		ok(c, gin.H{"token": token, "user": gin.H{
			"id": user.ID, "username": user.Username, "role": user.Role,
		}})
	}
}
