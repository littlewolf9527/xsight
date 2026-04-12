package tests

// helpers_test.go — shared test infrastructure for the tests package.
// Defines the JWT constant, token generator, and base router constructor
// that every test file in this package relies on.

import (
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/littlewolf9527/xsight/controller/internal/api"
	"github.com/littlewolf9527/xsight/controller/internal/store"
)

// testJWTSecret is the shared JWT signing secret used across all test files.
const testJWTSecret = "test-secret-key"

// makeTestToken generates a valid HS256 JWT signed with testJWTSecret.
// Used to add an Authorization header to test HTTP requests.
func makeTestToken(t *testing.T) string {
	t.Helper()
	type claims struct {
		UserID   int    `json:"user_id"`
		Username string `json:"username"`
		Role     string `json:"role"`
		jwt.RegisteredClaims
	}
	c := claims{
		UserID:   1,
		Username: "testuser",
		Role:     "admin",
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(1 * time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, c)
	signed, err := tok.SignedString([]byte(testJWTSecret))
	if err != nil {
		t.Fatalf("makeTestToken: %v", err)
	}
	return signed
}

// setupRouter builds a gin.Engine backed by the given store with no optional
// dependencies (ConfigPub=nil, ActionEngine=nil). Used by tests that only
// exercise pure CRUD / response-action logic.
func setupRouter(s store.Store) *gin.Engine {
	gin.SetMode(gin.TestMode)
	deps := api.Dependencies{
		Store:     s,
		JWTSecret: testJWTSecret,
		APIKey:    "test-api-key",
	}
	return api.NewRouter(deps)
}

// intPtr returns a pointer to an int. Convenience helper for test fixtures.
func intPtr(i int) *int { return &i }
