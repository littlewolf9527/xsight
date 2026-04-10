package api

import (
	"io"
	"io/fs"
	"net/http"
	"path/filepath"
	"strings"

	"github.com/gin-gonic/gin"
)

// ServeSPA configures the router to serve a Vue SPA from an embedded filesystem.
// All non-/api/ routes fall back to index.html for client-side routing.
// This avoids http.FileServer's directory redirect (301 → ./) which breaks SPA routing.
func ServeSPA(r *gin.Engine, webFS fs.FS) {
	// Pre-read index.html into memory for fast SPA fallback
	indexHTML, _ := fs.ReadFile(webFS, "index.html")

	r.NoRoute(func(c *gin.Context) {
		path := c.Request.URL.Path
		// API routes should 404 normally
		if strings.HasPrefix(path, "/api/") {
			c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
			return
		}

		// Try to serve the exact static file (assets, favicon, etc.)
		cleanPath := strings.TrimPrefix(path, "/")
		if cleanPath != "" {
			f, err := webFS.Open(cleanPath)
			if err == nil {
				stat, _ := f.Stat()
				if stat != nil && !stat.IsDir() {
					// Serve the file with correct content type
					contentType := "application/octet-stream"
					switch ext := filepath.Ext(cleanPath); ext {
					case ".js":
						contentType = "application/javascript"
					case ".css":
						contentType = "text/css"
					case ".html":
						contentType = "text/html"
					case ".svg":
						contentType = "image/svg+xml"
					case ".json":
						contentType = "application/json"
					case ".woff2":
						contentType = "font/woff2"
					case ".png":
						contentType = "image/png"
					}
					data, _ := io.ReadAll(f)
					f.Close()
					c.Data(http.StatusOK, contentType, data)
					return
				}
				f.Close()
			}
		}

		// Fallback: serve index.html for SPA client-side routing
		// Directly write bytes — do NOT use FileFromFS (it triggers directory redirects)
		c.Data(http.StatusOK, "text/html; charset=utf-8", indexHTML)
	})
}
