package server

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/aegishjalmur/aegir/internal/config"
	"github.com/gin-gonic/gin"
)

// TestCSRFOriginValidation is the ISC-120 probe: HTTP MCP requests bearing an
// Origin header not in the configured allowlist are rejected with 403.
func TestCSRFOriginValidation(t *testing.T) {
	gin.SetMode(gin.TestMode)

	cases := []struct {
		name           string
		allowedOrigins []string
		requestOrigin  string
		wantStatus     int
	}{
		{
			name:           "attacker_origin_rejected",
			allowedOrigins: []string{"https://trusted.example.com"},
			requestOrigin:  "https://attacker.example",
			wantStatus:     http.StatusForbidden,
		},
		{
			name:           "trusted_origin_allowed",
			allowedOrigins: []string{"https://trusted.example.com"},
			requestOrigin:  "https://trusted.example.com",
			wantStatus:     http.StatusOK,
		},
		{
			name:           "no_origin_header_passes",
			allowedOrigins: []string{"https://trusted.example.com"},
			requestOrigin:  "",
			wantStatus:     http.StatusOK,
		},
		{
			name:           "empty_allowlist_permits_all",
			allowedOrigins: []string{},
			requestOrigin:  "https://attacker.example",
			wantStatus:     http.StatusOK,
		},
		{
			name:           "nil_allowlist_permits_all",
			allowedOrigins: nil,
			requestOrigin:  "https://any.example.com",
			wantStatus:     http.StatusOK,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := &MCPFirewall{
				config: &config.Config{
					Security: config.Security{
						AllowedOrigins: tc.allowedOrigins,
					},
				},
				logger: testLogger(),
			}

			router := gin.New()
			router.Use(s.csrfOriginMiddleware())
			router.POST("/mcp", func(c *gin.Context) { c.JSON(http.StatusOK, gin.H{"ok": true}) })

			req := httptest.NewRequest(http.MethodPost, "/mcp", nil)
			if tc.requestOrigin != "" {
				req.Header.Set("Origin", tc.requestOrigin)
			}
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)

			if w.Code != tc.wantStatus {
				t.Errorf("Origin=%q: got status %d want %d; body=%s", tc.requestOrigin, w.Code, tc.wantStatus, w.Body.String())
			}
		})
	}
}
