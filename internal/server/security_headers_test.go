package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

// TestDashboardCSPNoUnsafeInline is the ISC-157 / AEGIR-L-001 probe: the
// server-wide security-headers middleware (securityHeaders(), applied to
// every route including the dashboard) must emit a Content-Security-Policy
// header that does not contain 'unsafe-inline', so an attacker who manages to
// inject content cannot execute arbitrary inline scripts.
func TestDashboardCSPNoUnsafeInline(t *testing.T) {
	gin.SetMode(gin.TestMode)

	s := &MCPFirewall{}
	router := gin.New()
	router.Use(s.securityHeaders())
	router.GET("/", func(c *gin.Context) { c.Status(http.StatusOK) })

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	csp := w.Header().Get("Content-Security-Policy")
	if csp == "" {
		t.Fatal("Content-Security-Policy header is missing")
	}
	if strings.Contains(csp, "unsafe-inline") {
		t.Errorf("CSP contains unsafe-inline: %q", csp)
	}
}
