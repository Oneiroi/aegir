package server

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

// TestSSECORSStrictAllowlist is the ISC-165 (AEGIR-M-001 follow-up) probe: the
// SSE endpoint must emit Access-Control-Allow-Origin ONLY for a request Origin
// that is an exact match in Security.AllowedOrigins. An unlisted Origin (or a
// present Origin when the allowlist is empty, or no Origin at all) must
// receive NO Access-Control-Allow-Origin header — the firewall must never
// reflect an origin it hasn't been explicitly told to trust, and must never
// emit a wildcard (ISC-152 still holds).
//
// newProxyWithOrigins and gin.SetMode(gin.TestMode) come from
// tool_result_injection_test.go (same package, ISC-152's proxy helper).
func TestSSECORSStrictAllowlist(t *testing.T) {
	gin.SetMode(gin.TestMode)

	cases := []struct {
		name       string
		allowed    []string
		origin     string
		wantHeader string // expected Access-Control-Allow-Origin value ("" means absent)
	}{
		{"allowlisted_origin_reflected", []string{"https://trusted.example.com"}, "https://trusted.example.com", "https://trusted.example.com"},
		{"unlisted_origin_gets_no_header", []string{"https://trusted.example.com"}, "https://attacker.example", ""},
		{"empty_allowlist_gets_no_header", nil, "https://any.example.com", ""},
		{"no_origin_gets_no_header", []string{"https://trusted.example.com"}, "", ""},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			proxy := newProxyWithOrigins(t, tc.allowed)
			router := gin.New()
			router.GET("/mcp/sse", proxy.HandleSSE)

			req := httptest.NewRequest(http.MethodGet, "/mcp/sse", nil)
			if tc.origin != "" {
				req.Header.Set("Origin", tc.origin)
			}
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)

			got := w.Header().Get("Access-Control-Allow-Origin")
			if got != tc.wantHeader {
				t.Errorf("Access-Control-Allow-Origin = %q, want %q (Origin=%q, allowlist=%v)", got, tc.wantHeader, tc.origin, tc.allowed)
			}
			if got == "*" {
				t.Errorf("SSE emitted wildcard Access-Control-Allow-Origin for Origin=%q (allowlist=%v)", tc.origin, tc.allowed)
			}
		})
	}
}
