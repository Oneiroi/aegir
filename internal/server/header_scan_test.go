package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/aegishjalmur/aegir/internal/config"
	"github.com/aegishjalmur/aegir/internal/sanitizer"
	"github.com/aegishjalmur/aegir/internal/upstream"
	"github.com/gin-gonic/gin"
)

// newHeaderScanTestProxy builds an MCPProxy with the Detection master switch
// (ISC-132) and SecretDetection actually enabled — createTestMCPProxy's shared
// config leaves internal/config.Detection.Enabled at its zero value (false),
// which silently no-ops every detector including the ones this ISC exercises.
func newHeaderScanTestProxy(t *testing.T) *MCPProxy {
	t.Helper()
	logger := testLogger()
	secCfg := config.Security{
		Detection:        config.Detection{Enabled: true},
		SecretDetection:  config.SecretDetection{Enabled: true},
		CommandInjection: config.CommandInjection{Enabled: true},
		Sanitization:     config.Sanitization{Enabled: true, XSSPrevention: true},
	}
	sanitizerMgr := sanitizer.New(secCfg, logger)
	complianceMgr := sanitizer.NewComplianceManager(config.Compliance{}, logger)
	upstreamMgr := upstream.NewManager(&config.Upstream{}, logger)
	cfg := &config.Config{Security: secCfg}
	return NewMCPProxy(cfg, logger, sanitizerMgr, complianceMgr, upstreamMgr, nil, nil, nil)
}

// awsShapedKey is a syntactically-valid AWS access key ID shape (AKIA + 16
// alnum) that trips the existing "aws_access_key" secret pattern directly,
// with no "key=value" framing needed — i.e. exactly the bare-token shape a
// header value would carry.
const awsShapedKey = "AKIAABCDEFGHIJKLMNOP"

// TestScanHeadersDetectsXMcpHeaderCredential verifies ISC-170: a credential
// mapped into a header via the x-mcp-header directive is flagged and reported
// as such regardless of the underlying detector's own severity ranking.
func TestScanHeadersDetectsXMcpHeaderCredential(t *testing.T) {
	proxy := newHeaderScanTestProxy(t)

	headers := http.Header{}
	headers.Set("X-Mcp-Header-Api-Key", awsShapedKey)

	findings := proxy.scanHeaders(headers, "request")
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d: %+v", len(findings), findings)
	}
	if !findings[0].ViaXMCPHeader {
		t.Errorf("expected finding to be flagged as x-mcp-header, got %+v", findings[0])
	}
	if !headersBlocked(findings) {
		t.Errorf("expected headersBlocked to be true for an x-mcp-header credential")
	}
}

// TestScanHeadersSkipsAuthorizationHeader verifies the legitimate auth channel
// (which by design carries a bearer-token-shaped value on every authenticated
// request) is never flagged as a leak.
func TestScanHeadersSkipsAuthorizationHeader(t *testing.T) {
	proxy := newHeaderScanTestProxy(t)

	headers := http.Header{}
	headers.Set("Authorization", "Bearer "+awsShapedKey+"extraentropypadding1234567890")

	findings := proxy.scanHeaders(headers, "request")
	if len(findings) != 0 {
		t.Errorf("expected Authorization header to be skipped, got findings: %+v", findings)
	}
}

// TestScanHeadersCleanHeaderAllowed verifies an ordinary, non-credential header
// produces no finding and is never blocked.
func TestScanHeadersCleanHeaderAllowed(t *testing.T) {
	proxy := newHeaderScanTestProxy(t)

	headers := http.Header{}
	headers.Set("X-Request-Id", "req-12345-abcde")

	findings := proxy.scanHeaders(headers, "request")
	if len(findings) != 0 {
		t.Errorf("expected no findings for a clean header, got: %+v", findings)
	}
	if headersBlocked(findings) {
		t.Errorf("expected headersBlocked to be false for clean headers")
	}
}

// TestSecretInResponseHeaderFlagged verifies ISC-169 on the response direction:
// a secret-shaped value in what would be an upstream response header is
// detected and reported as blocking. This exercises the exact function
// HandleMCPRequest calls on upstreamResp.Headers (internal/server/mcp_proxy.go);
// it is not a full network round-trip because Aegir's upstream dialer applies
// SSRF loopback protection (internal/upstream/manager.go:secureDialContext),
// which correctly refuses to connect to a 127.0.0.1 test server regardless of
// caller — that guard is deliberate and is not something a test should bypass.
func TestSecretInResponseHeaderFlagged(t *testing.T) {
	proxy := newHeaderScanTestProxy(t)

	headers := http.Header{}
	headers.Set("X-Debug-Token", "ghp_"+"A1B2C3D4E5F6G7H8I9J0K1L2M3N4O5P6Q7R8")

	findings := proxy.scanHeaders(headers, "response")
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding for a github-token-shaped response header, got %d: %+v", len(findings), findings)
	}
	if !headersBlocked(findings) {
		t.Errorf("expected headersBlocked to be true for a high/critical severity secret")
	}
}

// TestXMcpHeaderCredentialBlockedOverHTTP drives the real HandleMCPRequest
// entry point end-to-end: a tools/call request carrying an AWS-shaped key in
// an X-Mcp-Header-* header must be rejected with 403 before ever reaching the
// forward-to-upstream step.
func TestXMcpHeaderCredentialBlockedOverHTTP(t *testing.T) {
	gin.SetMode(gin.TestMode)
	proxy := newHeaderScanTestProxy(t)
	router := gin.New()
	router.POST("/mcp", proxy.HandleMCPRequest)
	ts := httptest.NewServer(router)
	defer ts.Close()

	body, _ := json.Marshal(MCPRequest{
		Method: "tools/call",
		Params: map[string]interface{}{"name": "test"},
		ID:     "header-leak-1",
	})
	req, err := http.NewRequest(http.MethodPost, ts.URL+"/mcp", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("failed to build request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Mcp-Header-Api-Key", awsShapedKey)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("HTTP request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 for an x-mcp-header credential leak, got %d", resp.StatusCode)
	}

	var result MCPResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if result.Error == nil {
		t.Errorf("expected an MCP error body, got none")
	}
}
