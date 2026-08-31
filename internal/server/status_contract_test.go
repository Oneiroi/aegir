package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"

	"github.com/aegishjalmur/aegir/internal/config"
	"github.com/aegishjalmur/aegir/internal/logging"
	"github.com/aegishjalmur/aegir/internal/sanitizer"
	"github.com/aegishjalmur/aegir/internal/upstream"
)

// newContractProxy builds a minimal MCPProxy for status-contract assertions:
// real sanitizer + compliance manager, no upstreams (standalone mode), and a
// configurable meta inspector.
func newContractProxy(t *testing.T, comp config.Compliance, mi config.MetaInspectionConfig) *MCPProxy {
	t.Helper()
	gin.SetMode(gin.TestMode)
	logger, _ := logging.New(config.Logging{
		Level:   "info",
		Format:  "json",
		HMACKey: "test-hmac-key-32-characters-long",
	})
	sec := config.Security{
		Sanitization:    config.Sanitization{Enabled: true},
		SecretDetection: config.SecretDetection{Enabled: true},
		MetaInspection:  mi,
	}
	cfg := &config.Config{Security: sec, Compliance: comp}
	return NewMCPProxy(cfg, logger,
		sanitizer.New(sec, logger),
		sanitizer.NewComplianceManager(comp, logger),
		upstream.NewManager(&config.Upstream{}, logger),
		nil, nil, nil)
}

// postMCP posts a raw body to the proxy's /mcp handler and returns the
// recorder.
func postMCP(t *testing.T, proxy *MCPProxy, body string) *httptest.ResponseRecorder {
	t.Helper()
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	req := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	c.Request = req
	proxy.HandleMCPRequest(c)
	return w
}

// TestStatusContract is the F8/bundle-6 regression: every gate returns a
// consistent HTTP status + MCP error code pair (see README "API error
// contract"). Clients monitoring status codes must see every block as 4xx.
func TestStatusContract(t *testing.T) {
	comp := config.Compliance{
		Enabled: true,
		PCI:     config.PCIConfig{Enabled: true, CardDetection: true},
	}

	tests := []struct {
		name         string
		proxy        *MCPProxy
		body         string
		wantStatus   int
		wantErrCode  int
	}{
		{
			name:         "malformed JSON -> 400 / -32600",
			proxy:        newContractProxy(t, comp, config.MetaInspectionConfig{Enabled: true}),
			body:         `{not json`,
			wantStatus:   http.StatusBadRequest,
			wantErrCode:  -32600,
		},
		{
			name:         "unknown method (standalone) -> 200 / -32601",
			proxy:        newContractProxy(t, comp, config.MetaInspectionConfig{Enabled: true}),
			body:         `{"jsonrpc":"2.0","method":"bogus/method","id":1}`,
			wantStatus:   http.StatusOK,
			wantErrCode:  -32601,
		},
		{
			name:         "meta-inspection reject -> 403 / -32000",
			proxy:        newContractProxy(t, comp, config.MetaInspectionConfig{Enabled: true, RejectUnknown: true}),
			body:         `{"jsonrpc":"2.0","method":"tools/call","params":{"name":"t","arguments":{"q":"x"},"_meta":{"rogueKey":"x"}},"id":1}`,
			wantStatus:   http.StatusForbidden,
			wantErrCode:  -32000,
		},
		{
			name:         "compliance critical block -> 403 / -32001",
			proxy:        newContractProxy(t, comp, config.MetaInspectionConfig{Enabled: true}),
			body:         `{"jsonrpc":"2.0","method":"tools/call","params":{"name":"t","arguments":{"q":"card cvv 123"}},"id":1}`,
			wantStatus:   http.StatusForbidden,
			wantErrCode:  -32001,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := postMCP(t, tt.proxy, tt.body)
			if w.Code != tt.wantStatus {
				t.Fatalf("status = %d, want %d (body: %s)", w.Code, tt.wantStatus, w.Body.String())
			}
			var resp MCPResponse
			if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
				t.Fatalf("response is not an MCPResponse: %v (body: %s)", err, w.Body.String())
			}
			if resp.Error == nil {
				t.Fatalf("expected an MCP error object, got result (body: %s)", w.Body.String())
			}
			if resp.Error.Code != tt.wantErrCode {
				t.Errorf("error code = %d, want %d (body: %s)", resp.Error.Code, tt.wantErrCode, w.Body.String())
			}
		})
	}
}
