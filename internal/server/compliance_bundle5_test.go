package server

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/aegishjalmur/aegir/internal/config"
	"github.com/aegishjalmur/aegir/internal/sanitizer"
	"github.com/aegishjalmur/aegir/internal/upstream"
	"github.com/gin-gonic/gin"
)

// newB5Proxy builds a full proxy with the compliance layer in the requested
// state. Detection is on (so the sanitizer pass runs before compliance, per
// the bundle-5 ordering); the echo mock upstream captures what is forwarded.
func newB5Proxy(t *testing.T, comp config.Compliance, mockURL string) *MCPProxy {
	t.Helper()
	sec := config.Security{
		AnomalyDetection: config.AnomalyDetection{Enabled: false, BlockThreshold: 0.95, LogThreshold: 0.60},
		Detection:        config.Detection{Enabled: true},
		Sanitization:     config.Sanitization{Enabled: true, PromptInjection: true, XSSPrevention: true, HomoglyphFilter: true},
	}
	cfg := &config.Config{Security: sec, Compliance: comp}
	if mockURL != "" {
		cfg.Upstream = config.Upstream{
			Services: []config.UpstreamService{{Name: "mock", URL: mockURL, Transport: "http", Enabled: true}},
		}
	}
	logger := testLogger()
	analyzer := NewMockSessionAnalyzer()
	return NewMCPProxy(cfg, logger, sanitizer.New(sec, logger),
		sanitizer.NewComplianceManager(comp, logger),
		upstream.NewManager(&cfg.Upstream, logger), analyzer, nil, nil)
}

// b5EchoMock stands in for the upstream and records the forwarded query.
func b5EchoMock() (*httptest.Server, *string) {
	var mu sync.Mutex
	q := new(string)
	mock := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		var in struct {
			Params map[string]interface{} `json:"params"`
		}
		_ = json.Unmarshal(raw, &in)
		if qv, ok := in.Params["query"].(string); ok {
			mu.Lock()
			*q = qv
			mu.Unlock()
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"result":"ok"}`))
	}))
	return mock, q
}

func b5Post(t *testing.T, router http.Handler, payload string) *httptest.ResponseRecorder {
	t.Helper()
	body, _ := json.Marshal(MCPRequest{Method: "tools/call", ID: 1, Params: map[string]interface{}{"name": "web_search", "query": payload}})
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, req)
	return w
}

// N3: a single sub-threshold SSN is forwarded REDACTED, not verbatim.
func TestB5RequestSingleSSNRedactedForward(t *testing.T) {
	gin.SetMode(gin.TestMode)
	mock, got := b5EchoMock()
	defer mock.Close()
	proxy := newB5Proxy(t, config.Compliance{Enabled: true, GDPR: config.GDPRConfig{Enabled: true, PIIDetection: true}}, mock.URL)
	router := gin.New()
	router.POST("/mcp", proxy.HandleMCPRequest)

	w := b5Post(t, router, "my ssn is 123-45-6789 please verify")
	if w.Code != http.StatusOK {
		t.Fatalf("single SSN must forward (redact is the request action), got %d: %s", w.Code, w.Body.String())
	}
	if !strings.Contains(*got, "PII_REDACTED") {
		t.Errorf("forwarded query must carry the redaction marker, got %q", *got)
	}
	if strings.Contains(*got, "123-45-6789") {
		t.Errorf("raw SSN must not be forwarded, got %q", *got)
	}
}

// F6 card posture, request side: Luhn-invalid PAN => 200, forwarded as-is
// (log-only, no redaction by default).
func TestB5RequestLuhnInvalidPANPassesThrough(t *testing.T) {
	gin.SetMode(gin.TestMode)
	mock, got := b5EchoMock()
	defer mock.Close()
	proxy := newB5Proxy(t, config.Compliance{Enabled: true, PCI: config.PCIConfig{Enabled: true, CardDetection: true}}, mock.URL)
	router := gin.New()
	router.POST("/mcp", proxy.HandleMCPRequest)

	w := b5Post(t, router, "invoice 4111 1111 1111 1112 paid")
	if w.Code != http.StatusOK {
		t.Fatalf("Luhn-invalid PAN must not block, got %d: %s", w.Code, w.Body.String())
	}
	if *got != "invoice 4111 1111 1111 1112 paid" {
		t.Errorf("log-only PAN must forward untouched, got %q", *got)
	}
}

// Fail-closed floor: Luhn-valid PAN => critical => 403 regardless of policy.
func TestB5RequestValidCardBlocks(t *testing.T) {
	gin.SetMode(gin.TestMode)
	mock, _ := b5EchoMock()
	defer mock.Close()
	// Operator tries to down-map the class — the critical floor must win.
	proxy := newB5Proxy(t, config.Compliance{
		Enabled:       true,
		PCI:           config.PCIConfig{Enabled: true, CardDetection: true},
		RequestPolicy: map[string]string{"pci": "log-only"},
	}, mock.URL)
	router := gin.New()
	router.POST("/mcp", proxy.HandleMCPRequest)

	w := b5Post(t, router, "charge card 4111 1111 1111 1111 now")
	if w.Code != http.StatusForbidden {
		t.Fatalf("Luhn-valid card must 403 even under a log-only policy map, got %d: %s", w.Code, w.Body.String())
	}
}

// S7e parity: ICD-10 diagnosis code (high) => 200 + PHI_REDACTED forward.
func TestB5RequestICD10RedactedForward(t *testing.T) {
	gin.SetMode(gin.TestMode)
	mock, got := b5EchoMock()
	defer mock.Close()
	proxy := newB5Proxy(t, config.Compliance{Enabled: true, HIPAA: config.HIPAAConfig{Enabled: true, PHIDetection: true}}, mock.URL)
	router := gin.New()
	router.POST("/mcp", proxy.HandleMCPRequest)

	w := b5Post(t, router, "patient has I10 hypertension on metoprolol")
	if w.Code != http.StatusOK {
		t.Fatalf("single ICD-10 must forward redacted, got %d: %s", w.Code, w.Body.String())
	}
	if !strings.Contains(*got, "PHI_REDACTED") || strings.Contains(*got, "I10") {
		t.Errorf("ICD-10 must be redacted in the forward, got %q", *got)
	}
}

// H5 (3 SSNs): the per-class model redacts (3 x high -> redact), masking
// every occurrence — the red-team "passes verbatim" class is closed.
func TestB5RequestThreeSSNsRedactedForward(t *testing.T) {
	gin.SetMode(gin.TestMode)
	mock, got := b5EchoMock()
	defer mock.Close()
	proxy := newB5Proxy(t, config.Compliance{Enabled: true, GDPR: config.GDPRConfig{Enabled: true, PIIDetection: true}}, mock.URL)
	router := gin.New()
	router.POST("/mcp", proxy.HandleMCPRequest)

	w := b5Post(t, router, "a: 123-45-6789 b: 987-65-4320 c: 111-22-3333")
	if w.Code != http.StatusOK {
		t.Fatalf("3 SSNs redact-forward, got %d: %s", w.Code, w.Body.String())
	}
	if strings.Contains(*got, "123-45-6789") || strings.Contains(*got, "987-65-4320") || strings.Contains(*got, "111-22-3333") {
		t.Errorf("all SSNs must be redacted in the forward, got %q", *got)
	}
	if strings.Count(*got, "PII_REDACTED") != 3 {
		t.Errorf("expected 3 redaction markers, got %q", *got)
	}
}

// Benign request with compliance on: byte-identical forward, no block.
func TestB5RequestBenignUnchanged(t *testing.T) {
	gin.SetMode(gin.TestMode)
	mock, got := b5EchoMock()
	defer mock.Close()
	proxy := newB5Proxy(t, config.Compliance{Enabled: true, GDPR: config.GDPRConfig{Enabled: true, PIIDetection: true}, PCI: config.PCIConfig{Enabled: true, CardDetection: true}, HIPAA: config.HIPAAConfig{Enabled: true, PHIDetection: true}}, mock.URL)
	router := gin.New()
	router.POST("/mcp", proxy.HandleMCPRequest)

	w := b5Post(t, router, "hello world")
	if w.Code != http.StatusOK {
		t.Fatalf("benign must forward, got %d: %s", w.Code, w.Body.String())
	}
	if *got != "hello world" {
		t.Errorf("benign forward must be byte-identical, got %q", *got)
	}
}

// Fail-closed: a redaction that corrupts the JSON structure (SSN matched
// inside a numeric field) blocks with 403 — never 500, never forwarded.
func TestB5RequestRedactionCorruptionBlocks(t *testing.T) {
	gin.SetMode(gin.TestMode)
	mock, _ := b5EchoMock()
	defer mock.Close()
	proxy := newB5Proxy(t, config.Compliance{Enabled: true, GDPR: config.GDPRConfig{Enabled: true, PIIDetection: true}}, mock.URL)
	router := gin.New()
	router.POST("/mcp", proxy.HandleMCPRequest)

	body, _ := json.Marshal(MCPRequest{Method: "tools/call", ID: 1, Params: map[string]interface{}{"name": "web_search", "ssn": 123456789}})
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("corrupting redaction must fail closed with 403, got %d: %s", w.Code, w.Body.String())
	}
}

// N2: the response "redact" action must actually mask the compliance class
// it fired on (SSN), not merely run the generic sanitizer.
func TestB5ResponseRedactMasksComplianceClass(t *testing.T) {
	logger, _ := auditLogger(t)
	proxy := newComplianceProxy(t, logger, map[string]string{"pii": "redact"})

	respJSON := `{"content":[{"type":"text","text":"Member SSN 123-45-6789 is on record."}]}`
	var current interface{}
	_ = json.Unmarshal([]byte(respJSON), &current)

	decision := proxy.enforceResponseCompliance(respJSON, current)
	if decision.action != "redact" {
		t.Fatalf("action = %q, want redact", decision.action)
	}
	out, _ := json.Marshal(decision.result)
	if !strings.Contains(string(out), "PII_REDACTED") {
		t.Errorf("redacted response must carry the PII marker, got %s", out)
	}
	if strings.Contains(string(out), "123-45-6789") {
		t.Errorf("raw SSN must not survive redaction, got %s", out)
	}
}

// F6: a loud startup warning when the compliance master is off.
func TestB5ComplianceDisabledStartupWarning(t *testing.T) {
	logPath := t.TempDir() + "/startup.log"
	cfg := &config.Config{Logging: config.Logging{
		Level: "info", Format: "json", HMACKey: "test-hmac-key-32-characters-long", File: logPath,
	}}
	if _, err := New(cfg); err != nil {
		t.Fatalf("New with empty config failed: %v", err)
	}
	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("startup log not written: %v", err)
	}
	if !strings.Contains(string(data), "Compliance detection") || !strings.Contains(string(data), "DISABLED") {
		t.Errorf("expected the compliance-disabled startup warning, log: %s", data)
	}
}

// TestB5RequestLogOnlyPolicyFidelity is the fix-round regression for the
// request-path action gate. The trigger is a HIGH-severity PCI pattern
// (exp_date — no PAN, no cvv, no track data in the payload), so under the
// approved severity matrix (critical -> block, high -> redact,
// medium/low -> log-only) the DEFAULT policy resolves 'redact', while an
// operator mapping request_policy {pci: log-only} must forward untouched.
//
// Leg A (log-only): the forward is byte-identical — the map override wins
// and the redacted copy is never applied. Leg B (control, default policy):
// the same payload comes back with the exp value replaced by its redaction
// marker, proving the gate is the policy and not the detector.
func TestB5RequestLogOnlyPolicyFidelity(t *testing.T) {
	gin.SetMode(gin.TestMode)
	mock, got := b5EchoMock()
	defer mock.Close()

	payload := "exp: 12/25, ship it when ready"

	// Leg A: operator maps the pci class to log-only.
	proxy := newB5Proxy(t, config.Compliance{
		Enabled:       true,
		PCI:           config.PCIConfig{Enabled: true, CardDetection: true},
		GDPR:          config.GDPRConfig{},
		HIPAA:         config.HIPAAConfig{},
		RequestPolicy: map[string]string{"pci": "log-only"},
	}, mock.URL)
	router := gin.New()
	router.POST("/mcp", proxy.HandleMCPRequest)

	w := b5Post(t, router, payload)
	if w.Code != http.StatusOK {
		t.Fatalf("log-only policy must not block, got %d: %s", w.Code, w.Body.String())
	}
	if *got != payload {
		t.Fatalf("log-only must forward byte-identical, got %q", *got)
	}
	if strings.Contains(*got, "REDACTED") {
		t.Fatalf("log-only must not redact: %q", *got)
	}

	// Leg B (control): same payload, default request policy (all redact).
	proxy2 := newB5Proxy(t, config.Compliance{
		Enabled: true,
		PCI:     config.PCIConfig{Enabled: true, CardDetection: true},
	}, mock.URL)
	router2 := gin.New()
	router2.POST("/mcp", proxy2.HandleMCPRequest)

	w2 := b5Post(t, router2, payload)
	if w2.Code != http.StatusOK {
		t.Fatalf("control: expected 200 (high => redact, not block), got %d: %s", w2.Code, w2.Body.String())
	}
	if !strings.Contains(*got, "CARD_DATA_REDACTED") {
		t.Fatalf("control (default policy) must redact the exp date, got %q", *got)
	}
	if strings.Contains(*got, "12/25") {
		t.Fatalf("control: raw exp date must not be forwarded, got %q", *got)
	}
}
