package dashboard

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/aegishjalmur/aegir/internal/config"
	"github.com/aegishjalmur/aegir/internal/logging"
	"github.com/gin-gonic/gin"
)

func init() {
	gin.SetMode(gin.TestMode)
}

// newTestLogger returns a logger suitable for tests (writes to /dev/null-equivalent).
func newTestLogger(t *testing.T) *logging.Logger {
	t.Helper()
	logger, err := logging.New(config.Logging{
		Level:           "info",
		Format:          "json",
		HMACKey:         "test-hmac-key-32-characters-long",
		IntegrityChecks: false,
	})
	if err != nil {
		t.Fatalf("newTestLogger: %v", err)
	}
	return logger
}

// newTestCollector creates a StatsCollector backed by a test logger.
func newTestCollector(t *testing.T) *StatsCollector {
	t.Helper()
	return NewStatsCollector(newTestLogger(t))
}

// --- StatsCollector unit tests ---

func TestNewStatsCollector_InitialState(t *testing.T) {
	sc := newTestCollector(t)
	d := sc.GetDashboard()

	if d.TotalRequests != 0 {
		t.Errorf("TotalRequests = %d, want 0", d.TotalRequests)
	}
	if d.TotalAttacksBlocked != 0 {
		t.Errorf("TotalAttacksBlocked = %d, want 0", d.TotalAttacksBlocked)
	}
	if d.ActiveRequests != 0 {
		t.Errorf("ActiveRequests = %d, want 0", d.ActiveRequests)
	}
	if d.AttacksBlocked == nil {
		t.Error("AttacksBlocked map is nil")
	}
	if d.Uptime == "" {
		t.Error("Uptime is empty")
	}
}

func TestRecordAndFinishRequest_UpdatesCounters(t *testing.T) {
	sc := newTestCollector(t)

	sc.RecordRequest("req-1", "POST", "/mcp", "127.0.0.1", "test-agent")

	d := sc.GetDashboard()
	if d.TotalRequests != 1 {
		t.Errorf("TotalRequests after record = %d, want 1", d.TotalRequests)
	}
	if d.ActiveRequests != 1 {
		t.Errorf("ActiveRequests after record = %d, want 1", d.ActiveRequests)
	}

	sc.FinishRequest("req-1", http.StatusOK, 100, 200, nil)

	d = sc.GetDashboard()
	if d.TotalRequests != 1 {
		t.Errorf("TotalRequests after finish = %d, want 1", d.TotalRequests)
	}
	if d.ActiveRequests != 0 {
		t.Errorf("ActiveRequests after finish = %d, want 0", d.ActiveRequests)
	}
	if d.BytesProcessed != 100 {
		t.Errorf("BytesProcessed = %d, want 100", d.BytesProcessed)
	}
	if d.BytesTransferred != 200 {
		t.Errorf("BytesTransferred = %d, want 200", d.BytesTransferred)
	}
}

func TestFinishRequest_UnknownID_IsNoOp(t *testing.T) {
	sc := newTestCollector(t)
	// Should not panic or change any counters.
	sc.FinishRequest("never-started", http.StatusOK, 0, 0, nil)
	if d := sc.GetDashboard(); d.TotalRequests != 0 {
		t.Error("TotalRequests should remain 0 after finishing unknown request")
	}
}

func TestRecordAttack_TracksPerCategory(t *testing.T) {
	sc := newTestCollector(t)

	sc.RecordAttack(AttackPromptInjection, map[string]any{"detail": "test"})
	sc.RecordAttack(AttackPromptInjection, map[string]any{"detail": "test2"})
	sc.RecordAttack(AttackJailbreak, map[string]any{})

	d := sc.GetDashboard()
	if d.TotalAttacksBlocked != 3 {
		t.Errorf("TotalAttacksBlocked = %d, want 3", d.TotalAttacksBlocked)
	}
	if d.AttacksBlocked[AttackPromptInjection] != 2 {
		t.Errorf("prompt_injection count = %d, want 2", d.AttacksBlocked[AttackPromptInjection])
	}
	if d.AttacksBlocked[AttackJailbreak] != 1 {
		t.Errorf("jailbreak count = %d, want 1", d.AttacksBlocked[AttackJailbreak])
	}
}

func TestFinishRequest_RecordsAttacksInRecentRequests(t *testing.T) {
	sc := newTestCollector(t)

	sc.RecordRequest("req-atk", "POST", "/mcp", "1.2.3.4", "ua")
	sc.FinishRequest("req-atk", http.StatusForbidden, 50, 0, []AttackCategory{AttackXSS, AttackSQLInjection})

	d := sc.GetDashboard()
	if d.TotalAttacksBlocked != 2 {
		t.Errorf("TotalAttacksBlocked = %d, want 2", d.TotalAttacksBlocked)
	}
	if len(d.RecentRequests) != 1 {
		t.Fatalf("RecentRequests len = %d, want 1", len(d.RecentRequests))
	}
	req := d.RecentRequests[0]
	if len(req.AttacksFound) != 2 {
		t.Errorf("AttacksFound len = %d, want 2", len(req.AttacksFound))
	}
}

func TestRecentRequests_CappedAt100(t *testing.T) {
	sc := newTestCollector(t)

	for i := range 120 {
		id := fmt.Sprintf("req-%d", i)
		sc.RecordRequest(id, "GET", "/mcp", "1.2.3.4", "ua")
		sc.FinishRequest(id, http.StatusOK, 10, 10, nil)
	}

	d := sc.GetDashboard()
	if len(d.RecentRequests) > 100 {
		t.Errorf("RecentRequests len = %d, want ≤100", len(d.RecentRequests))
	}
	if d.TotalRequests != 120 {
		t.Errorf("TotalRequests = %d, want 120", d.TotalRequests)
	}
}

func TestGetDashboard_ComputesAverageRequestTime(t *testing.T) {
	sc := newTestCollector(t)

	// Force known request times directly (white-box).
	sc.mu.Lock()
	sc.requestTimes = []time.Duration{100 * time.Millisecond, 200 * time.Millisecond, 300 * time.Millisecond}
	sc.mu.Unlock()

	d := sc.GetDashboard()
	want := 200 * time.Millisecond
	if d.AverageRequestTime != want {
		t.Errorf("AverageRequestTime = %v, want %v", d.AverageRequestTime, want)
	}
}

func TestGetDashboard_ComputesMedianRequestTime(t *testing.T) {
	sc := newTestCollector(t)

	sc.mu.Lock()
	sc.requestTimes = []time.Duration{
		50 * time.Millisecond,
		100 * time.Millisecond,
		300 * time.Millisecond,
	}
	sc.mu.Unlock()

	d := sc.GetDashboard()
	// Sorted: [50, 100, 300] → median index 1 = 100ms.
	want := 100 * time.Millisecond
	if d.MedianRequestTime != want {
		t.Errorf("MedianRequestTime = %v, want %v", d.MedianRequestTime, want)
	}
}

func TestConcurrentRecordRequest_NoDataRace(t *testing.T) {
	sc := newTestCollector(t)

	var wg sync.WaitGroup
	for i := range 50 {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			id := fmt.Sprintf("concurrent-%d", n)
			sc.RecordRequest(id, "POST", "/mcp", "1.2.3.4", "ua")
			sc.FinishRequest(id, http.StatusOK, 10, 10, nil)
		}(i)
	}
	wg.Wait()

	if d := sc.GetDashboard(); d.TotalRequests != 50 {
		t.Errorf("TotalRequests under concurrency = %d, want 50", d.TotalRequests)
	}
}

// --- DashboardAPI handler tests ---

// newTestRouter wires the DashboardAPI handlers onto a gin router under /api/dashboard.
func newTestRouter(t *testing.T, sc *StatsCollector) *gin.Engine {
	t.Helper()
	r := gin.New()
	api := NewDashboardAPI(sc)
	api.RegisterRoutes(r.Group("/api"))
	return r
}

func TestHandler_GetStats_Returns200(t *testing.T) {
	sc := newTestCollector(t)
	r := newTestRouter(t, sc)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/dashboard/stats", nil)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", w.Code)
	}

	var body map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("response not valid JSON: %v", err)
	}

	for _, key := range []string{"uptime", "total_requests", "active_requests", "total_attacks_blocked"} {
		if _, ok := body[key]; !ok {
			t.Errorf("response missing key %q", key)
		}
	}
}

func TestHandler_GetAttackStats_Returns200(t *testing.T) {
	sc := newTestCollector(t)
	sc.RecordAttack(AttackPromptInjection, map[string]any{})
	r := newTestRouter(t, sc)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/dashboard/attacks", nil)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", w.Code)
	}
	var body map[string]any
	json.Unmarshal(w.Body.Bytes(), &body) //nolint:errcheck
	if _, ok := body["total_attacks"]; !ok {
		t.Error("response missing total_attacks")
	}
	if _, ok := body["attacks_by_type"]; !ok {
		t.Error("response missing attacks_by_type")
	}
}

func TestHandler_GetPerformanceStats_Returns200(t *testing.T) {
	sc := newTestCollector(t)
	r := newTestRouter(t, sc)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/dashboard/performance", nil)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", w.Code)
	}
	var body map[string]any
	json.Unmarshal(w.Body.Bytes(), &body) //nolint:errcheck
	for _, key := range []string{"requests", "response_times", "throughput", "system"} {
		if _, ok := body[key]; !ok {
			t.Errorf("response missing key %q", key)
		}
	}
}

func TestHandler_GetRecentRequests_DefaultLimit(t *testing.T) {
	sc := newTestCollector(t)
	for i := range 10 {
		id := fmt.Sprintf("r%d", i)
		sc.RecordRequest(id, "GET", "/mcp", "1.2.3.4", "ua")
		sc.FinishRequest(id, http.StatusOK, 0, 0, nil)
	}
	r := newTestRouter(t, sc)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/dashboard/requests", nil)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", w.Code)
	}
	var body map[string]any
	json.Unmarshal(w.Body.Bytes(), &body) //nolint:errcheck
	if body["limit"].(float64) != 50 {
		t.Errorf("default limit = %v, want 50", body["limit"])
	}
}

func TestHandler_GetRecentRequests_LimitCappedAt100(t *testing.T) {
	sc := newTestCollector(t)
	r := newTestRouter(t, sc)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/dashboard/requests?limit=999", nil)
	r.ServeHTTP(w, req)

	var body map[string]any
	json.Unmarshal(w.Body.Bytes(), &body) //nolint:errcheck
	if body["limit"].(float64) != 100 {
		t.Errorf("limit should be capped at 100, got %v", body["limit"])
	}
}

func TestHandler_GetHealthSummary_Healthy(t *testing.T) {
	sc := newTestCollector(t)
	r := newTestRouter(t, sc)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/dashboard/health", nil)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", w.Code)
	}
	var body map[string]any
	json.Unmarshal(w.Body.Bytes(), &body) //nolint:errcheck
	if body["status"] != "healthy" {
		t.Errorf("status = %q, want \"healthy\"", body["status"])
	}
	alerts, _ := body["alerts"].([]any)
	if len(alerts) != 0 {
		t.Errorf("alerts = %v, want empty", alerts)
	}
}

func TestHandler_GetHealthSummary_HighAttackRate_Critical(t *testing.T) {
	sc := newTestCollector(t)

	// Add 55 requests each with 2 attacks (110 total) so the sum exceeds the >100
	// threshold even after the 100-entry RecentRequests ring-buffer cap.
	for i := range 55 {
		id := fmt.Sprintf("atk-%d", i)
		sc.RecordRequest(id, "POST", "/mcp", "1.2.3.4", "ua")
		sc.FinishRequest(id, http.StatusForbidden, 0, 0, []AttackCategory{AttackPromptInjection, AttackXSS})
	}

	r := newTestRouter(t, sc)
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/dashboard/health", nil)
	r.ServeHTTP(w, req)

	var body map[string]any
	json.Unmarshal(w.Body.Bytes(), &body) //nolint:errcheck
	if body["status"] != "critical" {
		t.Errorf("status = %q, want \"critical\" under high attack rate", body["status"])
	}
}

func TestHandler_GetHealthSummary_SlowResponses_Warning(t *testing.T) {
	sc := newTestCollector(t)

	// Inject a request time > 5 seconds directly (white-box).
	sc.mu.Lock()
	sc.requestTimes = []time.Duration{6 * time.Second}
	sc.mu.Unlock()

	r := newTestRouter(t, sc)
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/dashboard/health", nil)
	r.ServeHTTP(w, req)

	var body map[string]any
	json.Unmarshal(w.Body.Bytes(), &body) //nolint:errcheck
	if body["status"] != "warning" {
		t.Errorf("status = %q, want \"warning\" for slow avg response time", body["status"])
	}
}

func TestHandler_ResetStats_Attacks(t *testing.T) {
	sc := newTestCollector(t)
	sc.RecordAttack(AttackXSS, map[string]any{})
	r := newTestRouter(t, sc)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/dashboard/reset?type=attacks", nil)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", w.Code)
	}
	if d := sc.GetDashboard(); d.TotalAttacksBlocked != 0 {
		t.Errorf("TotalAttacksBlocked after reset = %d, want 0", d.TotalAttacksBlocked)
	}
}

func TestHandler_ResetStats_Performance(t *testing.T) {
	sc := newTestCollector(t)
	sc.mu.Lock()
	sc.requestTimes = []time.Duration{100 * time.Millisecond, 200 * time.Millisecond}
	sc.dashboard.LongestRequestTime = 500 * time.Millisecond
	sc.mu.Unlock()

	r := newTestRouter(t, sc)
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/dashboard/reset?type=performance", nil)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", w.Code)
	}
	sc.mu.RLock()
	rt := len(sc.requestTimes)
	lt := sc.dashboard.LongestRequestTime
	sc.mu.RUnlock()
	if rt != 0 {
		t.Errorf("requestTimes len after reset = %d, want 0", rt)
	}
	if lt != 0 {
		t.Errorf("LongestRequestTime after reset = %v, want 0", lt)
	}
}

func TestHandler_ResetStats_Requests(t *testing.T) {
	sc := newTestCollector(t)
	sc.RecordRequest("r1", "GET", "/mcp", "1.2.3.4", "ua")
	sc.FinishRequest("r1", http.StatusOK, 0, 0, nil)

	r := newTestRouter(t, sc)
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/dashboard/reset?type=requests", nil)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", w.Code)
	}
	if d := sc.GetDashboard(); len(d.RecentRequests) != 0 {
		t.Errorf("RecentRequests len after reset = %d, want 0", len(d.RecentRequests))
	}
}

func TestHandler_ResetStats_InvalidType_Returns400(t *testing.T) {
	sc := newTestCollector(t)
	r := newTestRouter(t, sc)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/dashboard/reset?type=bogus", nil)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
}

// --- Middleware tests ---

func newMiddlewareRouter(t *testing.T, sc *StatsCollector) *gin.Engine {
	t.Helper()
	r := gin.New()
	r.Use(sc.Middleware())
	r.GET("/mcp", func(c *gin.Context) { c.Status(http.StatusOK) })
	r.GET("/health", func(c *gin.Context) { c.Status(http.StatusOK) })
	r.GET("/metrics", func(c *gin.Context) { c.Status(http.StatusOK) })
	r.GET("/api/dashboard/stats", func(c *gin.Context) { c.Status(http.StatusOK) })
	return r
}

func TestMiddleware_SkipsHealthPath(t *testing.T) {
	sc := newTestCollector(t)
	r := newMiddlewareRouter(t, sc)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/health", nil))

	if d := sc.GetDashboard(); d.TotalRequests != 0 {
		t.Errorf("TotalRequests after /health = %d, want 0 (should be skipped)", d.TotalRequests)
	}
}

func TestMiddleware_SkipsMetricsPath(t *testing.T) {
	sc := newTestCollector(t)
	r := newMiddlewareRouter(t, sc)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/metrics", nil))

	if d := sc.GetDashboard(); d.TotalRequests != 0 {
		t.Errorf("TotalRequests after /metrics = %d, want 0 (should be skipped)", d.TotalRequests)
	}
}

func TestMiddleware_SkipsDashboardPaths(t *testing.T) {
	sc := newTestCollector(t)
	r := newMiddlewareRouter(t, sc)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/dashboard/stats", nil))

	if d := sc.GetDashboard(); d.TotalRequests != 0 {
		t.Errorf("TotalRequests after /api/dashboard/* = %d, want 0 (should be skipped)", d.TotalRequests)
	}
}

func TestMiddleware_RecordsRegularRequests(t *testing.T) {
	sc := newTestCollector(t)
	r := newMiddlewareRouter(t, sc)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/mcp", nil))

	if d := sc.GetDashboard(); d.TotalRequests != 1 {
		t.Errorf("TotalRequests after /mcp = %d, want 1", d.TotalRequests)
	}
}

// --- rpsCalculator unit tests ---

func TestRPSCalculator_ZeroInitially(t *testing.T) {
	rps := newRPSCalculator(60 * time.Second)
	if got := rps.getCurrentRPS(); got != 0 {
		t.Errorf("initial RPS = %f, want 0", got)
	}
}

func TestRPSCalculator_CountsWithinWindow(t *testing.T) {
	rps := newRPSCalculator(60 * time.Second)
	now := time.Now()
	for i := 0; i < 60; i++ {
		rps.addRequest(now.Add(time.Duration(i) * time.Second))
	}
	// 60 requests over 60 second window ≈ 1 RPS.
	got := rps.getCurrentRPS()
	if got == 0 {
		t.Error("RPS should be > 0 after adding requests")
	}
}
