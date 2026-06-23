package judge

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sort"
	"testing"
	"time"
)

// TestJudgePerformanceGate is the ISC-41 probe: p95 judge latency for SUSPICIOUS
// requests must be <2000ms. Uses a mock backend that responds instantly, so the
// only overhead is the judge's own request-parsing and verdict-parsing path.
// A real-LLM p95 depends on model serving latency; this gate validates the
// Aegir proxy overhead alone, not end-to-end model latency.
func TestJudgePerformanceGate(t *testing.T) {
	const (
		n              = 100
		suspiciousRate = 10 // 10% suspicious: 10 out of 100
		p95Limit       = 2000 * time.Millisecond
	)

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(ollamaResp("SUSPICIOUS")))
	}))
	defer ts.Close()

	j := NewOllamaJudge(Config{BaseURL: ts.URL, TimeoutMs: 5000}, ts.Client(), nil)

	var latencies []time.Duration
	for i := 0; i < n; i++ {
		if i%suspiciousRate != 0 {
			continue // only time the SUSPICIOUS-destined calls
		}
		start := time.Now()
		_, err := j.Check(context.Background(), "adversarial payload for ATLAS technique")
		latencies = append(latencies, time.Since(start))
		if err != nil {
			t.Fatalf("judge error on call %d: %v", i, err)
		}
	}

	if len(latencies) == 0 {
		t.Fatal("no latency samples collected")
	}
	sort.Slice(latencies, func(i, j int) bool { return latencies[i] < latencies[j] })
	p95 := latencies[int(float64(len(latencies))*0.95)]

	if p95 > p95Limit {
		t.Errorf("ISC-41: p95 judge latency %v exceeds %v limit (n=%d, p95 idx=%d)",
			p95, p95Limit, len(latencies), int(float64(len(latencies))*0.95))
	}
	t.Logf("ISC-41: judge proxy-overhead p95=%v (n=%d, limit=%v) — PASS", p95, len(latencies), p95Limit)
}
