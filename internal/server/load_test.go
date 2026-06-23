package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
)

// TestNonJudgePathLatency is the ISC-91 probe: p99 processing latency for the
// non-judge request path must be <10ms under a 1k request load. Tests the gin
// handler directly via recorder (no TCP loopback) to measure Aegir's own
// processing overhead, not the Go HTTP stack's scheduling cost.
func TestNonJudgePathLatency(t *testing.T) {
	if testing.Short() {
		t.Skip("ISC-91: skipping load test in -short mode")
	}

	gin.SetMode(gin.TestMode)
	proxy := createTestMCPProxy(t)

	initReq := MCPRequest{
		Method: "initialize",
		Params: map[string]interface{}{
			"protocolVersion": "2024-11-05",
		},
		ID: "load-test",
	}
	body, _ := json.Marshal(initReq)

	const n = 1000
	latencies := make([]time.Duration, n)
	var wg sync.WaitGroup
	sem := make(chan struct{}, 50)

	for i := range n {
		wg.Add(1)
		sem <- struct{}{}
		go func(idx int) {
			defer wg.Done()
			defer func() { <-sem }()

			// Use gin recorder — measures handler processing time without TCP overhead.
			w := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(w)
			req, _ := http.NewRequest("POST", "/mcp", bytes.NewBuffer(body))
			req.Header.Set("Content-Type", "application/json")
			c.Request = req

			start := time.Now()
			proxy.HandleMCPRequest(c)
			latencies[idx] = time.Since(start)
		}(i)
	}
	wg.Wait()

	sort.Slice(latencies, func(i, j int) bool { return latencies[i] < latencies[j] })
	p99 := latencies[int(float64(n)*0.99)]
	p50 := latencies[n/2]

	t.Logf("ISC-91: p50=%v p99=%v (n=%d, limit=10ms)", p50, p99, n)

	const p99Limit = 10 * time.Millisecond
	if p99 > p99Limit {
		t.Errorf("ISC-91: non-judge p99=%v exceeds %v processing gate under %d req load", p99, p99Limit, n)
	}
}

// TestDetectionThroughput is the ISC-92 probe: pattern-based detection must
// sustain 10k req/s throughput on a single node. Tests the sanitizer layer
// directly — measuring detection processing overhead without network.
func TestDetectionThroughput(t *testing.T) {
	if testing.Short() {
		t.Skip("ISC-92: skipping throughput test in -short mode")
	}

	const (
		n        = 10000
		duration = time.Second
	)

	proxy := createTestMCPProxy(t)
	payload := `{"method":"tools/call","params":{"name":"safe_tool","arguments":{"query":"hello world"}}}`

	start := time.Now()
	count := 0
	for time.Since(start) < duration && count < n {
		_ = proxy.sanitizer.SanitizeContent(payload)
		count++
	}
	elapsed := time.Since(start)
	rps := float64(count) / elapsed.Seconds()

	t.Logf("ISC-92: detection throughput=%.0f req/s (n=%d, elapsed=%v, target=10000)", rps, count, elapsed)

	if rps < 10000 {
		t.Errorf("ISC-92: detection throughput %.0f req/s is below 10k req/s gate", rps)
	}
}
