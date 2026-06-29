// Aegir latency benchmark tool.
//
// Measures end-to-end p50/p95/p99 latency through a live Aegir instance across
// scenario categories: clean, pattern, suspicious, hard-block.
//
// Usage:
//
//	go run ./benchmark [flags]
//	  --target       https://localhost:8443   Aegir base URL
//	  --token        <jwt>                    Bearer token (or AEGIR_BENCH_TOKEN env)
//	  --payload-file <path>                   Optional: one JSON-RPC payload per line
//	  --iterations   200                      Requests per built-in scenario
//	  --concurrency  10                       Parallel workers
//	  --judge-provider ollama|openai|anthropic Label for the judge backend in report
//	  --insecure                              Skip TLS verification (local dev)
//
// Payload file (optional):
//
//	Pass a JSONL corpus file or a plain-text file (one payload per line).
//	JSONL format: {"id":"...","payload":"...","attack_module":"...","owasp":"..."}
//
//	  go run ./benchmark --payload-file redteam/aegir/benign_corpus.jsonl
//	  go run ./benchmark --payload-file redteam/aegir/corpus/adversarial.jsonl
//
//	Generate adversarial.jsonl first: cd redteam/aegir && python3 harvest.py
//
// Judge backend:
//
//	Configuration is Aegir-side (aegir.yaml / MCP_JUDGE_* env vars), not here.
//	--judge-provider is a report label only — it does NOT route to any backend.
//	To actually run with OMLX as judge: start Aegir via 'just run-judge-omlx',
//	then set AEGIR_BENCH_JUDGE=omlx for the report label.
package main

import (
	"bufio"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"math"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
)

type scenario struct {
	category string
	name     string
	payload  string
}

type reqResult struct {
	latency time.Duration
	status  int
}

type categoryStats struct {
	latencies []time.Duration
	statuses  map[int]int
}

func main() {
	target := flag.String("target", "https://localhost:8443", "Aegir base URL")
	tokenFlag := flag.String("token", "", "Bearer JWT (or AEGIR_BENCH_TOKEN env)")
	payloadFile := flag.String("payload-file", "", "Optional file with one text payload per line")
	iterations := flag.Int("iterations", 200, "Requests per scenario")
	concurrency := flag.Int("concurrency", 10, "Parallel workers")
	judgeProvider := flag.String("judge-provider", "ollama", "Judge backend label (report only)")
	insecure := flag.Bool("insecure", true, "Skip TLS verification")
	flag.Parse()

	token := *tokenFlag
	if token == "" {
		token = os.Getenv("AEGIR_BENCH_TOKEN")
	}
	if token == "" {
		fmt.Fprintln(os.Stderr, "error: provide --token or set AEGIR_BENCH_TOKEN")
		os.Exit(1)
	}

	scenarios := loadScenarios(*payloadFile)

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: *insecure}, //nolint:gosec
	}
	client := &http.Client{Transport: transport, Timeout: 30 * time.Second}

	fmt.Printf("Aegir Latency Benchmark\n")
	fmt.Printf("Target:        %s\n", *target)
	fmt.Printf("Judge backend: %s\n", *judgeProvider)
	fmt.Printf("Iterations:    %d per scenario\n", *iterations)
	fmt.Printf("Concurrency:   %d workers\n", *concurrency)
	fmt.Printf("Scenarios:     %d\n\n", len(scenarios))

	byCategory := map[string]*categoryStats{}

	for _, sc := range scenarios {
		label := fmt.Sprintf("%-40s [%s]", sc.name, sc.category)
		fmt.Printf("Running %-55s ... ", label)

		results := runScenario(client, *target, token, sc.payload, *iterations, *concurrency)

		cat := sc.category
		if byCategory[cat] == nil {
			byCategory[cat] = &categoryStats{statuses: map[int]int{}}
		}
		cs := byCategory[cat]
		lats := make([]time.Duration, len(results))
		for i, r := range results {
			lats[i] = r.latency
			cs.latencies = append(cs.latencies, r.latency)
			cs.statuses[r.status]++
		}

		p50, p95, p99 := percentiles(lats)
		fmt.Printf("p50=%s p95=%s p99=%s\n", fmtDur(p50), fmtDur(p95), fmtDur(p99))
	}

	fmt.Printf("\n%-22s %10s %10s %10s %10s   statuses\n", "CATEGORY", "p50", "p95", "p99", "max")
	fmt.Printf("%s\n", strings.Repeat("-", 82))

	cats := sortedKeys(byCategory)
	for _, cat := range cats {
		cs := byCategory[cat]
		sort.Slice(cs.latencies, func(i, j int) bool { return cs.latencies[i] < cs.latencies[j] })
		p50, p95, p99 := percentiles(cs.latencies)
		maxLat := cs.latencies[len(cs.latencies)-1]
		fmt.Printf("%-22s %10s %10s %10s %10s   %s\n",
			cat, fmtDur(p50), fmtDur(p95), fmtDur(p99), fmtDur(maxLat), fmtStatuses(cs.statuses))
	}
}

func runScenario(client *http.Client, target, token, payload string, iterations, concurrency int) []reqResult {
	jobs := make(chan struct{}, iterations)
	for i := 0; i < iterations; i++ {
		jobs <- struct{}{}
	}
	close(jobs)

	out := make([]reqResult, 0, iterations)
	var mu sync.Mutex
	var wg sync.WaitGroup

	for w := 0; w < concurrency; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range jobs {
				r := send(client, target, token, payload)
				mu.Lock()
				out = append(out, r)
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	return out
}

func send(client *http.Client, target, token, payload string) reqResult {
	payloadJSON, _ := json.Marshal(payload)
	body := fmt.Sprintf(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"bench","arguments":{"input":%s}}}`, string(payloadJSON))

	req, _ := http.NewRequest("POST", target+"/mcp", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)

	start := time.Now()
	resp, err := client.Do(req)
	lat := time.Since(start)

	status := 0
	if err == nil {
		status = resp.StatusCode
		resp.Body.Close()
	}
	return reqResult{latency: lat, status: status}
}

// corpusEntry matches the JSONL format produced by harvest.py and benign_corpus.jsonl.
type corpusEntry struct {
	ID           string `json:"id"`
	Payload      string `json:"payload"`
	AttackModule string `json:"attack_module"`
	OWASP        string `json:"owasp"`
}

func loadScenarios(payloadFile string) []scenario {
	if payloadFile != "" {
		if out := loadFile(payloadFile); len(out) > 0 {
			fmt.Printf("Loaded %d payloads from %s\n\n", len(out), payloadFile)
			return out
		}
	}
	fmt.Printf("Using built-in representative scenarios\n\n")
	return builtInScenarios()
}

func loadFile(path string) []scenario {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()

	var out []scenario
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<20) // 1 MiB per line for long payloads
	i := 0
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		i++
		// Try JSONL corpus format first (has "payload" field).
		var entry corpusEntry
		if err := json.Unmarshal([]byte(line), &entry); err == nil && entry.Payload != "" {
			cat := entry.AttackModule
			if cat == "" {
				cat = "custom"
			}
			id := entry.ID
			if id == "" {
				id = fmt.Sprintf("%d", i)
			}
			out = append(out, scenario{category: cat, name: cat + "/" + id, payload: entry.Payload})
			continue
		}
		// Fall back to plain-text: one payload per line.
		out = append(out, scenario{category: "custom", name: fmt.Sprintf("custom/%d", i), payload: line})
	}
	if err := sc.Err(); err != nil {
		fmt.Fprintf(os.Stderr, "warning: scanner error reading %s: %v\n", path, err)
	}
	return out
}

func percentiles(sorted []time.Duration) (p50, p95, p99 time.Duration) {
	n := len(sorted)
	if n == 0 {
		return
	}
	idx := func(pct float64) int {
		return clamp(int(math.Round(float64(n)*pct))-1, 0, n-1)
	}
	return sorted[idx(0.50)], sorted[idx(0.95)], sorted[idx(0.99)]
}

func clamp(v, lo, hi int) int {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

func fmtDur(d time.Duration) string {
	if d >= time.Second {
		return fmt.Sprintf("%.2fs", d.Seconds())
	}
	return fmt.Sprintf("%dms", d.Milliseconds())
}

func fmtStatuses(m map[int]int) string {
	codes := sortedIntKeys(m)
	parts := make([]string, 0, len(codes))
	for _, c := range codes {
		parts = append(parts, fmt.Sprintf("%d×%d", c, m[c]))
	}
	return strings.Join(parts, " ")
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func sortedIntKeys(m map[int]int) []int {
	keys := make([]int, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Ints(keys)
	return keys
}
