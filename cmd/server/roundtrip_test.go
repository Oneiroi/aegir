package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestUpstreamRoundTrip is the F9(3)/F1 probe: assert that upstream content
// actually round-trips through the real binary — build once, run an in-test
// echo upstream, point aegir at it via a temp --config, and verify a canary
// string in a tools/call argument comes back in the response. This is the
// end-to-end path the unit tests (gin recorder) cannot exercise.
func TestUpstreamRoundTrip(t *testing.T) {
	if testing.Short() {
		t.Skip("F9: skipping round-trip probe in -short mode")
	}

	// Build the binary once.
	build := exec.Command("go", "build", "-o", "test-aegir-roundtrip", ".")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("Failed to build test binary: %v: %s", err, out)
	}
	defer os.Remove("./test-aegir-roundtrip")

	// In-test echo upstream: returns the request params in the result text.
	echo := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		// Marshal the response so the embedded body is JSON-escaped (a raw
		// Fprintf of the body's quotes would produce invalid JSON).
		resp := map[string]interface{}{
			"jsonrpc": "2.0",
			"result":  map[string]interface{}{"content": []map[string]string{{"type": "text", "text": "echo: " + string(raw)}}},
			"id":      1,
		}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer echo.Close()

	// Temp config: TLS off, rate limit off, upstream = the echo server.
	tmp := t.TempDir()
	cfgPath := filepath.Join(tmp, "aegir-rt.yaml")
	cfg := fmt.Sprintf(`environment: development
server:
  port: 18999
  host: "127.0.0.1"
  tls:
    enabled: false
auth:
  jwt:
    secret: "roundtrip-test-secret-32-characters-min"
    issuer: "aegir"
logging:
  level: "info"
  format: "text"
  file: %q
  hmac_key: "roundtrip-test-hmac-key-32-characters-min"
security:
  rate_limit:
    enabled: false
upstream:
  services:
    - name: "echo"
      url: %q
      transport: "http"
      enabled: true
      timeout: 30
`, filepath.Join(tmp, "aegir.log"), echo.URL)
	if err := os.WriteFile(cfgPath, []byte(cfg), 0o600); err != nil {
		t.Fatalf("write temp config: %v", err)
	}

	// Start aegir against the echo upstream.
	logPath := filepath.Join(tmp, "aegir.log")
	logFile, err := os.Create(logPath)
	if err != nil {
		t.Fatalf("create log file: %v", err)
	}
	defer logFile.Close()

	cmd := exec.Command("./test-aegir-roundtrip", "--config", cfgPath)
	cmd.Env = append(os.Environ(), "AEGIR_ALLOW_INSECURE_JWT_SECRET=true")
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	if err := cmd.Start(); err != nil {
		t.Fatalf("start aegir: %v", err)
	}
	defer func() {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
	}()

	base := "http://127.0.0.1:18999"

	// Poll /health (the justfile's own pattern) — no fixed sleep.
	healthy := false
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		if resp, err := http.Get(base + "/health"); err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				healthy = true
				break
			}
		}
		time.Sleep(200 * time.Millisecond)
	}
	if !healthy {
		logs, _ := os.ReadFile(logPath)
		t.Fatalf("aegir did not become healthy within deadline; log:\n%s", logs)
	}

	// Read the generated admin password from the startup log line.
	password := ""
	deadline = time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		logs, _ := os.ReadFile(logPath)
		for _, line := range strings.Split(string(logs), "\n") {
			if i := strings.Index(line, "Admin password (save this): "); i >= 0 {
				password = strings.TrimSpace(line[i+len("Admin password (save this): "):])
			}
		}
		if password != "" {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	if password == "" {
		logs, _ := os.ReadFile(logPath)
		t.Fatalf("could not read admin password from log; log:\n%s", logs)
	}

	// Log in for a JWT.
	loginBody, _ := json.Marshal(map[string]string{"username": "admin", "password": password})
	resp, err := http.Post(base+"/auth/login", "application/json", bytes.NewReader(loginBody))
	if err != nil {
		t.Fatalf("login POST: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("login status = %d, want 200 (body: %s)", resp.StatusCode, body)
	}
	var loginResp struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&loginResp); err != nil {
		t.Fatalf("decode login response: %v", err)
	}
	if loginResp.AccessToken == "" {
		t.Fatal("login returned an empty access_token")
	}

	// Canary round-trip: a tools/call whose argument carries the canary must
	// come back through the upstream echo in the response.
	const canary = "AEGIR-RT-CANARY-20260828"
	callBody, _ := json.Marshal(map[string]interface{}{
		"jsonrpc": "2.0",
		"method":  "tools/call",
		"params":  map[string]interface{}{"name": "echo", "arguments": map[string]interface{}{"query": canary}},
		"id":      1,
	})
	req, _ := http.NewRequest(http.MethodPost, base+"/mcp", bytes.NewReader(callBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+loginResp.AccessToken)
	resp2, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("tools/call POST: %v", err)
	}
	defer resp2.Body.Close()
	body2, _ := io.ReadAll(resp2.Body)
	if resp2.StatusCode != http.StatusOK {
		logs, _ := os.ReadFile(logPath)
		t.Fatalf("tools/call status = %d, want 200 (body: %s); aegir log:\n%s", resp2.StatusCode, body2, logs)
	}
	if !strings.Contains(string(body2), canary) {
		t.Fatalf("canary did not round-trip through the upstream; response: %s", body2)
	}
	t.Logf("F9 round-trip OK: canary %q returned via upstream echo", canary)
}
