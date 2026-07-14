package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

// startToolsCallAndGetTaskToken drives a tools/call through the real HTTP
// entry point and returns the signed task token issued via the
// X-Aegir-Task-Token response header (set in the V6 task-registration block).
func startToolsCallAndGetTaskToken(t *testing.T, ts *httptest.Server, id string) string {
	t.Helper()
	body, _ := json.Marshal(MCPRequest{
		Method: "tools/call",
		Params: map[string]interface{}{"name": "test"},
		ID:     id,
	})
	resp, err := http.Post(ts.URL+"/mcp", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("tools/call request failed: %v", err)
	}
	resp.Body.Close()
	token := resp.Header.Get("X-Aegir-Task-Token")
	if token == "" {
		t.Fatalf("expected an X-Aegir-Task-Token header on the tools/call response")
	}
	return token
}

func taskStatusRequest(t *testing.T, ts *httptest.Server, token string) *http.Response {
	t.Helper()
	body, _ := json.Marshal(MCPRequest{
		Method: "tasks/status",
		Params: map[string]interface{}{"task_token": token},
		ID:     "status-1",
	})
	resp, err := http.Post(ts.URL+"/mcp", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("tasks/status request failed: %v", err)
	}
	return resp
}

// TestUnsignedResumeStateRejected verifies ISC-175 end-to-end: a client that
// supplies its own unsigned/garbage task token to tasks/status is rejected,
// never resumed.
func TestUnsignedResumeStateRejected(t *testing.T) {
	gin.SetMode(gin.TestMode)
	proxy := createTestMCPProxy(t)
	router := gin.New()
	router.POST("/mcp", proxy.HandleMCPRequest)
	ts := httptest.NewServer(router)
	defer ts.Close()

	resp := taskStatusRequest(t, ts, "attacker-guessed-task-id-no-signature")
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 for an unsigned task token, got %d", resp.StatusCode)
	}
}

// TestTamperedTaskIdRejected verifies ISC-175 end-to-end: a legitimately
// issued token whose payload segment has been altered (forged task_id) fails
// verification and is rejected.
func TestTamperedTaskIdRejected(t *testing.T) {
	gin.SetMode(gin.TestMode)
	proxy := createTestMCPProxy(t)
	router := gin.New()
	router.POST("/mcp", proxy.HandleMCPRequest)
	ts := httptest.NewServer(router)
	defer ts.Close()

	token := startToolsCallAndGetTaskToken(t, ts, "task-req-1")
	tampered := token[:len(token)-1] + "X"

	resp := taskStatusRequest(t, ts, tampered)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 for a tampered task token, got %d", resp.StatusCode)
	}
}

// TestCrossTenantResumeDenied verifies ISC-176 end-to-end: a task token
// legitimately issued to one identity cannot be redeemed by tasks/status
// requests from a different identity, even though the signature is valid.
func TestCrossTenantResumeDenied(t *testing.T) {
	gin.SetMode(gin.TestMode)
	proxy := createTestMCPProxy(t)
	router := gin.New()
	// Middleware assigns identity from a test-only header so the two calls
	// below can simulate two different authenticated identities.
	router.Use(func(c *gin.Context) {
		if uid := c.GetHeader("X-Test-User-Id"); uid != "" {
			c.Set("user_id", uid)
		}
		c.Next()
	})
	router.POST("/mcp", proxy.HandleMCPRequest)
	ts := httptest.NewServer(router)
	defer ts.Close()

	// Identity "alice" starts a task and receives a token bound to her.
	body, _ := json.Marshal(MCPRequest{
		Method: "tools/call",
		Params: map[string]interface{}{"name": "test"},
		ID:     "alice-task-1",
	})
	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/mcp", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Test-User-Id", "alice")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("alice's tools/call failed: %v", err)
	}
	token := resp.Header.Get("X-Aegir-Task-Token")
	resp.Body.Close()
	if token == "" {
		t.Fatalf("expected alice's tools/call to return a task token")
	}

	// Identity "bob" tries to redeem alice's token.
	statusBody, _ := json.Marshal(MCPRequest{
		Method: "tasks/status",
		Params: map[string]interface{}{"task_token": token},
		ID:     "bob-status-1",
	})
	statusReq, _ := http.NewRequest(http.MethodPost, ts.URL+"/mcp", bytes.NewReader(statusBody))
	statusReq.Header.Set("Content-Type", "application/json")
	statusReq.Header.Set("X-Test-User-Id", "bob")
	statusResp, err := http.DefaultClient.Do(statusReq)
	if err != nil {
		t.Fatalf("bob's tasks/status request failed: %v", err)
	}
	defer statusResp.Body.Close()

	if statusResp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected bob to be denied alice's task token with 403, got %d", statusResp.StatusCode)
	}

	// Alice redeeming her own token must still succeed.
	aliceStatusReq, _ := http.NewRequest(http.MethodPost, ts.URL+"/mcp", bytes.NewReader(statusBody))
	aliceStatusReq.Header.Set("Content-Type", "application/json")
	aliceStatusReq.Header.Set("X-Test-User-Id", "alice")
	aliceResp, err := http.DefaultClient.Do(aliceStatusReq)
	if err != nil {
		t.Fatalf("alice's tasks/status request failed: %v", err)
	}
	defer aliceResp.Body.Close()
	if aliceResp.StatusCode != http.StatusOK {
		t.Errorf("expected alice to redeem her own task token with 200, got %d", aliceResp.StatusCode)
	}
}
