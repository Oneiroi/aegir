package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/aegishjalmur/aegir/internal/session"
	"github.com/gin-gonic/gin"
)

// TestEraseUserData_GDPRErasure is the ISC-64 probe: the GDPR right-to-erasure
// endpoint DELETE /api/user/:id/data exists and actually erases the user's
// session state, returning 200 with erased=true.
func TestEraseUserData_GDPRErasure(t *testing.T) {
	gin.SetMode(gin.TestMode)

	analyzer := session.NewConversationalThreatAnalyzer(session.AnalyzerConfig{
		MaxSessionAge:   time.Hour,
		MaxHistorySize:  16,
		CleanupInterval: time.Hour,
	}, testLogger())

	const userID = "user-42"
	// Seed a session keyed on the user id (the erase handler deletes by :id).
	analyzer.AnalyzeMessage(userID, userID, "hello world")
	if got := analyzer.GetSessionStats()["active_sessions"].(int); got != 1 {
		t.Fatalf("precondition: expected 1 active session, got %d", got)
	}

	s := &MCPFirewall{logger: testLogger(), sessionAnalyzer: analyzer}

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodDelete, "/api/user/"+userID+"/data", nil)
	c.Params = gin.Params{{Key: "id", Value: userID}}

	s.eraseUserData(c)

	if w.Code != http.StatusOK {
		t.Fatalf("status: got %d want 200; body=%s", w.Code, w.Body.String())
	}
	var body struct {
		Status string `json:"status"`
		UserID string `json:"user_id"`
		Erased bool   `json:"erased"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if !body.Erased || body.UserID != userID {
		t.Errorf("unexpected body: %+v", body)
	}
	if got := analyzer.GetSessionStats()["active_sessions"].(int); got != 0 {
		t.Errorf("session not erased: %d active sessions remain", got)
	}
}

// TestEraseUserData_MissingID covers the defensive empty-id guard.
func TestEraseUserData_MissingID(t *testing.T) {
	gin.SetMode(gin.TestMode)
	s := &MCPFirewall{logger: testLogger()}

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodDelete, "/api/user//data", nil)
	c.Params = gin.Params{{Key: "id", Value: ""}}

	s.eraseUserData(c)

	if w.Code != http.StatusBadRequest {
		t.Errorf("empty id: got %d want 400", w.Code)
	}
}
