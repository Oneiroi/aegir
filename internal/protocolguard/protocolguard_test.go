package protocolguard_test

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/aegishjalmur/aegir/internal/protocolguard"
)

// ISC-110 — JSON-RPC 2.0 schema validation

func TestISC110_ValidRequest(t *testing.T) {
	msg := []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}`)
	ok, errResp := protocolguard.Validate(msg)
	if !ok {
		t.Errorf("ISC-110: valid request rejected: %s", errResp)
	}
	if errResp != nil {
		t.Errorf("ISC-110: errResponse should be nil for valid message")
	}
}

func TestISC110_ValidResponse(t *testing.T) {
	msg := []byte(`{"jsonrpc":"2.0","id":1,"result":{"tools":[]}}`)
	ok, errResp := protocolguard.Validate(msg)
	if !ok {
		t.Errorf("ISC-110: valid response rejected: %s", errResp)
	}
}

func TestISC110_ValidNotification(t *testing.T) {
	// Notification has no id
	msg := []byte(`{"jsonrpc":"2.0","method":"notify/update","params":{}}`)
	ok, errResp := protocolguard.Validate(msg)
	if !ok {
		t.Errorf("ISC-110: valid notification rejected: %s", errResp)
	}
}

func TestISC110_MissingJsonrpc(t *testing.T) {
	msg := []byte(`{"id":1,"method":"test"}`)
	ok, errResp := protocolguard.Validate(msg)
	if ok {
		t.Error("ISC-110: message missing jsonrpc should be rejected")
	}
	if errResp == nil {
		t.Fatal("ISC-110: errResponse must not be nil on rejection")
	}
	validateErrorResponse(t, errResp)
}

func TestISC110_WrongJsonrpcVersion(t *testing.T) {
	msg := []byte(`{"jsonrpc":"1.0","id":1,"method":"test"}`)
	ok, errResp := protocolguard.Validate(msg)
	if ok {
		t.Error("ISC-110: jsonrpc 1.0 should be rejected")
	}
	validateErrorResponse(t, errResp)
}

func TestISC110_UnknownTopLevelField(t *testing.T) {
	msg := []byte(`{"jsonrpc":"2.0","id":1,"method":"test","extraField":"evil"}`)
	ok, errResp := protocolguard.Validate(msg)
	if ok {
		t.Error("ISC-110: unknown top-level field should be rejected")
	}
	validateErrorResponse(t, errResp)
}

func TestISC110_MultipleUnknownFields(t *testing.T) {
	msg := []byte(`{"jsonrpc":"2.0","id":1,"method":"test","x":1,"y":2}`)
	ok, errResp := protocolguard.Validate(msg)
	if ok {
		t.Error("ISC-110: multiple unknown fields should be rejected")
	}
	validateErrorResponse(t, errResp)
}

func TestISC110_MalformedJSON(t *testing.T) {
	msg := []byte(`{not valid json}`)
	ok, errResp := protocolguard.Validate(msg)
	if ok {
		t.Error("ISC-110: malformed JSON should be rejected")
	}
	if errResp == nil {
		t.Fatal("ISC-110: errResponse must not be nil on parse error")
	}
	validateErrorResponse(t, errResp)
}

func TestISC110_ErrorResponseIsWellFormed(t *testing.T) {
	msg := []byte(`{"jsonrpc":"2.0","id":42,"method":"test","injected":"value"}`)
	_, errResp := protocolguard.Validate(msg)
	if errResp == nil {
		t.Fatal("expected error response")
	}
	var resp map[string]interface{}
	if err := json.Unmarshal(errResp, &resp); err != nil {
		t.Fatalf("error response is not valid JSON: %v", err)
	}
	if resp["jsonrpc"] != "2.0" {
		t.Errorf("error response jsonrpc field should be 2.0, got %v", resp["jsonrpc"])
	}
	if _, ok := resp["error"]; !ok {
		t.Error("error response must have error field")
	}
}

// ISC-118 — replay protection

func TestISC118_FirstCallNotReplay(t *testing.T) {
	rc := protocolguard.NewReplayCache(0)
	now := time.Now()
	if rc.CheckReplay("sess1", "msg1", now) {
		t.Error("ISC-118: first call should not be detected as replay")
	}
}

func TestISC118_SecondCallWithinTTLIsReplay(t *testing.T) {
	rc := protocolguard.NewReplayCache(60 * time.Second)
	now := time.Now()
	rc.CheckReplay("sess1", "msg1", now)
	if !rc.CheckReplay("sess1", "msg1", now.Add(10*time.Second)) {
		t.Error("ISC-118: second call within TTL should be replay")
	}
}

func TestISC118_AfterTTLExpiryNotReplay(t *testing.T) {
	rc := protocolguard.NewReplayCache(5 * time.Second)
	now := time.Now()
	rc.CheckReplay("sess1", "msg2", now)
	// 10 seconds later — past 5s TTL
	if rc.CheckReplay("sess1", "msg2", now.Add(10*time.Second)) {
		t.Error("ISC-118: call after TTL expiry should not be replay")
	}
}

func TestISC118_DifferentSessionsAreIndependent(t *testing.T) {
	rc := protocolguard.NewReplayCache(60 * time.Second)
	now := time.Now()
	rc.CheckReplay("sess_a", "msg1", now)
	// Same msgID, different session — not a replay
	if rc.CheckReplay("sess_b", "msg1", now) {
		t.Error("ISC-118: different sessions should be independent")
	}
}

func TestISC118_DifferentMsgIDsSameSession(t *testing.T) {
	rc := protocolguard.NewReplayCache(60 * time.Second)
	now := time.Now()
	rc.CheckReplay("sess1", "msg1", now)
	if rc.CheckReplay("sess1", "msg2", now) {
		t.Error("ISC-118: different message IDs in same session should not be replay")
	}
}

func TestISC118_DefaultTTL(t *testing.T) {
	// Zero TTL → defaults to 60s
	rc := protocolguard.NewReplayCache(0)
	now := time.Now()
	rc.CheckReplay("s", "m", now)
	// Within 30 seconds — should still be replay
	if !rc.CheckReplay("s", "m", now.Add(30*time.Second)) {
		t.Error("ISC-118: with default 60s TTL, call at 30s should still be replay")
	}
}

// validateErrorResponse checks that the given bytes are a well-formed JSON-RPC 2.0 error response.
func validateErrorResponse(t *testing.T, errResp []byte) {
	t.Helper()
	var resp map[string]interface{}
	if err := json.Unmarshal(errResp, &resp); err != nil {
		t.Fatalf("error response is not valid JSON: %v", err)
	}
	if resp["jsonrpc"] != "2.0" {
		t.Errorf("error response must have jsonrpc:2.0, got %v", resp["jsonrpc"])
	}
	if _, ok := resp["error"]; !ok {
		t.Errorf("error response must have error field")
	}
}
