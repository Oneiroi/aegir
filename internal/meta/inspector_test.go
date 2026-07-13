package meta

import (
	"encoding/json"
	"testing"
)

// TestMetaUnknownKeysStripped verifies that ISC-167 strips unknown keys from _meta.
func TestMetaUnknownKeysStripped(t *testing.T) {
	// Create inspector with a custom allowlist that includes known_key
	allowedKeys := map[string]bool{
		"trace_id":       true,
		"span_id":        true,
		"correlation_id": true,
		"source":         true,
		"intent":         true,
		"known_key":      true, // Add known_key as allowed
	}
	inspector := NewInspector(allowedKeys, false)

	params := json.RawMessage(`{"_meta":{"known_key":"value","unknown_key":"should_be_stripped"},"other":"data"}`)
	sanitized, allowed := inspector.Inspect(params)

	if !allowed {
		t.Errorf("Expected request to be allowed")
	}

	var paramsMap map[string]interface{}
	if err := json.Unmarshal(sanitized, &paramsMap); err != nil {
		t.Fatalf("Failed to unmarshal sanitized params: %v", err)
	}

	meta, hasMeta := paramsMap["_meta"]
	if !hasMeta {
		t.Fatal("Expected _meta to be present")
	}

	metaMap, ok := meta.(map[string]interface{})
	if !ok {
		t.Fatalf("_meta is not a map: %T", meta)
	}

	// Known key should remain
	if _, hasKnown := metaMap["known_key"]; !hasKnown {
		t.Error("Expected known_key to be present in sanitized _meta")
	}

	// Unknown key should be stripped
	if _, hasUnknown := metaMap["unknown_key"]; hasUnknown {
		t.Error("Expected unknown_key to be stripped from sanitized _meta")
	}
}

// TestMetaUnknownKeysRejected verifies that ISC-167 rejects requests with unknown keys
// when RejectUnknown is true.
func TestMetaUnknownKeysRejected(t *testing.T) {
	inspector := NewInspector(nil, true) // Reject unknown keys

	params := json.RawMessage(`{"_meta":{"known_key":"value","unknown_key":"should_be_rejected"},"other":"data"}`)
	sanitized, allowed := inspector.Inspect(params)

	if allowed {
		t.Errorf("Expected request to be rejected due to unknown key")
	}
	if sanitized != nil {
		t.Errorf("Expected sanitized to be nil when rejecting")
	}
}

// TestMetaTenantCannotEscalate verifies that ISC-168 rejects requests where
// _meta contains authorization-relevant keys like "tenant".
func TestMetaTenantCannotEscalate(t *testing.T) {
	inspector := NewInspector(nil, false)

	params := json.RawMessage(`{"_meta":{"tenant":"admin"},"other":"data"}`)
	allowed := inspector.IsAuthorized(params)

	if allowed {
		t.Errorf("Expected request to be rejected due to tenant key influencing authz")
	}
}

// TestMetaTraceIDAllowed verifies that trace_id is an allowed key.
func TestMetaTraceIDAllowed(t *testing.T) {
	inspector := NewInspector(nil, false)

	params := json.RawMessage(`{"_meta":{"trace_id":"abc123"},"other":"data"}`)
	sanitized, allowed := inspector.Inspect(params)

	if !allowed {
		t.Errorf("Expected request to be allowed")
	}

	var paramsMap map[string]interface{}
	if err := json.Unmarshal(sanitized, &paramsMap); err != nil {
		t.Fatalf("Failed to unmarshal sanitized params: %v", err)
	}

	meta, hasMeta := paramsMap["_meta"]
	if !hasMeta {
		t.Fatal("Expected _meta to be present")
	}

	metaMap, ok := meta.(map[string]interface{})
	if !ok {
		t.Fatalf("_meta is not a map: %T", meta)
	}

	if _, hasTraceID := metaMap["trace_id"]; !hasTraceID {
		t.Error("Expected trace_id to be present in sanitized _meta")
	}

	// Trace ID should not affect authorization
	authAllowed := inspector.IsAuthorized(params)
	if !authAllowed {
		t.Error("Expected request with trace_id to be authorized")
	}
}

// TestNoMetaAllowed verifies that requests without _meta are allowed.
func TestNoMetaAllowed(t *testing.T) {
	inspector := NewInspector(nil, false)

	params := json.RawMessage(`{"other":"data"}`)
	_, allowed := inspector.Inspect(params)

	if !allowed {
		t.Errorf("Expected request without _meta to be allowed")
	}

	authAllowed := inspector.IsAuthorized(params)
	if !authAllowed {
		t.Errorf("Expected request without _meta to be authorized")
	}
}

// TestEmptyMetaAllowed verifies that empty _meta is allowed.
func TestEmptyMetaAllowed(t *testing.T) {
	inspector := NewInspector(nil, false)

	params := json.RawMessage(`{"_meta":{}}`)
	_, allowed := inspector.Inspect(params)

	if !allowed {
		t.Errorf("Expected request with empty _meta to be allowed")
	}
}

// TestMultipleProhibitedKeys verifies that multiple authorization-relevant keys
// are detected and rejected by IsAuthorized.
func TestMultipleProhibitedKeys(t *testing.T) {
	inspector := NewInspector(nil, false)

	// Test each prohibited key individually
	prohibitedKeys := []string{"tenant", "role", "permission", "scope", "permissions", "groups", "teams"}

	for _, key := range prohibitedKeys {
		params := json.RawMessage(`{"_meta":{"` + key + `":"value"}}`)
		allowed := inspector.IsAuthorized(params)

		if allowed {
			t.Errorf("Expected request with _meta.%s to be rejected by IsAuthorized", key)
		}
	}
}
