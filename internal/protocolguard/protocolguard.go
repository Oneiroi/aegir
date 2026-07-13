// Package protocolguard enforces JSON-RPC 2.0 schema and replay protection.
package protocolguard

import (
	"encoding/json"
	"fmt"
	"sync"
	"time"
)

// validTopLevelFields is the complete set of allowed JSON-RPC 2.0 fields.
var validTopLevelFields = map[string]bool{
	"jsonrpc": true,
	"id":      true,
	"method":  true,
	"params":  true,
	"result":  true,
	"error":   true,
}

// jsonRPCError is the standard JSON-RPC 2.0 error object.
type jsonRPCError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// jsonRPCErrorResponse is a well-formed JSON-RPC 2.0 error response.
type jsonRPCErrorResponse struct {
	Jsonrpc string       `json:"jsonrpc"`
	ID      interface{}  `json:"id"`
	Error   jsonRPCError `json:"error"`
}

// buildErrorResponse constructs a well-formed JSON-RPC 2.0 error response.
func buildErrorResponse(id interface{}, code int, msg string) []byte {
	resp := jsonRPCErrorResponse{
		Jsonrpc: "2.0",
		ID:      id,
		Error: jsonRPCError{
			Code:    code,
			Message: msg,
		},
	}
	b, _ := json.Marshal(resp)
	return b
}

// Validate checks rawMsg against JSON-RPC 2.0 schema.
// ISC-110: valid message must have jsonrpc:"2.0"; unknown top-level fields are rejected.
// Returns ok=true when the message is structurally valid, or ok=false with a JSON-RPC error
// response in errResponse.
func Validate(rawMsg []byte) (ok bool, errResponse []byte) {
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(rawMsg, &doc); err != nil {
		return false, buildErrorResponse(nil, -32700, fmt.Sprintf("parse error: %v", err))
	}

	// Extract id for error responses (best effort — may be absent)
	var id interface{}
	if rawID, exists := doc["id"]; exists {
		_ = json.Unmarshal(rawID, &id)
	}

	// Must have jsonrpc field equal to "2.0"
	rawVersion, hasVersion := doc["jsonrpc"]
	if !hasVersion {
		return false, buildErrorResponse(id, -32600, `missing required field "jsonrpc"`)
	}
	var version string
	if err := json.Unmarshal(rawVersion, &version); err != nil || version != "2.0" {
		return false, buildErrorResponse(id, -32600, `"jsonrpc" must be "2.0"`)
	}

	// Check for unknown top-level fields
	var unknown []string
	for k := range doc {
		if !validTopLevelFields[k] {
			unknown = append(unknown, k)
		}
	}
	if len(unknown) > 0 {
		return false, buildErrorResponse(id, -32600, fmt.Sprintf("unknown top-level fields: %v", unknown))
	}

	return true, nil
}

// ValidateWithHeaders checks rawMsg against JSON-RPC 2.0 schema and
// validates consistency between HTTP headers and the JSON-RPC body.
// ISC-166: when Mcp-Method and/or Mcp-Name HTTP headers are present, the gateway
// asserts they equal the JSON-RPC body method and tool name; any mismatch is rejected.
// Returns ok=true when the message is structurally valid and headers match, or ok=false
// with a JSON-RPC error response in errResponse.
func ValidateWithHeaders(rawMsg []byte, methodHeader, nameHeader string) (ok bool, errResponse []byte) {
	// First validate the JSON-RPC structure
	ok, errResponse = Validate(rawMsg)
	if !ok {
		return false, errResponse
	}

	// Parse the message to extract method and params (if any)
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(rawMsg, &doc); err != nil {
		return false, buildErrorResponse(nil, -32700, fmt.Sprintf("parse error: %v", err))
	}

	// Extract method from body
	var methodFromBody string
	if rawMethod, exists := doc["method"]; exists {
		if err := json.Unmarshal(rawMethod, &methodFromBody); err != nil {
			return false, buildErrorResponse(nil, -32600, `"method" must be a string`)
		}
	}

	// Check Mcp-Method header matches body method
	if methodHeader != "" && methodHeader != methodFromBody {
		return false, buildErrorResponse(nil, -32600, fmt.Sprintf("Mcp-Method header (%s) does not match body method (%s)", methodHeader, methodFromBody))
	}

	// Extract tool name from params (tools/call has "name" field)
	var toolName string
	if rawParams, exists := doc["params"]; exists {
		var paramsMap map[string]json.RawMessage
		if err := json.Unmarshal(rawParams, &paramsMap); err == nil {
			if rawName, ok := paramsMap["name"]; ok {
				if err := json.Unmarshal(rawName, &toolName); err != nil {
					return false, buildErrorResponse(nil, -32600, `"params.name" must be a string`)
				}
			}
		}
	}

	// Check Mcp-Name header matches tool name (for tools/call)
	if nameHeader != "" && nameHeader != toolName {
		return false, buildErrorResponse(nil, -32600, fmt.Sprintf("Mcp-Name header (%s) does not match tool name (%s)", nameHeader, toolName))
	}

	return true, nil
}

// replayEntry records when a message ID was first seen.
type replayEntry struct {
	seenAt time.Time
}

// ReplayCache is a session-scoped replay-detection store.
type ReplayCache struct {
	mu      sync.Mutex
	ttl     time.Duration
	entries map[string]map[string]replayEntry // sessionID → msgID → entry
}

// NewReplayCache creates a ReplayCache with the given TTL (default 60s if zero).
func NewReplayCache(ttl time.Duration) *ReplayCache {
	if ttl <= 0 {
		ttl = 60 * time.Second
	}
	return &ReplayCache{
		ttl:     ttl,
		entries: make(map[string]map[string]replayEntry),
	}
}

// CheckReplay returns true if the (sessionID, msgID) pair has been seen within TTL.
// ISC-118: registers the message on first call; subsequent calls within TTL return true.
func (rc *ReplayCache) CheckReplay(sessionID, msgID string, ts time.Time) bool {
	rc.mu.Lock()
	defer rc.mu.Unlock()

	rc.evict(sessionID, ts)

	sess, ok := rc.entries[sessionID]
	if !ok {
		sess = make(map[string]replayEntry)
		rc.entries[sessionID] = sess
	}

	entry, seen := sess[msgID]
	if seen && ts.Sub(entry.seenAt) <= rc.ttl {
		return true // replay detected
	}

	// First time — register it
	sess[msgID] = replayEntry{seenAt: ts}
	return false
}

// evict removes TTL-expired entries for the given session.
func (rc *ReplayCache) evict(sessionID string, now time.Time) {
	sess, ok := rc.entries[sessionID]
	if !ok {
		return
	}
	for msgID, entry := range sess {
		if now.Sub(entry.seenAt) > rc.ttl {
			delete(sess, msgID)
		}
	}
}
