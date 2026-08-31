// Package meta provides _meta object validation and sanitization for MCP requests.
// ISC-167/168: Inspects inbound params._meta, key-allowlists unknown keys, and ensures
// no _meta value influences routing or authorization decisions.
package meta

import (
	"encoding/json"
)

// Inspector validates and sanitizes the _meta object in MCP requests.
type Inspector struct {
	// AllowedKeys is the set of _meta keys that are permitted.
	// Unknown keys are stripped if this is nil, or the request is rejected.
	AllowedKeys map[string]bool
	// RejectUnknown controls whether unknown keys cause rejection (true) or stripping (false).
	RejectUnknown bool
	// Bypass disables inspection entirely: params pass through unmodified.
	// Set when security.meta_inspection.enabled is false (F7, bundle 6).
	Bypass bool
}

// NewInspector creates a new Inspector with the given configuration.
func NewInspector(allowedKeys map[string]bool, rejectUnknown bool) *Inspector {
	if allowedKeys == nil {
		// Default allowlist: observability keys plus the MCP spec's own
		// _meta keys (F7, bundle 6). progressToken (2025-03-26) and
		// requestState (2025-06-18) are spec-conformant and must not be
		// silently stripped from spec clients.
		allowedKeys = map[string]bool{
			"trace_id":       true,
			"span_id":        true,
			"correlation_id": true,
			"source":         true,
			"intent":         true,
			"progressToken":  true,
			"requestState":   true,
		}
	}
	return &Inspector{
		AllowedKeys:   allowedKeys,
		RejectUnknown: rejectUnknown,
	}
}

// Inspect validates and sanitizes the _meta object from params.
// Returns the sanitized _meta (with unknown keys removed or nil if rejected),
// and a boolean indicating if the request should be allowed.
func (i *Inspector) Inspect(params json.RawMessage) (json.RawMessage, bool) {
	if i.Bypass {
		return params, true // control disabled: identity, never reject
	}
	if len(params) == 0 {
		return nil, true // No params, allow
	}

	var paramsMap map[string]json.RawMessage
	if err := json.Unmarshal(params, &paramsMap); err != nil {
		return nil, true // Invalid params, allow upstream to handle
	}

	// Extract _meta if present
	rawMeta, hasMeta := paramsMap["_meta"]
	if !hasMeta {
		return nil, true // No _meta, allow
	}

	var metaMap map[string]interface{}
	if err := json.Unmarshal(rawMeta, &metaMap); err != nil {
		return nil, true // Invalid _meta, allow upstream to handle
	}

	// Create sanitized _meta with only allowed keys
	sanitizedMeta := make(map[string]interface{})
	for key, value := range metaMap {
		// Check if key is allowed
		if i.AllowedKeys != nil && !i.AllowedKeys[key] {
			if i.RejectUnknown {
				// Reject request with unknown key
				return nil, false
			}
			// Strip unknown key - skip it
			continue
		}
		sanitizedMeta[key] = value
	}

	// Re-marshal sanitized _meta
	if len(sanitizedMeta) == 0 {
		// No valid _meta keys remain - remove from params
		delete(paramsMap, "_meta")
	} else {
		// Update _meta with sanitized version
		sanitizedJSON, _ := json.Marshal(sanitizedMeta)
		paramsMap["_meta"] = sanitizedJSON
	}

	// Re-marshal params with sanitized _meta
	resultJSON, _ := json.Marshal(paramsMap)
	return resultJSON, true
}

// IsAuthorized checks if the _meta object would influence authorization.
// Returns true if _meta contains no authorization-relevant keys.
func (i *Inspector) IsAuthorized(params json.RawMessage) bool {
	if len(params) == 0 {
		return true
	}

	var paramsMap map[string]json.RawMessage
	if err := json.Unmarshal(params, &paramsMap); err != nil {
		return true // Invalid params, allow
	}

	rawMeta, hasMeta := paramsMap["_meta"]
	if !hasMeta {
		return true // No _meta
	}

	var metaMap map[string]interface{}
	if err := json.Unmarshal(rawMeta, &metaMap); err != nil {
		return true // Invalid _meta
	}

	// Keys that should never influence authorization
	prohibitedAuthKeys := map[string]bool{
		"tenant":      true,
		"role":        true,
		"permission":  true,
		"scope":       true,
		"permissions": true,
		"groups":      true,
		"teams":       true,
	}

	for key := range metaMap {
		if prohibitedAuthKeys[key] {
			return false // Found a prohibited key
		}
	}

	return true
}
