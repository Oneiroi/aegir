package server

import (
	"testing"
)

// TestCapabilityMerge is the ISC-76 probe: tools/list response must contain
// Aegir's built-in security tools prepended before upstream tools.
func TestCapabilityMerge(t *testing.T) {
	proxy := createTestMCPProxy(t)

	upstream := &MCPResponse{
		Result: map[string]interface{}{
			"tools": []interface{}{
				map[string]interface{}{"name": "upstream_tool_A", "description": "An upstream tool"},
				map[string]interface{}{"name": "upstream_tool_B", "description": "Another upstream tool"},
			},
		},
	}
	req := &MCPRequest{Method: "tools/list", ID: "merge-test"}

	merged := proxy.mergeToolsList(upstream, req)

	resultMap, ok := merged.Result.(map[string]interface{})
	if !ok {
		t.Fatal("ISC-76: merged result is not a map")
	}
	tools, ok := resultMap["tools"].([]interface{})
	if !ok {
		t.Fatal("ISC-76: merged tools is not a slice")
	}

	builtinCount := len(proxy.builtinTools())
	if len(tools) != builtinCount+2 {
		t.Errorf("ISC-76: expected %d tools (builtin=%d + 2 upstream), got %d",
			builtinCount+2, builtinCount, len(tools))
	}

	// Aegir built-ins must come first.
	for i, bt := range proxy.builtinTools() {
		bm, _ := bt.(map[string]interface{})
		tm, _ := tools[i].(map[string]interface{})
		if bm == nil || tm == nil {
			t.Errorf("ISC-76: built-in tool at index %d is not a map", i)
			continue
		}
		if bm["name"] != tm["name"] {
			t.Errorf("ISC-76: built-in tool[%d] name = %q, want %q", i, tm["name"], bm["name"])
		}
	}

	// Upstream tools must follow.
	upstreamNames := []string{"upstream_tool_A", "upstream_tool_B"}
	for j, want := range upstreamNames {
		idx := builtinCount + j
		tm, _ := tools[idx].(map[string]interface{})
		if tm == nil {
			t.Errorf("ISC-76: upstream tool[%d] is not a map", idx)
			continue
		}
		if tm["name"] != want {
			t.Errorf("ISC-76: upstream tool[%d] = %q, want %q", idx, tm["name"], want)
		}
	}
}

// TestCapabilityMerge_NilUpstream verifies that mergeToolsList on a nil upstream
// response returns only Aegir's built-in tools without panicking.
func TestCapabilityMerge_NilUpstream(t *testing.T) {
	proxy := createTestMCPProxy(t)
	req := &MCPRequest{Method: "tools/list", ID: "nil-test"}

	merged := proxy.mergeToolsList(nil, req)

	resultMap, ok := merged.Result.(map[string]interface{})
	if !ok {
		t.Fatal("ISC-76: nil-upstream result is not a map")
	}
	tools, ok := resultMap["tools"].([]interface{})
	if !ok {
		t.Fatal("ISC-76: nil-upstream tools is not a slice")
	}
	if len(tools) != len(proxy.builtinTools()) {
		t.Errorf("ISC-76: nil upstream: got %d tools, want %d built-in", len(tools), len(proxy.builtinTools()))
	}
}
