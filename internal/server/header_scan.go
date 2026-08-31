package server

import (
	"net/http"
	"strings"
)

// headerScanSkipList covers headers that legitimately carry high-entropy or
// credential-shaped values on every request/response by design (bearer tokens,
// cookies, protocol plumbing). Scanning them for "secrets" would false-positive
// on every authenticated call. ISC-169/170 targets *accidental* leakage via
// non-standard/application headers (x-mcp-header, custom debug headers, ...),
// not the transport's own auth channel.
var headerScanSkipList = map[string]bool{
	"authorization":   true,
	"cookie":          true,
	"set-cookie":      true,
	"content-type":    true,
	"content-length":  true,
	"host":            true,
	"user-agent":      true,
	"accept":          true,
	"accept-encoding": true,
	"accept-language": true,
	"connection":      true,
	// referer (F9, bundle 6): standard browser header that legitimately
	// carries a URL on every navigation. It is not a secret channel, so
	// scanning it false-positives on the URL's credential-shaped substrings.
	"referer":    true,
	"mcp-method": true, // handled by the ISC-166 desync guard
	"mcp-name":   true,
	// x-session-id (N4, bundle 6): protocol identifier header. It carries a
	// client-chosen session ID that has its own sanitization path
	// (sanitizeSessionID: length clamp + control-char strip) and is never
	// forwarded upstream (upstream/manager.go sets only Content-Type and
	// User-Agent). Secret-scanning it false-positives on JWT-shaped session
	// IDs (the jwt_header pattern) and blocks legitimate clients.
	"x-session-id": true,
}

// xMCPHeaderPrefix matches the MCP 2026-07-28 `x-mcp-header` directive: clients/
// servers map sensitive inputs into headers named with this prefix (ISC-170).
const xMCPHeaderPrefix = "x-mcp-header"

// severityRank orders detector severities so the highest found across a value's
// secret + PII/PHI/PCI detections can be selected. Absent from the map (empty
// string, "clean") ranks lowest.
var severityRank = map[string]int{"": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

func higherSeverity(a, b string) string {
	if severityRank[b] > severityRank[a] {
		return b
	}
	return a
}

// headerFinding describes one header value that tripped a secret/PII detector.
type headerFinding struct {
	HeaderName    string
	Severity      string
	ViaXMCPHeader bool
}

// scanHeaders runs the existing secret detector (sanitizer.Manager) and the
// PII/PHI/PCI detector (sanitizer.ComplianceManager) over each header value
// (ISC-169), flagging any x-mcp-header-named header distinctly regardless of
// severity (ISC-170). direction is "request" or "response", used only for
// logging. Skip-listed headers (auth/cookie/protocol plumbing) are never scanned.
func (p *MCPProxy) scanHeaders(headers http.Header, direction string) []headerFinding {
	var findings []headerFinding
	for name, values := range headers {
		lower := strings.ToLower(name)
		if headerScanSkipList[lower] {
			continue
		}
		viaXMCPHeader := strings.HasPrefix(lower, xMCPHeaderPrefix)
		for _, value := range values {
			if value == "" {
				continue
			}
			severity := p.detectSecretOrPIISeverity(value)
			if severity == "" && !viaXMCPHeader {
				continue
			}
			findings = append(findings, headerFinding{
				HeaderName:    name,
				Severity:      severity,
				ViaXMCPHeader: viaXMCPHeader,
			})
			p.logger.Warn("Credential-shaped value detected in HTTP header",
				"direction", direction,
				"header", name,
				"severity", severity,
				"via_x_mcp_header", viaXMCPHeader)
		}
	}
	return findings
}

// detectSecretOrPIISeverity runs the sanitizer secret detector and the
// compliance PII/PHI/PCI detector over a single header value and returns the
// highest severity found, or "" if the value is clean.
func (p *MCPProxy) detectSecretOrPIISeverity(value string) string {
	highest := ""
	if p.sanitizer != nil {
		sanitized := p.sanitizer.SanitizeContent(value)
		for _, d := range sanitized.Detections {
			highest = higherSeverity(highest, d.Severity)
		}
	}
	if p.complianceManager != nil {
		comp := p.complianceManager.ScanForCompliance(value)
		for _, v := range comp.Violations {
			highest = higherSeverity(highest, v.Severity)
		}
	}
	return highest
}

// headersBlocked reports whether any finding is severe enough to reject the
// request/response: any x-mcp-header-flagged credential (ISC-170, regardless
// of the detector's own severity ranking — the directive itself is the signal),
// or any critical/high severity finding elsewhere (ISC-169).
func headersBlocked(findings []headerFinding) bool {
	for _, f := range findings {
		if f.ViaXMCPHeader || f.Severity == "critical" || f.Severity == "high" {
			return true
		}
	}
	return false
}
