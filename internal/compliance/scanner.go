// Package compliance implements response content security scanning for the Aegir MCP gateway.
//
// ISC-114: ACE (Arbitrary Code Execution) pattern detection
// ISC-117: Resource Content Poisoning (prompt injection in responses)
// ISC-123: Content-length anomaly detection
package compliance

import (
	"context"
	"regexp"
)

const defaultMaxBodyBytes = 1 * 1024 * 1024 // 1 MB

// Config holds tunable parameters for the ResponseScanner.
type Config struct {
	// MaxBodyBytes is the response body size threshold above which
	// a large_response_anomaly event is emitted. Defaults to 1 MB when zero.
	MaxBodyBytes int64

	// HoldOnLargeResponse makes the scanner mark the result as blocked
	// when the body exceeds MaxBodyBytes (policy: hold). Default is alert-only.
	HoldOnLargeResponse bool
}

// ScanEvent is emitted by the scanner when a security concern is detected.
type ScanEvent struct {
	// Type is one of: "ace_pattern_detected", "resource_content_poisoning",
	// "large_response_anomaly".
	Type string

	// ToolName is the MCP tool that produced the response body.
	ToolName string

	// SessionID identifies the MCP session.
	SessionID string

	// ByteCount is populated only for large_response_anomaly events.
	ByteCount int64

	// Pattern is the matching pattern string (ACE / poisoning events).
	Pattern string
}

// ScanResult summarises what the scanner found in one body.
type ScanResult struct {
	ToolName    string
	SessionID   string
	ByteCount   int64

	ACEDetected              bool
	ContentPoisoningDetected bool
	LargeResponseDetected    bool

	// Blocked is true when policy is "hold" and an anomaly was found.
	Blocked bool

	ACEMatches      []string
	PoisonMatches   []string
}

// EventSink is called synchronously for each detected event.
// A nil sink is safe — events are silently dropped.
type EventSink func(ScanEvent)

// acePatterns covers CWE-77/78/94/95 shell metacharacter and code-execution calls.
// All patterns are pre-compiled at construction time.
var acePatterns = []*regexp.Regexp{
	// Shell command substitution: `...` and $(...)
	regexp.MustCompile("`[^`]+`"),
	regexp.MustCompile(`\$\([^)]+\)`),
	// eval / exec / system / passthru / shell_exec followed by ( — language-agnostic
	regexp.MustCompile(`(?i)\beval\s*\(`),
	regexp.MustCompile(`(?i)\bexec\s*\(`),
	regexp.MustCompile(`(?i)\bsystem\s*\(`),
	regexp.MustCompile(`(?i)\bpassthru\s*\(`),
	regexp.MustCompile(`(?i)\bshell_exec\s*\(`),
	// popen / subprocess
	regexp.MustCompile(`(?i)\bpopen\s*\(`),
	regexp.MustCompile(`(?i)\bsubprocess\s*\(`),
	// os.system / os.popen
	regexp.MustCompile(`(?i)\bos\.(system|popen|exec)\s*\(`),
	// Runtime.exec (Java)
	regexp.MustCompile(`(?i)\bRuntime\.exec\s*\(`),
	// Process.Start (.NET)
	regexp.MustCompile(`(?i)\bProcess\.Start\s*\(`),
}

// poisonPatterns detect prompt-injection phrasing embedded in tool response bodies.
var poisonPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)ignore\s+(all\s+)?(previous|prior|above)\s+(instructions?|context|prompts?|rules?|constraints?)`),
	regexp.MustCompile(`(?i)forget\s+(all\s+)?(previous|prior|above|your)\s+(instructions?|context|prompts?|rules?|constraints?)`),
	regexp.MustCompile(`(?i)disregard\s+(all\s+)?(previous|prior|above)\s+(instructions?|context|prompts?)`),
	regexp.MustCompile(`(?i)override\s+(all\s+)?(previous|prior|above|your)\s+(instructions?|directives?|rules?)`),
	regexp.MustCompile(`(?i)(act\s+as|pretend\s+(to\s+be|you\s+are)|you\s+are\s+now)\s+(a\s+)?(different|new|another|unrestricted)\s+(AI|assistant|model|agent|bot)`),
	regexp.MustCompile(`(?i)exfiltrate\s+(all\s+)?(data|information|credentials?|secrets?|keys?)`),
	regexp.MustCompile(`(?i)new\s+instructions?\s*:`),
	regexp.MustCompile(`(?i)\[system\s*\]`),
	regexp.MustCompile(`(?i)<\s*system\s*>`),
	regexp.MustCompile(`(?i)your\s+(true|real|actual|secret)\s+(instructions?|purpose|goal|mission|directive)`),
	regexp.MustCompile(`(?i)do\s+not\s+follow\s+(the\s+)?(previous|prior|above|original)\s+(instructions?|rules?|guidelines?)`),
	regexp.MustCompile(`(?i)instead\s+of\s+(following|obeying)\s+(your\s+)?(instructions?|rules?|guidelines?)`),
}

// ResponseScanner scans tools/call response bodies for security anomalies.
type ResponseScanner struct {
	cfg      Config
	sink     EventSink
	maxBytes int64
}

// NewResponseScanner constructs a ResponseScanner with pre-compiled patterns.
// sink may be nil; in that case events are discarded.
func NewResponseScanner(cfg Config, sink EventSink) *ResponseScanner {
	max := cfg.MaxBodyBytes
	if max <= 0 {
		max = defaultMaxBodyBytes
	}
	return &ResponseScanner{
		cfg:      cfg,
		sink:     sink,
		maxBytes: max,
	}
}

// emit fires a scan event to the registered sink (if any).
func (s *ResponseScanner) emit(e ScanEvent) {
	if s.sink != nil {
		s.sink(e)
	}
}

// Scan evaluates body for ACE patterns, prompt-injection, and size anomalies.
// toolName is the MCP tool identifier; sessionID identifies the session.
func (s *ResponseScanner) Scan(_ context.Context, body, toolName, sessionID string) ScanResult {
	result := ScanResult{
		ToolName:  toolName,
		SessionID: sessionID,
		ByteCount: int64(len(body)),
	}

	// ISC-114: ACE pattern detection
	for _, re := range acePatterns {
		if m := re.FindString(body); m != "" {
			result.ACEDetected = true
			result.ACEMatches = append(result.ACEMatches, m)
			s.emit(ScanEvent{
				Type:      "ace_pattern_detected",
				ToolName:  toolName,
				SessionID: sessionID,
				Pattern:   m,
			})
			// Emit once per unique match but continue scanning all patterns.
		}
	}

	// ISC-117: Resource Content Poisoning
	for _, re := range poisonPatterns {
		if m := re.FindString(body); m != "" {
			result.ContentPoisoningDetected = true
			result.PoisonMatches = append(result.PoisonMatches, m)
			s.emit(ScanEvent{
				Type:      "resource_content_poisoning",
				ToolName:  toolName,
				SessionID: sessionID,
				Pattern:   m,
			})
		}
	}

	// ISC-123: Content-length anomaly
	if result.ByteCount > s.maxBytes {
		result.LargeResponseDetected = true
		if s.cfg.HoldOnLargeResponse {
			result.Blocked = true
		}
		s.emit(ScanEvent{
			Type:      "large_response_anomaly",
			ToolName:  toolName,
			SessionID: sessionID,
			ByteCount: result.ByteCount,
		})
	}

	return result
}
