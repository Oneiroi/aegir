// Package toolmeta scans MCP tool metadata for injection, shadowing, drift, and secret leakage.
package toolmeta

import (
	"crypto/sha256"
	"fmt"
	"regexp"
	"strings"
	"time"
)

// Tool represents an MCP tool with name, description, and version.
type Tool struct {
	Name        string
	Description string
	Version     string
}

// Event is a security finding produced by the Scanner.
type Event struct {
	Type      string
	Severity  string
	Message   string
	ToolName  string
	Details   map[string]string
	Timestamp time.Time
}

// injection patterns — ISC-105
var injectionPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)ignore\s+all\s+previous\s+instructions`),
	regexp.MustCompile(`(?i)override\s+(system|all|previous)`),
	regexp.MustCompile(`(?i)act\s+as\s+(a\s+)?`),
	regexp.MustCompile(`(?i)you\s+are\s+now\s+`),
	regexp.MustCompile(`(?i)disregard\s+(all\s+)?(previous|prior|above)`),
	regexp.MustCompile(`(?i)forget\s+(all\s+)?(previous|prior|above|your)\s+instructions`),
	regexp.MustCompile(`(?i)new\s+(role|persona|instruction)`),
	regexp.MustCompile(`(?i)system\s+prompt\s*(override|bypass|inject)`),
}

// awsKeyPattern — ISC-109
var awsKeyPattern = regexp.MustCompile(`AKIA[A-Z0-9]{16}`)

// Scanner holds state for repeated Scan calls.
type Scanner struct {
	// descHashes maps tool name → "version:sha256hex"
	descHashes map[string]string
}

// NewScanner creates a Scanner ready for use.
func NewScanner() *Scanner {
	return &Scanner{descHashes: make(map[string]string)}
}

// hashDesc returns a hex SHA-256 of the description string.
func hashDesc(s string) string {
	h := sha256.Sum256([]byte(s))
	return fmt.Sprintf("%x", h)
}

// Scan inspects the given tool list and returns security events.
func (s *Scanner) Scan(tools []Tool) []Event {
	var events []Event
	names := make([]string, len(tools))
	for i, t := range tools {
		names[i] = t.Name
	}

	for _, tool := range tools {
		desc := tool.Description

		// ISC-105: prompt injection in description
		for _, pat := range injectionPatterns {
			if pat.MatchString(desc) {
				events = append(events, Event{
					Type:     "tool_desc_injection",
					Severity: "critical",
					Message:  fmt.Sprintf("tool %q description matches injection pattern %q", tool.Name, pat.String()),
					ToolName: tool.Name,
					Details: map[string]string{
						"pattern": pat.String(),
					},
					Timestamp: time.Now(),
				})
				break // one event per tool is enough
			}
		}

		// ISC-106: cross-tool shadowing — description references other tool names
		for _, otherName := range names {
			if otherName == tool.Name {
				continue
			}
			// Look for the other tool's name mentioned as a callable reference
			// Heuristic: other name appears as a word in the description
			if strings.Contains(desc, otherName) {
				events = append(events, Event{
					Type:     "tool_shadowing_detected",
					Severity: "high",
					Message:  fmt.Sprintf("tool %q description references other tool %q", tool.Name, otherName),
					ToolName: tool.Name,
					Details: map[string]string{
						"referenced_tool": otherName,
					},
					Timestamp: time.Now(),
				})
				break // one shadowing event per tool
			}
		}

		// ISC-107: description drift — hash changed without version bump
		newHash := hashDesc(desc)
		key := fmt.Sprintf("%s:%s", tool.Version, newHash)
		if prev, seen := s.descHashes[tool.Name]; seen {
			parts := strings.SplitN(prev, ":", 2)
			prevVersion, prevHash := parts[0], parts[1]
			if prevHash != newHash && prevVersion == tool.Version {
				events = append(events, Event{
					Type:     "tool_description_changed",
					Severity: "high",
					Message:  fmt.Sprintf("tool %q description changed without version bump (version=%s)", tool.Name, tool.Version),
					ToolName: tool.Name,
					Details: map[string]string{
						"old_hash": prevHash,
						"new_hash": newHash,
						"version":  tool.Version,
					},
					Timestamp: time.Now(),
				})
			}
		}
		s.descHashes[tool.Name] = key

		// ISC-109: AWS key pattern in description
		if m := awsKeyPattern.FindString(desc); m != "" {
			events = append(events, Event{
				Type:     "tool_secret_detected",
				Severity: "critical",
				Message:  fmt.Sprintf("tool %q description contains AWS access key pattern", tool.Name),
				ToolName: tool.Name,
				Details: map[string]string{
					"pattern": "AWS_ACCESS_KEY_ID",
					"match":   m,
				},
				Timestamp: time.Now(),
			})
		}
	}

	return events
}
