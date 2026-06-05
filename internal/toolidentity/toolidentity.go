// Package toolidentity detects tool name collisions, schema poisoning, and name confusion.
package toolidentity

import (
	"crypto/sha256"
	"fmt"
	"sort"
	"strings"
	"time"
)

// Param describes one parameter of an MCP tool.
type Param struct {
	Name     string
	Type     string
	Required bool
}

// SchemaTool is a tool with its full parameter schema.
type SchemaTool struct {
	Name    string
	Version string
	Params  []Param
}

// Event is a security finding produced by the Checker.
type Event struct {
	Type      string
	Severity  string
	Message   string
	ToolName  string
	Details   map[string]string
	Timestamp time.Time
}

// CollisionPolicy controls whether name collisions are warnings or blocks.
type CollisionPolicy string

const (
	PolicyWarn  CollisionPolicy = "warn"
	PolicyBlock CollisionPolicy = "block"
)

// CheckerConfig holds tunable parameters.
type CheckerConfig struct {
	CollisionPolicy       CollisionPolicy
	ConfusionThreshold    int // Levenshtein distance threshold; default 2
	TrustedNameAllowlist  []string
}

// DefaultConfig returns a CheckerConfig with sensible defaults.
func DefaultConfig() CheckerConfig {
	return CheckerConfig{
		CollisionPolicy:    PolicyWarn,
		ConfusionThreshold: 2,
	}
}

// Checker is a stateful identity validator.
type Checker struct {
	cfg CheckerConfig
	// registered maps tool name → list of upstreams that registered it (ISC-108)
	registered map[string][]string
	// schemaHashes maps tool name → "version:hashHex" (ISC-115)
	schemaHashes map[string]string
}

// NewChecker creates a Checker with the given configuration.
func NewChecker(cfg CheckerConfig) *Checker {
	return &Checker{
		cfg:          cfg,
		registered:   make(map[string][]string),
		schemaHashes: make(map[string]string),
	}
}

// Register records a tool name from a given upstream namespace.
// Returns collision events if the name is already registered from a different upstream.
func (c *Checker) Register(upstream, name string) []Event {
	var events []Event
	existing := c.registered[name]

	// Check whether this upstream is already in the list
	for _, u := range existing {
		if u == upstream {
			return nil // same upstream re-registering — no collision
		}
	}

	if len(existing) > 0 {
		severity := "high"
		if c.cfg.CollisionPolicy == PolicyBlock {
			severity = "critical"
		}
		events = append(events, Event{
			Type:     "tool_name_collision",
			Severity: severity,
			Message:  fmt.Sprintf("tool %q registered by multiple upstreams: %v and %q", name, existing, upstream),
			ToolName: name,
			Details: map[string]string{
				"existing_upstreams": strings.Join(existing, ","),
				"new_upstream":       upstream,
				"policy":             string(c.cfg.CollisionPolicy),
			},
			Timestamp: time.Now(),
		})
	}

	c.registered[name] = append(existing, upstream)
	return events
}

// CheckSchema validates schema integrity and returns events.
// ISC-115: full schema poisoning; ISC-116: name confusion.
func (c *Checker) CheckSchema(tool SchemaTool) []Event {
	var events []Event

	// ISC-115 — compute schema hash from sorted param fingerprints
	newHash := schemaHash(tool.Params)
	key := fmt.Sprintf("%s:%s", tool.Version, newHash)
	if prev, seen := c.schemaHashes[tool.Name]; seen {
		parts := strings.SplitN(prev, ":", 2)
		prevVersion, prevHash := parts[0], parts[1]
		if prevHash != newHash && prevVersion == tool.Version {
			events = append(events, Event{
				Type:     "full_schema_poisoning_suspected",
				Severity: "critical",
				Message:  fmt.Sprintf("tool %q schema changed without version bump (version=%s)", tool.Name, tool.Version),
				ToolName: tool.Name,
				Details: map[string]string{
					"old_hash":    prevHash,
					"new_hash":    newHash,
					"version":     tool.Version,
					"param_diff":  paramDiff(c.schemaHashes, tool),
				},
				Timestamp: time.Now(),
			})
		}
	}
	c.schemaHashes[tool.Name] = key

	// ISC-116 — Levenshtein confusion against allowlist
	threshold := c.cfg.ConfusionThreshold
	if threshold <= 0 {
		threshold = 2
	}
	for _, trusted := range c.cfg.TrustedNameAllowlist {
		if tool.Name == trusted {
			continue // exact match — legitimate
		}
		d := levenshtein(tool.Name, trusted)
		if d <= threshold {
			events = append(events, Event{
				Type:     "tool_name_confusion_suspected",
				Severity: "high",
				Message:  fmt.Sprintf("tool name %q is suspiciously similar to trusted name %q (distance=%d)", tool.Name, trusted, d),
				ToolName: tool.Name,
				Details: map[string]string{
					"trusted_name": trusted,
					"distance":     fmt.Sprintf("%d", d),
					"threshold":    fmt.Sprintf("%d", threshold),
				},
				Timestamp: time.Now(),
			})
		}
	}

	return events
}

// schemaHash produces a deterministic SHA-256 over sorted param fingerprints.
func schemaHash(params []Param) string {
	type pf struct{ name, typ string; req bool }
	fps := make([]pf, len(params))
	for i, p := range params {
		fps[i] = pf{p.Name, p.Type, p.Required}
	}
	sort.Slice(fps, func(i, j int) bool {
		return fps[i].name < fps[j].name
	})
	var sb strings.Builder
	for _, f := range fps {
		fmt.Fprintf(&sb, "%s:%s:%v|", f.name, f.typ, f.req)
	}
	h := sha256.Sum256([]byte(sb.String()))
	return fmt.Sprintf("%x", h)
}

// paramDiff returns a simple textual diff of old vs new params.
// We only have the old hash stored, so we produce a summary string.
func paramDiff(hashes map[string]string, tool SchemaTool) string {
	return fmt.Sprintf("schema fingerprint changed for tool %q at version %s", tool.Name, tool.Version)
}

// levenshtein computes the edit distance between two strings.
func levenshtein(a, b string) int {
	ra := []rune(a)
	rb := []rune(b)
	la, lb := len(ra), len(rb)
	if la == 0 {
		return lb
	}
	if lb == 0 {
		return la
	}
	// dp row
	prev := make([]int, lb+1)
	curr := make([]int, lb+1)
	for j := 0; j <= lb; j++ {
		prev[j] = j
	}
	for i := 1; i <= la; i++ {
		curr[0] = i
		for j := 1; j <= lb; j++ {
			cost := 1
			if ra[i-1] == rb[j-1] {
				cost = 0
			}
			del := prev[j] + 1
			ins := curr[j-1] + 1
			sub := prev[j-1] + cost
			curr[j] = min3(del, ins, sub)
		}
		prev, curr = curr, prev
	}
	return prev[lb]
}

func min3(a, b, c int) int {
	if a < b {
		if a < c {
			return a
		}
		return c
	}
	if b < c {
		return b
	}
	return c
}
