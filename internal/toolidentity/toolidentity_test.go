package toolidentity_test

import (
	"testing"

	"github.com/aegishjalmur/aegir/internal/toolidentity"
)

// ISC-108 — duplicate tool names across upstreams

func TestISC108_CollisionDetected(t *testing.T) {
	cfg := toolidentity.DefaultConfig()
	c := toolidentity.NewChecker(cfg)

	_ = c.Register("upstream_a", "send_email")
	events := c.Register("upstream_b", "send_email")

	found := false
	for _, e := range events {
		if e.Type == "tool_name_collision" {
			found = true
		}
	}
	if !found {
		t.Errorf("ISC-108: expected tool_name_collision, got %+v", events)
	}
}

func TestISC108_NoCollisionSameUpstream(t *testing.T) {
	cfg := toolidentity.DefaultConfig()
	c := toolidentity.NewChecker(cfg)
	_ = c.Register("upstream_a", "send_email")
	events := c.Register("upstream_a", "send_email")
	for _, e := range events {
		if e.Type == "tool_name_collision" {
			t.Errorf("ISC-108: same-upstream re-register should not collide: %+v", e)
		}
	}
}

func TestISC108_NoCollisionDifferentNames(t *testing.T) {
	cfg := toolidentity.DefaultConfig()
	c := toolidentity.NewChecker(cfg)
	_ = c.Register("upstream_a", "send_email")
	events := c.Register("upstream_b", "read_file")
	for _, e := range events {
		if e.Type == "tool_name_collision" {
			t.Errorf("ISC-108: different names should not collide: %+v", e)
		}
	}
}

func TestISC108_PolicyBlock(t *testing.T) {
	cfg := toolidentity.DefaultConfig()
	cfg.CollisionPolicy = toolidentity.PolicyBlock
	c := toolidentity.NewChecker(cfg)
	_ = c.Register("upstream_a", "exec")
	events := c.Register("upstream_b", "exec")
	found := false
	for _, e := range events {
		if e.Type == "tool_name_collision" && e.Severity == "critical" {
			found = true
		}
	}
	if !found {
		t.Errorf("ISC-108: block policy should produce critical severity: %+v", events)
	}
}

// ISC-115 — full schema poisoning

func TestISC115_SchemaPoisoningDetected(t *testing.T) {
	cfg := toolidentity.DefaultConfig()
	c := toolidentity.NewChecker(cfg)

	original := toolidentity.SchemaTool{
		Name:    "send_email",
		Version: "1.0",
		Params: []toolidentity.Param{
			{Name: "to", Type: "string", Required: true},
			{Name: "body", Type: "string", Required: false},
		},
	}
	_ = c.CheckSchema(original)

	// Same version, but added a new hidden param
	poisoned := toolidentity.SchemaTool{
		Name:    "send_email",
		Version: "1.0",
		Params: []toolidentity.Param{
			{Name: "to", Type: "string", Required: true},
			{Name: "body", Type: "string", Required: false},
			{Name: "bcc", Type: "string", Required: false}, // injected!
		},
	}
	events := c.CheckSchema(poisoned)

	found := false
	for _, e := range events {
		if e.Type == "full_schema_poisoning_suspected" {
			found = true
		}
	}
	if !found {
		t.Errorf("ISC-115: expected full_schema_poisoning_suspected, got %+v", events)
	}
}

func TestISC115_NoAlertWhenVersionBumped(t *testing.T) {
	cfg := toolidentity.DefaultConfig()
	c := toolidentity.NewChecker(cfg)

	c.CheckSchema(toolidentity.SchemaTool{
		Name: "read_file", Version: "1.0",
		Params: []toolidentity.Param{{Name: "path", Type: "string", Required: true}},
	})
	events := c.CheckSchema(toolidentity.SchemaTool{
		Name: "read_file", Version: "1.1",
		Params: []toolidentity.Param{
			{Name: "path", Type: "string", Required: true},
			{Name: "encoding", Type: "string", Required: false},
		},
	})
	for _, e := range events {
		if e.Type == "full_schema_poisoning_suspected" {
			t.Errorf("ISC-115: should not fire when version bumped: %+v", e)
		}
	}
}

func TestISC115_NoAlertWhenSchemaUnchanged(t *testing.T) {
	cfg := toolidentity.DefaultConfig()
	c := toolidentity.NewChecker(cfg)
	params := []toolidentity.Param{{Name: "x", Type: "int", Required: true}}
	c.CheckSchema(toolidentity.SchemaTool{Name: "calc", Version: "2.0", Params: params})
	events := c.CheckSchema(toolidentity.SchemaTool{Name: "calc", Version: "2.0", Params: params})
	for _, e := range events {
		if e.Type == "full_schema_poisoning_suspected" {
			t.Errorf("ISC-115: false positive when schema unchanged: %+v", e)
		}
	}
}

// ISC-116 — Levenshtein name confusion

func TestISC116_ConfusionDetected_SendEmail(t *testing.T) {
	cfg := toolidentity.DefaultConfig()
	cfg.TrustedNameAllowlist = []string{"send_email", "read_file"}
	c := toolidentity.NewChecker(cfg)

	// send_emai1 vs send_email → distance 1
	events := c.CheckSchema(toolidentity.SchemaTool{
		Name:    "send_emai1",
		Version: "1.0",
		Params:  []toolidentity.Param{{Name: "to", Type: "string", Required: true}},
	})
	found := false
	for _, e := range events {
		if e.Type == "tool_name_confusion_suspected" && e.Details["trusted_name"] == "send_email" {
			found = true
		}
	}
	if !found {
		t.Errorf("ISC-116: expected confusion for send_emai1 vs send_email, got %+v", events)
	}
}

func TestISC116_NoConfusionOnExactMatch(t *testing.T) {
	cfg := toolidentity.DefaultConfig()
	cfg.TrustedNameAllowlist = []string{"send_email"}
	c := toolidentity.NewChecker(cfg)
	events := c.CheckSchema(toolidentity.SchemaTool{
		Name: "send_email", Version: "1.0",
		Params: []toolidentity.Param{{Name: "to", Type: "string", Required: true}},
	})
	for _, e := range events {
		if e.Type == "tool_name_confusion_suspected" {
			t.Errorf("ISC-116: exact match should not produce confusion: %+v", e)
		}
	}
}

func TestISC116_NoConfusionOnDistantName(t *testing.T) {
	cfg := toolidentity.DefaultConfig()
	cfg.TrustedNameAllowlist = []string{"send_email"}
	c := toolidentity.NewChecker(cfg)
	events := c.CheckSchema(toolidentity.SchemaTool{
		Name: "delete_database", Version: "1.0",
		Params: []toolidentity.Param{},
	})
	for _, e := range events {
		if e.Type == "tool_name_confusion_suspected" {
			t.Errorf("ISC-116: distant name should not produce confusion: %+v", e)
		}
	}
}

func TestISC116_ConfigurableThreshold(t *testing.T) {
	// With threshold=1, a name at distance 2 should NOT fire.
	// "send_emXYl" vs "send_email":
	//   send_email  (10 chars)
	//   send_emXYl  — position 8: 'X' replaces 'i', position 9: 'Y' replaces 'l'... wait let's count:
	//   s e n d _ e m a i l   (10)
	//   s e n d _ e m X Y l   — 'X' replaces 'a', 'Y' replaces 'i' → distance 2
	cfg := toolidentity.DefaultConfig()
	cfg.TrustedNameAllowlist = []string{"send_email"}
	cfg.ConfusionThreshold = 1
	c := toolidentity.NewChecker(cfg)
	// "send_emXYl" vs "send_email" = distance 2 (two substitutions: a→X, i→Y)
	events := c.CheckSchema(toolidentity.SchemaTool{
		Name: "send_emXYl", Version: "1.0",
		Params: []toolidentity.Param{},
	})
	for _, e := range events {
		if e.Type == "tool_name_confusion_suspected" {
			t.Errorf("ISC-116: with threshold=1, distance-2 name should not fire: %+v", e)
		}
	}
}

func TestLevenshteinDirectCases(t *testing.T) {
	// Indirect test through CheckSchema; validate the distance behaviour
	cfg := toolidentity.DefaultConfig()
	cfg.TrustedNameAllowlist = []string{"abc"}
	cfg.ConfusionThreshold = 3
	c := toolidentity.NewChecker(cfg)

	// "" vs "abc" = distance 3
	events := c.CheckSchema(toolidentity.SchemaTool{Name: "xyz", Version: "1"})
	// "xyz" vs "abc" = 3 substitutions — should fire at threshold 3
	found := false
	for _, e := range events {
		if e.Type == "tool_name_confusion_suspected" {
			found = true
		}
	}
	if !found {
		t.Errorf("Levenshtein: expected confusion at distance=threshold, got %+v", events)
	}
}
