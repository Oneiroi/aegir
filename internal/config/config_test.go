package config

import "testing"

// TestDefaultDetectionEnabled is the ISC-132 probe: a security gateway must
// scan by default. The production load path (viper defaults via setDefaults)
// must enable the master detection switch so an operator who ships without an
// explicit security.detection block is protected, not wide open.
func TestDefaultDetectionEnabled(t *testing.T) {
	// Load from an empty temp dir so no aegir.yaml is found — exercises the
	// setDefaults() path that the production Load() uses.
	cfg, err := LoadWithConfigDir(t.TempDir())
	if err != nil {
		t.Fatalf("load defaults: %v", err)
	}

	if !cfg.Security.Detection.Enabled {
		t.Fatal("security.detection.enabled must default to true — Aegir must not forward traffic unscanned out of the box")
	}
	if cfg.Security.Detection.ResponsePolicy != "block" {
		t.Errorf("security.detection.response_policy default = %q, want \"block\"", cfg.Security.Detection.ResponsePolicy)
	}
}
