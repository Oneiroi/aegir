package config

import (
	"os"
	"path/filepath"
	"testing"
)

// writeCfg writes a temp aegir yaml and loads it via the file loader.
func writeCfg(t *testing.T, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "aegir.yaml")
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// Bundle 5 (F6): master off by default => everything off (historical posture).
func TestComplianceMasterDefaultOff(t *testing.T) {
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Compliance.Enabled {
		t.Error("compliance.enabled must default false")
	}
	if cfg.Compliance.GDPR.Enabled || cfg.Compliance.HIPAA.Enabled || cfg.Compliance.PCI.Enabled {
		t.Error("classes must default off with the master off")
	}
	if cfg.Compliance.GDPR.PIIDetection || cfg.Compliance.PCI.CardDetection || cfg.Compliance.HIPAA.PHIDetection {
		t.Error("sub-detection flags must default off with the master off")
	}
}

// Bundle 5 note A: master on with unset classes => classes and sub-flags
// follow the master; an explicit false opts out.
func TestComplianceMasterFlipsUnsetClasses(t *testing.T) {
	cfg, err := LoadWithConfigFile(writeCfg(t, "compliance:\n  enabled: true\n"))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !cfg.Compliance.Enabled {
		t.Fatal("master must be true from the file")
	}
	if !cfg.Compliance.GDPR.Enabled || !cfg.Compliance.HIPAA.Enabled || !cfg.Compliance.PCI.Enabled {
		t.Errorf("unset classes must follow the master on: gdpr=%v hipaa=%v pci=%v",
			cfg.Compliance.GDPR.Enabled, cfg.Compliance.HIPAA.Enabled, cfg.Compliance.PCI.Enabled)
	}
	if !cfg.Compliance.GDPR.PIIDetection || !cfg.Compliance.PCI.CardDetection || !cfg.Compliance.HIPAA.PHIDetection {
		t.Errorf("unset sub-flags must follow the master on: gdpr_pii=%v pci_card=%v hipaa_phi=%v",
			cfg.Compliance.GDPR.PIIDetection, cfg.Compliance.PCI.CardDetection, cfg.Compliance.HIPAA.PHIDetection)
	}
}

func TestComplianceExplicitFalseOptOut(t *testing.T) {
	cfg, err := LoadWithConfigFile(writeCfg(t, `
compliance:
  enabled: true
  pci:
    enabled: false
`))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Compliance.PCI.Enabled {
		t.Error("explicit pci.enabled=false must opt out even with the master on")
	}
	if !cfg.Compliance.GDPR.Enabled {
		t.Error("unrelated unset classes must still follow the master on")
	}
}

// The request_policy defaults mirror the response_policy defaults.
func TestComplianceRequestPolicyDefaults(t *testing.T) {
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	for _, class := range []string{"pii", "phi", "pci"} {
		if got := cfg.Compliance.RequestPolicy[class]; got != "redact" {
			t.Errorf("request_policy[%s] = %q, want redact", class, got)
		}
	}
}
