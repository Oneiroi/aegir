package sanitizer

import (
	"strings"
	"testing"

	"github.com/aegishjalmur/aegir/internal/config"
	"github.com/aegishjalmur/aegir/internal/logging"
)

func b5Compliance(master bool) config.Compliance {
	return config.Compliance{
		Enabled: master,
		HIPAA:   config.HIPAAConfig{PHIDetection: true},
		PCI:     config.PCIConfig{CardDetection: true},
		GDPR:    config.GDPRConfig{PIIDetection: true},
	}
}

func b5ComplianceManager(t *testing.T, comp config.Compliance) *ComplianceManager {
	t.Helper()
	l, _ := logging.New(config.Logging{Level: "error", Format: "json", HMACKey: "test-hmac-key-32-characters-long"})
	return NewComplianceManager(comp, l)
}

// Bundle 5 (F6): master off => identity / "low" / no violations.
func TestComplianceMasterOffIdentity(t *testing.T) {
	cm := b5ComplianceManager(t, b5Compliance(false))
	in := "member ssn 123-45-6789 and card 4111 1111 1111 1111"
	res := cm.ScanForCompliance(in)
	if res.Sanitized != in {
		t.Errorf("master off must be identity, got %q", res.Sanitized)
	}
	if res.ComplianceRisk != "low" || len(res.Violations) != 0 {
		t.Errorf("master off must be low/no violations, got risk=%s n=%d", res.ComplianceRisk, len(res.Violations))
	}
}

// Bundle 5: master on + unset classes => detectors run (config-side default
// injection covers yaml/env; here the struct is built with class zero values,
// so the manager-level gate relies on the same master-aware resolution the
// config loader performs — explicit class values are set true for determinism).
func TestComplianceMasterOnDetects(t *testing.T) {
	cm := b5ComplianceManager(t, config.Compliance{
		Enabled: true,
		GDPR:    config.GDPRConfig{Enabled: true, PIIDetection: true},
	})
	res := cm.ScanForCompliance("member ssn 123-45-6789 please")
	if len(res.Violations) != 1 || res.Violations[0].Type != "pii" {
		t.Fatalf("master on must detect the SSN, got %+v", res.Violations)
	}
}

// N3: the scan's Sanitized actually masks — and re-scanning the masked text
// finds nothing (idempotent redaction).
func TestComplianceSanitizedMasksAndIdempotent(t *testing.T) {
	cm := b5ComplianceManager(t, config.Compliance{
		Enabled: true,
		GDPR:    config.GDPRConfig{Enabled: true, PIIDetection: true},
	})
	res := cm.ScanForCompliance(`{"text":"Member SSN 123-45-6789 is on record."}`)
	if !strings.Contains(res.Sanitized, "PII_REDACTED") || strings.Contains(res.Sanitized, "123-45-6789") {
		t.Fatalf("Sanitized must mask the SSN, got %q", res.Sanitized)
	}
	if again := cm.ScanForCompliance(res.Sanitized); len(again.Violations) != 0 {
		t.Fatalf("re-scan of masked text must be clean, got %+v", again.Violations)
	}
}

// F6 card posture: Luhn-valid PAN => critical; Luhn-invalid => low
// pan_unvalidated, log-only, NOT redacted.
func TestCardLuhnPosture(t *testing.T) {
	cm := b5ComplianceManager(t, config.Compliance{
		Enabled: true,
		PCI:     config.PCIConfig{Enabled: true, CardDetection: true},
	})

	valid := cm.ScanForCompliance("charge card 4111 1111 1111 1111 now")
	if len(valid.PCIDetections) != 1 || valid.PCIDetections[0].Severity != "critical" {
		t.Fatalf("Luhn-valid PAN must be one critical detection, got %+v", valid.PCIDetections)
	}
	if !strings.Contains(valid.Sanitized, "CARD_DATA_REDACTED") {
		t.Errorf("Luhn-valid PAN must be redacted, got %q", valid.Sanitized)
	}

	invalid := cm.ScanForCompliance("invoice 4111 1111 1111 1112 paid")
	if len(invalid.PCIDetections) != 1 || invalid.PCIDetections[0].Severity != "low" {
		t.Fatalf("Luhn-invalid PAN must be one low detection, got %+v", invalid.PCIDetections)
	}
	if invalid.PCIDetections[0].Type != "pci_pan_unvalidated" {
		t.Errorf("Luhn-invalid PAN detection type = %q, want pci_pan_unvalidated", invalid.PCIDetections[0].Type)
	}
	if invalid.ComplianceRisk != "low" {
		t.Errorf("low-severity pan_unvalidated must keep risk low, got %s", invalid.ComplianceRisk)
	}
	if !strings.Contains(invalid.Sanitized, "4111 1111 1111 1112") {
		t.Errorf("Luhn-invalid PAN must NOT be redacted, got %q", invalid.Sanitized)
	}
}

// Note C: a card number counts under PCI only — the PHI class must not emit
// duplicate violations for the same card value.
func TestCardCountedUnderPCIOOnly(t *testing.T) {
	cm := b5ComplianceManager(t, config.Compliance{
		Enabled: true,
		HIPAA: config.HIPAAConfig{Enabled: true, PHIDetection: true},
		PCI:   config.PCIConfig{Enabled: true, CardDetection: true},
		GDPR: config.GDPRConfig{Enabled: true, PIIDetection: true},
	})
	res := cm.ScanForCompliance("card 4111 1111 1111 1111")
	for _, v := range res.Violations {
		if v.Type == "phi" {
			t.Errorf("card must not produce PHI violations, got %+v", v)
		}
	}
	pan := 0
	for _, v := range res.Violations {
		if v.Type == "pci" {
			pan++
		}
	}
	if pan != 1 {
		t.Fatalf("card must count exactly once under PCI, got %d pci violations: %+v", pan, res.Violations)
	}
}

// Kimi/A5 footgun: nil logger must not panic.
func TestComplianceNilLoggerNoPanic(t *testing.T) {
	cm := NewComplianceManager(config.Compliance{
		Enabled: true,
		GDPR:    config.GDPRConfig{Enabled: true, PIIDetection: true},
	}, nil)
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("nil logger must not panic: %v", r)
		}
	}()
	_ = cm.ScanForCompliance("ssn 123-45-6789")
}
