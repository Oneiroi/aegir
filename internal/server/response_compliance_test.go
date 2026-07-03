package server

import (
	"os"
	"strings"
	"testing"

	"github.com/aegishjalmur/aegir/internal/config"
	"github.com/aegishjalmur/aegir/internal/logging"
	"github.com/aegishjalmur/aegir/internal/sanitizer"
)

// auditLogger builds a JSON logger that writes to a temp file so a test can read
// back the emitted security events (the audit trail). Returns the logger and the
// file path.
func auditLogger(t *testing.T) (*logging.Logger, string) {
	t.Helper()
	path := t.TempDir() + "/audit.log"
	l, err := logging.New(config.Logging{
		Level:           "info",
		Format:          "json",
		HMACKey:         "test-hmac-key-32-characters-long",
		IntegrityChecks: true,
		File:            path,
	})
	if err != nil {
		t.Fatalf("failed to build audit logger: %v", err)
	}
	return l, path
}

// newComplianceProxy builds an MCPProxy wired for the response-compliance gate:
// a compliance manager that detects GDPR PII (SSN) and a per-type response policy.
func newComplianceProxy(t *testing.T, logger *logging.Logger, policy map[string]string) *MCPProxy {
	t.Helper()
	comp := config.Compliance{
		GDPR:           config.GDPRConfig{Enabled: true, PIIDetection: true},
		ResponsePolicy: policy,
	}
	return &MCPProxy{
		config:            &config.Config{Compliance: comp},
		logger:            logger,
		complianceManager: sanitizer.NewComplianceManager(comp, logger),
		sanitizer:         sanitizer.New(config.Security{Sanitization: config.Sanitization{Enabled: true}}, logger),
	}
}

// TestComplianceBlockAudited is the ISC-162 probe: a policy-BLOCKED response must
// still produce the response_compliance_violation audit event. The H-002 fix had
// introduced a duplicate switch that returned 403 before the audit event fired,
// silently dropping blocked responses from the audit trail. The consolidated gate
// logs FIRST, then blocks — this test asserts that ordering end-to-end.
func TestComplianceBlockAudited(t *testing.T) {
	logger, logPath := auditLogger(t)
	proxy := newComplianceProxy(t, logger, map[string]string{"pii": "block"})

	respJSON := `{"content":[{"type":"text","text":"Member SSN 123-45-6789 is on record."}]}`
	decision := proxy.enforceResponseCompliance(respJSON, nil)

	if decision.action != "block" {
		t.Fatalf("decision.action = %q, want \"block\" (pii policy is block)", decision.action)
	}

	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("failed to read audit log: %v", err)
	}
	if !strings.Contains(string(data), `"event_type":"response_compliance_violation"`) {
		t.Fatalf("blocked response did not emit response_compliance_violation audit event.\nlog:\n%s", string(data))
	}
}

// TestComplianceScanBeforeRedaction is the ISC-149 probe: the compliance scan runs
// on PRE-redaction content, so severity/data-type reflect the true finding even
// when the forwarded payload is later masked. Proven two ways: (1) the audit event
// names the ssn/pii identifier with its severity, and (2) scanning a post-redaction
// copy finds nothing — so scanning after masking would lose the finding entirely.
func TestComplianceScanBeforeRedaction(t *testing.T) {
	logger, logPath := auditLogger(t)
	proxy := newComplianceProxy(t, logger, map[string]string{"pii": "redact"})

	rawJSON := `{"content":[{"type":"text","text":"Member SSN 123-45-6789 is on record."}]}`
	maskedJSON := `{"content":[{"type":"text","text":"Member SSN [REDACTED] is on record."}]}`

	// If the scan ran AFTER redaction, the finding would be gone: prove the gap.
	if masked := proxy.complianceManager.ScanForCompliance(maskedJSON); len(masked.Violations) != 0 {
		t.Fatalf("post-redaction content still shows %d violations; test premise invalid", len(masked.Violations))
	}

	decision := proxy.enforceResponseCompliance(rawJSON, nil)
	if decision.action != "redact" {
		t.Fatalf("decision.action = %q, want \"redact\"", decision.action)
	}

	// The audit event, captured from the RAW pre-redaction scan, must name the
	// ssn/pii identifier and carry a non-empty severity.
	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("failed to read audit log: %v", err)
	}
	log := string(data)
	if !strings.Contains(log, `"event_type":"response_compliance_violation"`) {
		t.Fatalf("redacted response did not emit audit event.\nlog:\n%s", log)
	}
	if !strings.Contains(log, "ssn[pii]") {
		t.Fatalf("audit event missing pre-redaction ssn[pii] data-type breakdown.\nlog:\n%s", log)
	}
}

// TestResponseComplianceAction_PerDataTypePolicy is the ISC-28 probe:
// compliance.response_policy maps violation types to block/redact/log-only, and
// the highest-priority action wins across all violations in a response.
func TestResponseComplianceAction_PerDataTypePolicy(t *testing.T) {
	cases := []struct {
		name       string
		policy     map[string]string
		violations []sanitizer.Violation
		want       string
	}{
		{
			name:       "block_wins_over_redact",
			policy:     map[string]string{"pii": "block", "phi": "redact"},
			violations: []sanitizer.Violation{{Type: "pii"}, {Type: "phi"}},
			want:       "block",
		},
		{
			name:       "redact_wins_over_log_only",
			policy:     map[string]string{"pci": "redact", "phi": "log-only"},
			violations: []sanitizer.Violation{{Type: "pci"}, {Type: "phi"}},
			want:       "redact",
		},
		{
			name:       "explicit_log_only",
			policy:     map[string]string{"pii": "log-only"},
			violations: []sanitizer.Violation{{Type: "pii"}},
			want:       "log-only",
		},
		{
			name:       "unmapped_type_defaults_to_redact",
			policy:     map[string]string{},
			violations: []sanitizer.Violation{{Type: "pii"}},
			want:       "redact",
		},
		{
			name:       "nil_policy_defaults_to_redact",
			policy:     nil,
			violations: []sanitizer.Violation{{Type: "phi"}},
			want:       "redact",
		},
		{
			name:       "no_violations_returns_log_only",
			policy:     map[string]string{"pii": "block"},
			violations: nil,
			want:       "log-only",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			proxy := &MCPProxy{
				config: &config.Config{
					Compliance: config.Compliance{
						ResponsePolicy: tc.policy,
					},
				},
			}
			got := proxy.responseComplianceAction(tc.violations)
			if got != tc.want {
				t.Errorf("responseComplianceAction() = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestSummarizeComplianceViolations_PerTypeSeverity is the ISC-27 mechanism
// probe: the response_compliance_violation log carries a per-data-type severity
// breakdown, not just an aggregate count, so the audit trail records which
// regulated data types appeared in the model output and how serious each was.
func TestSummarizeComplianceViolations_PerTypeSeverity(t *testing.T) {
	violations := []sanitizer.Violation{
		{Type: "pii", Pattern: "ssn", Regulation: "GDPR/CCPA", Severity: "high"},
		{Type: "pii", Pattern: "ssn", Regulation: "GDPR/CCPA", Severity: "high"},
		{Type: "phi", Pattern: "icd10", Regulation: "HIPAA", Severity: "medium"},
		{Type: "pci", Pattern: "card", Regulation: "PCI DSS", Severity: "high"},
	}

	got := summarizeComplianceViolations(violations)

	// Ordered by pattern; each distinct identifier carries class, severity, count.
	want := "card[pci]:high×1, icd10[phi]:medium×1, ssn[pii]:high×2"
	if got != want {
		t.Fatalf("summary mismatch:\n got: %s\nwant: %s", got, want)
	}
	if summarizeComplianceViolations(nil) != "" {
		t.Errorf("empty violations should summarize to empty string")
	}
}

// TestResponseComplianceSeverityFromSSN is the ISC-27 end-to-end data probe: an
// SSN present in model-output text is detected as a compliance violation with a
// severity, which is exactly what the response-path log records. This proves the
// data feeding summarizeComplianceViolations is real, not synthetic.
func TestResponseComplianceSeverityFromSSN(t *testing.T) {
	cm := sanitizer.NewComplianceManager(config.Compliance{
		GDPR: config.GDPRConfig{Enabled: true, PIIDetection: true},
	}, testLogger())

	res := cm.ScanForCompliance("Patient SSN on file: 123-45-6789, please verify.")

	if len(res.Violations) == 0 {
		t.Fatalf("expected an SSN compliance violation, got none")
	}
	var ssn *sanitizer.Violation
	for i := range res.Violations {
		if res.Violations[i].Pattern == "ssn" {
			ssn = &res.Violations[i]
			break
		}
	}
	if ssn == nil {
		t.Fatalf("expected a violation for the ssn pattern, got %+v", res.Violations)
	}
	if ssn.Severity == "" {
		t.Errorf("SSN violation must carry a severity for ISC-27 logging")
	}

	// The breakdown the log emits must name the ssn identifier and its severity.
	summary := summarizeComplianceViolations(res.Violations)
	if !strings.Contains(summary, "ssn[") || !strings.Contains(summary, ssn.Severity) {
		t.Errorf("summary %q missing ssn identifier/severity", summary)
	}
}
