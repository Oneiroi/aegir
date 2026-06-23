package server

import (
	"strings"
	"testing"

	"github.com/aegishjalmur/aegir/internal/config"
	"github.com/aegishjalmur/aegir/internal/sanitizer"
)

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
