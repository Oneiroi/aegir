// Package redaction implements PII/PHI/PCI detection and redaction for the Aegir MCP gateway.
//
// ISC-60/61: SSN redaction (PII)
// ISC-62:    ICD-10 code redaction (PHI)
// ISC-63:    Payment card number redaction via Luhn check (PCI)
// ISC-65:    Violation logging with data type, severity, redaction flag
// ISC-96:    Idempotency — already-redacted placeholders are left unchanged
package redaction

import (
	"regexp"
)

// Config holds configuration for the Redactor. Reserved for future options.
type Config struct{}

// Violation records a single detected sensitive data instance.
type Violation struct {
	// DataType identifies the category: "SSN", "ICD10", "PAYMENT_CARD".
	DataType string

	// Severity is the risk level: "HIGH" for PCI/PII, "MEDIUM" for PHI ICD-10.
	Severity string

	// RedactionApplied is true when the match was replaced with a placeholder.
	RedactionApplied bool
}

// redactorRule encapsulates a compiled pattern and its replacement strategy.
type redactorRule struct {
	re           *regexp.Regexp
	dataType     string
	severity     string
	replacement  string
	// luhnCheck activates the Luhn card-number validator before redacting.
	luhnCheck    bool
}

// Placeholder tokens used as replacements. These strings are also used to
// detect already-redacted content (ISC-96 idempotency).
const (
	placeholderPII  = "PII_REDACTED"
	placeholderPHI  = "PHI_REDACTED"
	placeholderPCI  = "CARD_DATA_REDACTED"
)

// Pre-compiled rules. Order matters for the idempotency guard: placeholder
// patterns are checked first so they are never matched by content patterns.
var rules = []redactorRule{
	// ISC-60/61: US Social Security Number  NNN-NN-NNNN
	{
		re:          regexp.MustCompile(`\b\d{3}-\d{2}-\d{4}\b`),
		dataType:    "SSN",
		severity:    "HIGH",
		replacement: placeholderPII,
	},
	// ISC-62: ICD-10 clinical code  [A-Z]\d{2}(\.\d{1,4})?
	// Must be preceded by a word boundary and followed by one to avoid
	// matching sub-strings inside other alphanumeric tokens.
	{
		re:          regexp.MustCompile(`\b[A-Z]\d{2}(\.\d{1,4})?\b`),
		dataType:    "ICD10",
		severity:    "MEDIUM",
		replacement: placeholderPHI,
	},
	// ISC-63: Payment card numbers 13–19 consecutive digits (Luhn-validated)
	{
		re:          regexp.MustCompile(`\b\d{13,19}\b`),
		dataType:    "PAYMENT_CARD",
		severity:    "HIGH",
		replacement: placeholderPCI,
		luhnCheck:   true,
	},
}

// placeholderPattern matches any of our own redaction tokens so that we can
// skip them during idempotency guards.
var placeholderPattern = regexp.MustCompile(
	`\b(` + placeholderPII + `|` + placeholderPHI + `|` + placeholderPCI + `)\b`,
)

// Redactor performs sensitive-data detection and in-place redaction.
type Redactor struct {
	cfg   Config
	rules []redactorRule
}

// NewRedactor constructs a Redactor. All regex patterns are pre-compiled at
// construction time — no per-call compilation occurs.
func NewRedactor(cfg Config) *Redactor {
	return &Redactor{cfg: cfg, rules: rules}
}

// Redact scans content for sensitive data patterns and replaces each match
// with the appropriate placeholder. It returns the redacted string and a
// slice of Violation records (one per match instance).
//
// Idempotency (ISC-96): text that already contains a placeholder token will
// not be double-redacted.
func (rd *Redactor) Redact(content string) (string, []Violation) {
	var violations []Violation
	out := content

	for _, rule := range rd.rules {
		// ReplaceAllStringFunc lets us apply the Luhn check per-match and
		// collect violations before mutating the string.
		out = rule.re.ReplaceAllStringFunc(out, func(match string) string {
			// ISC-96: skip if the match is already a redaction placeholder.
			if isPlaceholder(match) {
				return match
			}

			// ISC-63 Luhn gate: only redact if the number passes Luhn.
			if rule.luhnCheck && !luhn(match) {
				return match
			}

			violations = append(violations, Violation{
				DataType:         rule.dataType,
				Severity:         rule.severity,
				RedactionApplied: true,
			})
			return rule.replacement
		})
	}

	return out, violations
}

// isPlaceholder returns true when s is one of the known redaction tokens.
func isPlaceholder(s string) bool {
	return s == placeholderPII || s == placeholderPHI || s == placeholderPCI
}

// luhn validates a numeric string using the Luhn algorithm.
// Non-digit characters are stripped before evaluation (none expected here
// since the regex only matches \d sequences, but kept for robustness).
func luhn(s string) bool {
	// Strip any non-digit characters
	digits := make([]int, 0, len(s))
	for _, ch := range s {
		if ch >= '0' && ch <= '9' {
			digits = append(digits, int(ch-'0'))
		}
	}

	n := len(digits)
	if n < 13 || n > 19 {
		return false
	}

	sum := 0
	// Iterate right-to-left; double every second digit from the right.
	for i := 0; i < n; i++ {
		d := digits[n-1-i]
		if i%2 == 1 {
			d *= 2
			if d > 9 {
				d -= 9
			}
		}
		sum += d
	}
	return sum%10 == 0
}

