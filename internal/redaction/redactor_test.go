package redaction_test

import (
	"strings"
	"testing"

	"github.com/aegishjalmur/aegir/internal/redaction"
)

// --- ISC-60/61: PII redaction (SSN) ---

func TestISC60_SSNRedacted(t *testing.T) {
	r := redaction.NewRedactor(redaction.Config{})
	input := "Patient SSN is 123-45-6789 in file."
	out, violations := r.Redact(input)

	if strings.Contains(out, "123-45-6789") {
		t.Error("SSN should have been redacted")
	}
	if !strings.Contains(out, "PII_REDACTED") {
		t.Errorf("expected PII_REDACTED in output, got: %s", out)
	}

	found := false
	for _, v := range violations {
		if v.DataType == "SSN" {
			found = true
			if v.Severity == "" {
				t.Error("violation should have non-empty severity")
			}
			if !v.RedactionApplied {
				t.Error("RedactionApplied should be true for SSN")
			}
		}
	}
	if !found {
		t.Errorf("expected SSN violation in %+v", violations)
	}
}

func TestISC61_MultipleSSNsRedacted(t *testing.T) {
	r := redaction.NewRedactor(redaction.Config{})
	input := "First: 111-22-3333, Second: 444-55-6666"
	out, violations := r.Redact(input)

	if strings.Contains(out, "111-22-3333") || strings.Contains(out, "444-55-6666") {
		t.Error("all SSNs should be redacted")
	}
	ssnCount := 0
	for _, v := range violations {
		if v.DataType == "SSN" {
			ssnCount++
		}
	}
	if ssnCount != 2 {
		t.Errorf("expected 2 SSN violations, got %d: %+v", ssnCount, violations)
	}
	_ = out
}

// --- ISC-62: PHI redaction (ICD-10 codes) ---

func TestISC62_ICD10CodeRedacted(t *testing.T) {
	r := redaction.NewRedactor(redaction.Config{})

	cases := []struct {
		input string
		code  string
	}{
		{"Diagnosis: A10.1 confirmed", "A10.1"},
		{"Code Z99 applies", "Z99"},
		{"Finding: B12.34 noted", "B12.34"},
	}

	for _, tc := range cases {
		out, violations := r.Redact(tc.input)
		if strings.Contains(out, tc.code) {
			t.Errorf("ICD-10 code %q should have been redacted from %q, got: %s", tc.code, tc.input, out)
		}
		if !strings.Contains(out, "PHI_REDACTED") {
			t.Errorf("expected PHI_REDACTED in output for %q, got: %s", tc.input, out)
		}
		found := false
		for _, v := range violations {
			if v.DataType == "ICD10" {
				found = true
				if !v.RedactionApplied {
					t.Error("RedactionApplied should be true for ICD10")
				}
			}
		}
		if !found {
			t.Errorf("expected ICD10 violation for input %q, violations: %+v", tc.input, violations)
		}
	}
}

// --- ISC-63: PCI redaction (Luhn-valid card numbers) ---

func TestISC63_VisaCardRedacted(t *testing.T) {
	r := redaction.NewRedactor(redaction.Config{})
	// Valid Visa test number (passes Luhn): 4532015112830366
	input := "Card: 4532015112830366 on file"
	out, violations := r.Redact(input)

	if strings.Contains(out, "4532015112830366") {
		t.Error("card number should be redacted")
	}
	if !strings.Contains(out, "CARD_DATA_REDACTED") {
		t.Errorf("expected CARD_DATA_REDACTED in output, got: %s", out)
	}
	found := false
	for _, v := range violations {
		if v.DataType == "PAYMENT_CARD" {
			found = true
			if !v.RedactionApplied {
				t.Error("RedactionApplied should be true for PAYMENT_CARD")
			}
		}
	}
	if !found {
		t.Errorf("expected PAYMENT_CARD violation; violations: %+v", violations)
	}
}

func TestISC63_MastercardRedacted(t *testing.T) {
	r := redaction.NewRedactor(redaction.Config{})
	// Valid Mastercard test number: 5425233430109903
	input := "MC: 5425233430109903"
	out, violations := r.Redact(input)

	if strings.Contains(out, "5425233430109903") {
		t.Error("Mastercard number should be redacted")
	}
	_ = out
	_ = violations
}

func TestISC63_InvalidLuhnNotRedacted(t *testing.T) {
	r := redaction.NewRedactor(redaction.Config{})
	// 16 digit number that fails Luhn check
	input := "Number: 1234567890123456 here"
	out, violations := r.Redact(input)

	// Should NOT be redacted since it fails Luhn
	if strings.Contains(out, "CARD_DATA_REDACTED") {
		t.Error("number failing Luhn should not be redacted as card data")
	}
	for _, v := range violations {
		if v.DataType == "PAYMENT_CARD" {
			t.Errorf("unexpected PAYMENT_CARD violation for Luhn-failing number: %+v", v)
		}
	}
}

// --- ISC-65: violations logged with data type, severity, redaction flag ---

func TestISC65_ViolationFieldsComplete(t *testing.T) {
	r := redaction.NewRedactor(redaction.Config{})
	input := "SSN: 987-65-4321"
	_, violations := r.Redact(input)

	if len(violations) == 0 {
		t.Fatal("expected at least one violation")
	}
	for _, v := range violations {
		if v.DataType == "" {
			t.Error("DataType must not be empty")
		}
		if v.Severity == "" {
			t.Error("Severity must not be empty")
		}
		// RedactionApplied is bool; just confirm it is accessible (true here)
		if !v.RedactionApplied {
			t.Error("RedactionApplied should be true when redaction was performed")
		}
	}
}

// --- ISC-96: idempotency ---

func TestISC96_IdempotentSSN(t *testing.T) {
	r := redaction.NewRedactor(redaction.Config{})
	input := "PII_REDACTED on file"
	out, violations := r.Redact(input)

	// Must not become PII_REDACTED_REDACTED
	if strings.Contains(out, "PII_REDACTED_REDACTED") {
		t.Errorf("double-redaction occurred: %s", out)
	}
	if out != input {
		t.Errorf("already-redacted text should pass through unchanged, got: %s", out)
	}
	if len(violations) != 0 {
		t.Errorf("no violations expected for already-redacted text, got: %+v", violations)
	}
}

func TestISC96_IdempotentPHI(t *testing.T) {
	r := redaction.NewRedactor(redaction.Config{})
	input := "diagnosis: PHI_REDACTED"
	out, _ := r.Redact(input)

	if strings.Contains(out, "PHI_REDACTED_REDACTED") {
		t.Errorf("double-redaction of PHI placeholder: %s", out)
	}
}

func TestISC96_IdempotentCard(t *testing.T) {
	r := redaction.NewRedactor(redaction.Config{})
	input := "card: CARD_DATA_REDACTED end"
	out, _ := r.Redact(input)

	if strings.Contains(out, "CARD_DATA_REDACTED_REDACTED") {
		t.Errorf("double-redaction of card placeholder: %s", out)
	}
}

// --- combined: multiple data types in one body ---

func TestCombined_MultipleTypesInOneBody(t *testing.T) {
	r := redaction.NewRedactor(redaction.Config{})
	input := "SSN 123-45-6789, card 4532015112830366, ICD-10 A10.1 all present"
	out, violations := r.Redact(input)

	if strings.Contains(out, "123-45-6789") {
		t.Error("SSN not redacted in combined test")
	}
	if strings.Contains(out, "4532015112830366") {
		t.Error("card not redacted in combined test")
	}
	if strings.Contains(out, "A10.1") {
		t.Error("ICD-10 code not redacted in combined test")
	}

	dataTypes := map[string]bool{}
	for _, v := range violations {
		dataTypes[v.DataType] = true
	}
	if !dataTypes["SSN"] {
		t.Error("expected SSN in violations")
	}
	if !dataTypes["PAYMENT_CARD"] {
		t.Error("expected PAYMENT_CARD in violations")
	}
	if !dataTypes["ICD10"] {
		t.Error("expected ICD10 in violations")
	}
}

// --- Luhn algorithm correctness ---

func TestLuhn_KnownValues(t *testing.T) {
	// These are standard test card numbers that pass Luhn
	validCards := []string{
		"4532015112830366", // Visa
		"5425233430109903", // Mastercard
		"378282246310005",  // Amex (15 digits, industry-standard test number)
		"6011000990139424", // Discover
	}

	r := redaction.NewRedactor(redaction.Config{})
	for _, card := range validCards {
		input := "number " + card + " end"
		out, _ := r.Redact(input)
		if strings.Contains(out, card) {
			t.Errorf("Luhn-valid card %s should have been redacted", card)
		}
	}
}
