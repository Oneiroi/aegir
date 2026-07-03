package sanitizer

import (
	"strings"
	"testing"

	"github.com/aegishjalmur/aegir/internal/config"
	"github.com/aegishjalmur/aegir/internal/logging"
)

// TestGDPRCompliancePayloads tests GDPR PII detection with real-world data patterns
func TestGDPRCompliancePayloads(t *testing.T) {
	manager := createTestComplianceManager()

	testCases := []struct {
		name        string
		payload     string
		expectBlock bool
		description string
	}{
		// Social Security Numbers (various formats)
		{
			"ssn_standard",
			"My SSN is 123-45-6789 for verification",
			true,
			"Standard SSN format with dashes",
		},
		{
			"ssn_no_dashes",
			"Social Security Number: 123456789",
			true,
			"SSN without dashes",
		},
		{
			"ssn_spaces",
			"SSN 123 45 6789 on file",
			true,
			"SSN with spaces",
		},

		// Email addresses (PII under GDPR)
		{
			"email_standard",
			"Contact me at john.doe@example.com for details",
			true,
			"Standard email format",
		},
		{
			"email_subdomain",
			"Email: user.name+tag@mail.subdomain.example.org",
			true,
			"Complex email with subdomain and plus addressing",
		},

		// Phone numbers (international formats)
		{
			"phone_us_standard",
			"Call me at (555) 123-4567 tomorrow",
			true,
			"US phone number with parentheses",
		},
		{
			"phone_international",
			"International number: +44 20 7946 0958",
			true,
			"UK international phone number",
		},
		{
			"phone_no_formatting",
			"Phone: 5551234567",
			true,
			"Phone number without formatting",
		},

		// Physical addresses
		{
			"address_full",
			"Ship to: 123 Main Street, Apt 4B, New York, NY 10001",
			true,
			"Full US address with apartment",
		},
		{
			"address_uk",
			"Address: 10 Downing Street, London SW1A 2AA, UK",
			true,
			"UK address with postcode",
		},

		// IP addresses (can be PII in some contexts)
		{
			"ipv4_address",
			"User connecting from IP 192.168.1.100",
			true,
			"IPv4 address",
		},
		{
			"ipv6_address",
			"IPv6 address: 2001:0db8:85a3:0000:0000:8a2e:0370:7334",
			true,
			"IPv6 address",
		},

		// Driver's License Numbers
		{
			"drivers_license_ca",
			"CA License: A1234567",
			true,
			"California driver's license format",
		},
		{
			"drivers_license_ny",
			"NY DL: 123456789",
			true,
			"New York driver's license format",
		},

		// Passport numbers
		{
			"passport_us",
			"US Passport: 123456789",
			true,
			"US passport number",
		},
		{
			"passport_uk",
			"Passport number: 123456789UK",
			true,
			"UK passport number",
		},

		// Safe content (should not be blocked)
		{
			"safe_general_info",
			"The company has 123 employees in 45 offices across 6 countries",
			false,
			"General business information with numbers",
		},
		{
			"safe_technical",
			"Server configuration: port 8080, timeout 30 seconds",
			false,
			"Technical configuration information",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := manager.ScanForCompliance(tc.payload)

			if tc.expectBlock {
				if len(result.PIIDetections) == 0 && len(result.Violations) == 0 {
					t.Errorf("Expected GDPR violation for: %s", tc.description)
				}

				// Verify PII was redacted
				if result.Sanitized == tc.payload {
					t.Errorf("Expected PII to be redacted for: %s", tc.description)
				}

				// Check for redaction markers
				if !strings.Contains(result.Sanitized, "PII_REDACTED") &&
				   !strings.Contains(result.Sanitized, "REDACTED") {
					t.Errorf("Expected redaction marker in: %s", tc.description)
				}

				t.Logf("✅ GDPR: Successfully detected and redacted PII in %s", tc.description)
			} else {
				// For safe content, should have minimal PII detections
				if len(result.PIIDetections) > 0 {
					t.Errorf("False positive PII detection for safe content: %s", tc.description)
				}
				t.Logf("✅ GDPR: Safe content correctly allowed: %s", tc.description)
			}
		})
	}
}

// TestHIPAACompliancePayloads tests HIPAA PHI detection
func TestHIPAACompliancePayloads(t *testing.T) {
	manager := createTestComplianceManager()

	testCases := []struct {
		name        string
		payload     string
		expectBlock bool
		description string
	}{
		// Medical Record Numbers
		{
			"mrn_standard",
			"Patient MRN: MR123456789",
			true,
			"Standard Medical Record Number",
		},
		{
			"mrn_hospital",
			"Hospital ID: H-987654321",
			true,
			"Hospital Medical Record format",
		},

		// Health Plan Numbers
		{
			"health_plan_id",
			"Insurance ID: HP123456789",
			true,
			"Health plan identifier",
		},
		{
			"medicare_number",
			"Medicare: 1EG4-TE5-MK73",
			true,
			"Medicare Beneficiary Identifier",
		},

		// ICD-10 Diagnosis Codes
		{
			"icd10_diabetes",
			"Diagnosis: E11.9 Type 2 diabetes mellitus without complications",
			true,
			"ICD-10 diabetes diagnosis code",
		},
		{
			"icd10_hypertension",
			"Patient has I10 Essential hypertension",
			true,
			"ICD-10 hypertension code",
		},
		{
			"icd10_covid",
			"COVID-19 diagnosis: U07.1",
			true,
			"ICD-10 COVID-19 diagnosis",
		},

		// Biometric identifiers
		{
			"biometric_fingerprint",
			"Fingerprint hash: A1B2C3D4E5F6789",
			true,
			"Biometric fingerprint identifier",
		},

		// Device identifiers in medical context
		{
			"medical_device_id",
			"Pacemaker serial: PM123456789",
			true,
			"Medical device identifier",
		},
		{
			"implant_id",
			"Implant ID: IMP987654321",
			true,
			"Medical implant identifier",
		},

		// Genetic information
		{
			"genetic_marker",
			"BRCA1 gene mutation detected: c.68_69delAG",
			true,
			"Genetic information (BRCA1)",
		},

		// Health condition information
		{
			"health_condition",
			"Patient diagnosed with stage 3 breast cancer, receiving chemotherapy",
			true,
			"Specific health condition information",
		},

		// Safe medical content (general, non-identifying)
		{
			"safe_medical_general",
			"Diabetes is a common condition affecting millions worldwide",
			false,
			"General medical information",
		},
		{
			"safe_health_tips",
			"Regular exercise and healthy diet can prevent many diseases",
			false,
			"General health advice",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := manager.ScanForCompliance(tc.payload)

			if tc.expectBlock {
				if len(result.PHIDetections) == 0 && len(result.Violations) == 0 {
					t.Errorf("Expected HIPAA violation for: %s", tc.description)
				}

				// Verify PHI was redacted
				if result.Sanitized == tc.payload {
					t.Errorf("Expected PHI to be redacted for: %s", tc.description)
				}

				// Check for redaction markers
				if !strings.Contains(result.Sanitized, "PHI_REDACTED") &&
				   !strings.Contains(result.Sanitized, "REDACTED") {
					t.Errorf("Expected redaction marker in: %s", tc.description)
				}

				t.Logf("✅ HIPAA: Successfully detected and redacted PHI in %s", tc.description)
			} else {
				if len(result.PHIDetections) > 0 {
					t.Errorf("False positive PHI detection for safe content: %s", tc.description)
				}
				t.Logf("✅ HIPAA: Safe content correctly allowed: %s", tc.description)
			}
		})
	}
}

// TestPCIDSSCompliancePayloads tests PCI DSS cardholder data detection
func TestPCIDSSCompliancePayloads(t *testing.T) {
	manager := createTestComplianceManager()

	testCases := []struct {
		name        string
		payload     string
		expectBlock bool
		description string
	}{
		// Credit card numbers (various formats and types)
		{
			"visa_standard",
			"Visa card: 4111-1111-1111-1111",
			true,
			"Standard Visa card format with dashes",
		},
		{
			"visa_no_dashes",
			"Card number 4111111111111111",
			true,
			"Visa card without formatting",
		},
		{
			"mastercard",
			"MasterCard: 5555-5555-5555-4444",
			true,
			"MasterCard with dashes",
		},
		{
			"amex",
			"American Express: 3782-822463-10005",
			true,
			"American Express format",
		},
		{
			"discover",
			"Discover card: 6011-1111-1111-1117",
			true,
			"Discover card format",
		},

		// CVV/CVC codes
		{
			"cvv_three_digit",
			"CVV: 123",
			true,
			"Three-digit CVV code",
		},
		{
			"cvc_four_digit",
			"CVC 1234",
			true,
			"Four-digit CVC code (Amex)",
		},

		// Expiration dates in card context
		{
			"expiry_mmyy",
			"Card expires 12/25",
			true,
			"Card expiration MM/YY format",
		},
		{
			"expiry_mmyyyy",
			"Expiration: 12/2025",
			true,
			"Card expiration MM/YYYY format",
		},

		// Cardholder names
		{
			"cardholder_name",
			"Card holder: JOHN DOE",
			true,
			"Cardholder name on card",
		},

		// Track data (magnetic stripe)
		{
			"track1_data",
			"%B4111111111111111^DOE/JOHN^25121019999888777766?",
			true,
			"Track 1 magnetic stripe data",
		},
		{
			"track2_data",
			";4111111111111111=25121019999888777766?",
			true,
			"Track 2 magnetic stripe data",
		},

		// PAN (Primary Account Number) in various contexts
		{
			"pan_masked",
			"Card ending in 1111 (****-****-****-1111)",
			true,
			"Partially masked PAN",
		},

		// Combined cardholder data
		{
			"full_card_info",
			"Name: JOHN DOE, Card: 4111-1111-1111-1111, Exp: 12/25, CVV: 123",
			true,
			"Complete cardholder data set",
		},

		// Invalid/test card numbers (should still be detected for safety)
		{
			"test_card_luhn_invalid",
			"Test card: 4111-1111-1111-1112",
			true,
			"Invalid Luhn checksum (still sensitive format)",
		},

		// Safe content with numbers
		{
			"safe_order_number",
			"Order number: ORD123456789",
			false,
			"Order tracking number",
		},
		{
			"safe_phone_number",
			"Customer service: 1-800-555-1234",
			false,
			"Customer service phone number",
		},
		{
			"safe_product_code",
			"Product SKU: 4111-WIDGET-1111",
			false,
			"Product code that looks like card format",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := manager.ScanForCompliance(tc.payload)

			if tc.expectBlock {
				if len(result.PCIDetections) == 0 && len(result.Violations) == 0 {
					t.Errorf("Expected PCI DSS violation for: %s", tc.description)
				}

				// Verify cardholder data was redacted
				if result.Sanitized == tc.payload {
					t.Errorf("Expected cardholder data to be redacted for: %s", tc.description)
				}

				// Check for redaction markers
				if !strings.Contains(result.Sanitized, "CARD_REDACTED") &&
				   !strings.Contains(result.Sanitized, "CVV_REDACTED") &&
				   !strings.Contains(result.Sanitized, "REDACTED") &&
					   !strings.Contains(result.Sanitized, "XXXX-XXXX") {
					t.Errorf("Expected redaction marker in: %s", tc.description)
				}

				t.Logf("✅ PCI DSS: Successfully detected and redacted cardholder data in %s", tc.description)
			} else {
				if len(result.PCIDetections) > 0 {
					t.Errorf("False positive PCI DSS detection for safe content: %s", tc.description)
				}
				t.Logf("✅ PCI DSS: Safe content correctly allowed: %s", tc.description)
			}
		})
	}
}

// TestMultiFrameworkCompliance tests content that violates multiple frameworks
func TestMultiFrameworkCompliance(t *testing.T) {
	manager := createTestComplianceManager()

	payload := "Patient John Doe (SSN: 123-45-6789, john.doe@email.com) paid with card 4111-1111-1111-1111, CVV 123, for medical procedure ICD-10: Z51.1"

	result := manager.ScanForCompliance(payload)

	// Check for detections across multiple compliance areas
	totalDetections := len(result.PIIDetections) + len(result.PHIDetections) + len(result.PCIDetections)

	if totalDetections == 0 {
		t.Errorf("Expected multi-framework detections for comprehensive violation")
	}

	// Verify comprehensive redaction
	if result.Sanitized == payload {
		t.Errorf("Expected comprehensive redaction for multi-framework violation")
	}

	if totalDetections >= 3 {
		t.Logf("✅ Multi-framework: Successfully detected %d violations across multiple frameworks", totalDetections)
	}
}

// TestPartialRedactionCoverage exercises AEGIR-L-004 (ISC-160): the response
// compliance scan must catch SSNs that are (a) reassembled across a
// chunk/stream boundary with a stray artifact separator, or (b) already
// partially masked (some digit groups replaced with X/x/* while others
// remain real digits) — neither case may be waved through as if the value
// were either unrecognisable or already fully redacted.
func TestPartialRedactionCoverage(t *testing.T) {
	manager := createTestComplianceManager()

	testCases := []struct {
		name        string
		payload     string
		expectBlock bool
		description string
	}{
		// --- Split across a chunk/stream boundary ---
		{
			"ssn_split_zero_width_space",
			"SSN on file: 123-45-​6789 for verification",
			true,
			"SSN with a zero-width space stitched in at the second separator, " +
				"as if reassembled from two response chunks",
		},
		{
			"ssn_split_extra_newlines",
			"SSN on file: 123-45-\n\n6789 for verification",
			true,
			"SSN with stray extra newlines at the chunk boundary",
		},
		{
			"ssn_split_repeated_whitespace_first_group",
			"SSN on file: 123   45-6789 for verification",
			true,
			"SSN with repeated whitespace at the first separator (boundary corruption)",
		},

		// --- Already partially masked ---
		{
			"ssn_partial_masked_first_groups",
			"SSN on file: XXX-XX-6789 for verification",
			true,
			"SSN with the area/group numbers masked but the serial number exposed",
		},
		{
			"ssn_partial_masked_last_group",
			"SSN on file: 123-45-XXXX for verification",
			true,
			"SSN with the serial number masked but the area/group numbers exposed",
		},
		{
			"ssn_partial_masked_asterisks",
			"SSN on file: ***-**-6789 for verification",
			true,
			"SSN partially masked with asterisks instead of X characters",
		},

		// --- Must NOT flag a value that is genuinely fully redacted ---
		{
			"ssn_fully_masked_not_a_finding",
			"SSN on file: XXX-XX-XXXX for verification",
			false,
			"Fully masked SSN placeholder — nothing left to expose, not a new finding",
		},

		// --- Ordinary well-formed SSN must not be double-counted ---
		{
			"ssn_normal_single_violation",
			"SSN on file: 123-45-6789 for verification",
			true,
			"Normal single-separator SSN — sanity check that the new patterns " +
				"do not change existing single-separator detection",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := manager.ScanForCompliance(tc.payload)

			if tc.expectBlock {
				if len(result.PIIDetections) == 0 && len(result.Violations) == 0 {
					t.Fatalf("expected a PII violation for: %s (payload %q)", tc.description, tc.payload)
				}
				if result.Sanitized == tc.payload {
					t.Errorf("expected redaction for: %s", tc.description)
				}
				if !strings.Contains(result.Sanitized, "PII_REDACTED") {
					t.Errorf("expected PII_REDACTED marker in sanitized output for: %s (got %q)",
						tc.description, result.Sanitized)
				}
			} else {
				if len(result.PIIDetections) > 0 {
					t.Errorf("unexpected PII detection for genuinely-redacted content: %s (detections: %+v)",
						tc.description, result.PIIDetections)
				}
				if result.Sanitized != tc.payload {
					t.Errorf("genuinely-redacted content should pass through unchanged: %s", tc.description)
				}
			}
		})
	}

	// The single-separator sanity case must produce exactly one SSN-shaped
	// detection — the new split-boundary/partial-mask patterns must not
	// double-fire against an ordinary, already-well-handled SSN.
	t.Run("ssn_normal_produces_single_detection", func(t *testing.T) {
		result := manager.ScanForCompliance("SSN on file: 123-45-6789 for verification")
		ssnLike := 0
		for _, d := range result.PIIDetections {
			if strings.HasPrefix(d.Pattern, "ssn") {
				ssnLike++
			}
		}
		if ssnLike != 1 {
			t.Errorf("ssn-shaped detections for a normal single-separator SSN = %d, want 1", ssnLike)
		}
	})
}

func createTestComplianceManager() *ComplianceManager {
	cfg := config.Compliance{
		GDPR: config.GDPRConfig{
			Enabled:         true,
			PIIDetection:    true,
			RightToErasure:  true,
			DataPortability: true,
			ConsentTracking: true,
			Region:          "EU",
		},
		HIPAA: config.HIPAAConfig{
			Enabled:      true,
			PHIDetection: true,
			Encryption:   true,
			AuditTrail:   true,
		},
		PCI: config.PCIConfig{
			Enabled:        true,
			CardDetection:  true,
			TokenizeCards:  true,
			EncryptStorage: true,
		},
	}

	logCfg := config.Logging{
		Level:           "info",
		Format:          "json",
		HMACKey:         "test-hmac-key-32-characters-long",
		IntegrityChecks: true,
	}

	logger, _ := logging.New(logCfg)
	return NewComplianceManager(cfg, logger)
}