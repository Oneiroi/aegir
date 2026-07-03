package sanitizer

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/aegishjalmur/aegir/internal/config"
	"github.com/aegishjalmur/aegir/internal/logging"
)

type compiledPattern struct {
	re       *regexp.Regexp
	severity string
}

// ComplianceManager handles compliance-specific data detection and redaction
type ComplianceManager struct {
	config      config.Compliance
	logger      *logging.Logger
	piiPatterns map[string]compiledPattern
	phiPatterns map[string]compiledPattern
	pciPatterns map[string]compiledPattern
	digitRe     *regexp.Regexp
}

// ComplianceResult contains compliance scanning results
type ComplianceResult struct {
	PIIDetections  []Detection `json:"pii_detections"`
	PHIDetections  []Detection `json:"phi_detections"`
	PCIDetections  []Detection `json:"pci_detections"`
	Sanitized      string      `json:"sanitized"`
	ComplianceRisk string      `json:"compliance_risk"`
	Violations     []Violation `json:"violations"`
}

// Violation represents a compliance violation
type Violation struct {
	Type        string `json:"type"`
	Regulation  string `json:"regulation"`
	Severity    string `json:"severity"`
	Description string `json:"description"`
	Pattern     string `json:"pattern"`
	Position    int    `json:"position"`
}

// NewComplianceManager creates a new compliance manager
func NewComplianceManager(config config.Compliance, logger *logging.Logger) *ComplianceManager {
	cm := &ComplianceManager{
		config: config,
		logger: logger,
	}
	cm.initializePatterns()
	return cm
}

// ScanForCompliance scans content for compliance violations
func (cm *ComplianceManager) ScanForCompliance(content string) *ComplianceResult {
	result := &ComplianceResult{
		Sanitized:      content,
		ComplianceRisk: "low",
		PIIDetections:  []Detection{},
		PHIDetections:  []Detection{},
		PCIDetections:  []Detection{},
		Violations:     []Violation{},
	}

	// PCI DSS Card Data Detection — must run before PII so card numbers
	// aren't partially consumed by phone/SSN patterns first
	if cm.config.PCI.Enabled && cm.config.PCI.CardDetection {
		result = cm.detectPCI(result)
	}

	// HIPAA PHI Detection
	if cm.config.HIPAA.Enabled && cm.config.HIPAA.PHIDetection {
		result = cm.detectPHI(result)
	}

	// GDPR/CCPA PII Detection
	if cm.config.GDPR.Enabled && cm.config.GDPR.PIIDetection {
		result = cm.detectPII(result)
	}

	// Calculate compliance risk
	result.ComplianceRisk = cm.calculateComplianceRisk(result)

	// Log compliance events
	if len(result.PIIDetections) > 0 || len(result.PHIDetections) > 0 || len(result.PCIDetections) > 0 {
		cm.logComplianceEvent(result)
	}

	return result
}

// detectPII detects Personally Identifiable Information for GDPR/CCPA compliance
func (cm *ComplianceManager) detectPII(result *ComplianceResult) *ComplianceResult {
	content := result.Sanitized

	for patternName, cp := range cm.piiPatterns {
		matches := cp.re.FindAllStringIndex(content, -1)

		for _, match := range matches {
			detection := Detection{
				Type:        "pii_" + patternName,
				Pattern:     patternName,
				Replacement: "PII_REDACTED",
				Position:    match[0],
				Severity:    cp.severity,
			}
			result.PIIDetections = append(result.PIIDetections, detection)

			violation := Violation{
				Type:        "pii",
				Regulation:  "GDPR/CCPA",
				Severity:    cp.severity,
				Description: "Personally Identifiable Information detected: " + patternName,
				Pattern:     patternName,
				Position:    match[0],
			}
			result.Violations = append(result.Violations, violation)
		}

		content = cp.re.ReplaceAllString(content, "PII_REDACTED")
	}

	result.Sanitized = content
	return result
}

// detectPHI detects Protected Health Information for HIPAA compliance
func (cm *ComplianceManager) detectPHI(result *ComplianceResult) *ComplianceResult {
	content := result.Sanitized

	for patternName, cp := range cm.phiPatterns {
		matches := cp.re.FindAllStringIndex(content, -1)

		for _, match := range matches {
			detection := Detection{
				Type:        "phi_" + patternName,
				Pattern:     patternName,
				Replacement: "PHI_REDACTED",
				Position:    match[0],
				Severity:    cp.severity,
			}
			result.PHIDetections = append(result.PHIDetections, detection)

			violation := Violation{
				Type:        "phi",
				Regulation:  "HIPAA",
				Severity:    cp.severity,
				Description: "Protected Health Information detected: " + patternName,
				Pattern:     patternName,
				Position:    match[0],
			}
			result.Violations = append(result.Violations, violation)
		}

		content = cp.re.ReplaceAllString(content, "PHI_REDACTED")
	}

	result.Sanitized = content
	return result
}

// detectPCI detects Payment Card Industry data for PCI DSS compliance
func (cm *ComplianceManager) detectPCI(result *ComplianceResult) *ComplianceResult {
	content := result.Sanitized

	for patternName, cp := range cm.pciPatterns {
		matches := cp.re.FindAllStringIndex(content, -1)

		for _, match := range matches {
			detection := Detection{
				Type:        "pci_" + patternName,
				Pattern:     patternName,
				Replacement: "CARD_DATA_REDACTED",
				Position:    match[0],
				Severity:    cp.severity,
			}
			result.PCIDetections = append(result.PCIDetections, detection)

			violation := Violation{
				Type:        "pci",
				Regulation:  "PCI DSS",
				Severity:    cp.severity,
				Description: "Payment card data detected: " + patternName,
				Pattern:     patternName,
				Position:    match[0],
			}
			result.Violations = append(result.Violations, violation)
		}

		if cm.config.PCI.TokenizeCards {
			content = cp.re.ReplaceAllStringFunc(content, func(match string) string {
				return cm.tokenizeCardData(match)
			})
		} else {
			content = cp.re.ReplaceAllString(content, "CARD_DATA_REDACTED")
		}
	}

	result.Sanitized = content
	return result
}

// isValidCreditCard validates credit card number using Luhn algorithm
func (cm *ComplianceManager) isValidCreditCard(cardNumber string) bool {
	cardNumber = cm.digitRe.ReplaceAllString(cardNumber, "")

	if len(cardNumber) < 13 || len(cardNumber) > 19 {
		return false
	}

	sum := 0
	alternate := false

	for i := len(cardNumber) - 1; i >= 0; i-- {
		digit := int(cardNumber[i] - '0')
		if alternate {
			digit *= 2
			if digit > 9 {
				digit = (digit % 10) + 1
			}
		}
		sum += digit
		alternate = !alternate
	}

	return sum%10 == 0
}

// tokenizeCardData creates a format-preserving token for card data. Retaining
// the last four digits is opt-in (PCI.TokenizeCards) and is explicitly permitted
// by PCI DSS for display/reconciliation. The default redaction path (AEGIR-L-004)
// emits the fully-opaque CARD_DATA_REDACTED marker instead.
func (cm *ComplianceManager) tokenizeCardData(cardNumber string) string {
	digits := cm.digitRe.FindAllString(cardNumber, -1)
	if len(digits) < 4 {
		return "XXXX-XXXX-XXXX-XXXX"
	}
	last4 := strings.Join(digits[len(digits)-4:], "")
	return fmt.Sprintf("XXXX-XXXX-XXXX-%s", last4)
}

// calculateComplianceRisk determines overall compliance risk level
func (cm *ComplianceManager) calculateComplianceRisk(result *ComplianceResult) string {
	totalViolations := len(result.PIIDetections) + len(result.PHIDetections) + len(result.PCIDetections)

	if totalViolations == 0 {
		return "low"
	}

	criticalCount := 0
	highCount := 0

	for _, violation := range result.Violations {
		switch violation.Severity {
		case "critical":
			criticalCount++
		case "high":
			highCount++
		}
	}

	if criticalCount > 0 {
		return "critical"
	}
	if highCount > 2 {
		return "high"
	}
	if totalViolations > 5 {
		return "medium"
	}
	return "low"
}

// logComplianceEvent logs compliance-related security events
func (cm *ComplianceManager) logComplianceEvent(result *ComplianceResult) {
	event := &logging.SecurityEvent{
		Type:      "compliance_violation",
		Severity:  result.ComplianceRisk,
		Message:   "Compliance data detected in content",
		Timestamp: time.Now(),
		Details: map[string]string{
			"pii_detections": strconv.Itoa(len(result.PIIDetections)),
			"phi_detections": strconv.Itoa(len(result.PHIDetections)),
			"pci_detections": strconv.Itoa(len(result.PCIDetections)),
			"risk_level":     result.ComplianceRisk,
		},
	}

	cm.logger.LogSecurityEvent(event)
}

// initializePatterns precompiles all regex patterns at construction time
func (cm *ComplianceManager) initializePatterns() {
	cm.digitRe = regexp.MustCompile(`\D`)

	cm.piiPatterns = map[string]compiledPattern{
		"ssn": {
			re:       regexp.MustCompile(`\b(?:\d{3}[-\s]\d{2}[-\s]\d{4}|\d{9})\b`),
			severity: "high",
		},
		"email": {
			re:       regexp.MustCompile(`\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b`),
			severity: "medium",
		},
		"phone": {
			re:       regexp.MustCompile(`\b(?:\+?1[-.\s]?)?\(?([0-9]{3})\)?[-.\s]?([0-9]{3})[-.\s]?([0-9]{4})\b`),
			severity: "medium",
		},
		"phone_intl": {
			re:       regexp.MustCompile(`\+\d{1,3}[\s.-](?:\d[\s.-]?){5,14}\d`),
			severity: "medium",
		},
		"ip_address": {
			re:       regexp.MustCompile(`\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b`),
			severity: "low",
		},
		"ipv6_address": {
			re:       regexp.MustCompile(`\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b`),
			severity: "low",
		},
		"address": {
			re:       regexp.MustCompile(`\b\d+\s+[A-Za-z0-9\s,.-]+(?:Street|St|Avenue|Ave|Road|Rd|Drive|Dr|Lane|Ln|Boulevard|Blvd|Way)\b`),
			severity: "medium",
		},
		"passport": {
			re:       regexp.MustCompile(`\b(?:[A-Z]{1,2}[0-9]{6,9}|[0-9]{9}[A-Z]{2})\b`),
			severity: "high",
		},
		"drivers_license": {
			re:       regexp.MustCompile(`\b[A-Z]{1,2}[0-9]{6,8}\b`),
			severity: "high",
		},
	}

	cm.phiPatterns = map[string]compiledPattern{
		"mrn": {
			re:       regexp.MustCompile(`(?i)\b(?:MRN|Medical Record|Patient ID)[\s:]+([A-Z0-9]{6,12})\b`),
			severity: "critical",
		},
		"health_plan": {
			re:       regexp.MustCompile(`(?i)\b(?:Health Plan|Insurance|Policy)[\s#:]+([A-Z0-9]{8,15})\b`),
			severity: "high",
		},
		"diagnosis_code": {
			re:       regexp.MustCompile(`(?i)\b[A-Z]\d{2}(?:\.\d{1,4})?\b`),
			severity: "high",
		},
		"medicare_id": {
			re:       regexp.MustCompile(`(?i)\b\d[A-Z0-9]{3}-[A-Z0-9]{2}\d-[A-Z0-9]{2}\d{2}\b`),
			severity: "critical",
		},
		"genetic_info": {
			re:       regexp.MustCompile(`(?i)\b(?:BRCA[12]|TP53|KRAS|EGFR|ALK|BRAF|HER2|MLH1|MSH2)\b.*?(?:mutation|variant|deletion|insertion|c\.\d)`),
			severity: "critical",
		},
		"health_condition_phi": {
			re:       regexp.MustCompile(`(?i)\b(?:patient|diagnosed|diagnosis)\b.{0,50}\b(?:cancer|tumor|diabetes|hypertension|HIV|AIDS|hepatitis|dementia|schizophrenia|chemotherapy|radiation therapy)\b`),
			severity: "high",
		},
		"dob_phi": {
			re:       regexp.MustCompile(`(?i)\b(?:DOB|Date of Birth)[\s:]+(\d{1,2}[/-]\d{1,2}[/-]\d{4})\b`),
			severity: "high",
		},
		"biometric": {
			re:       regexp.MustCompile(`(?i)\b(?:fingerprint|retina|DNA|biometric)[\s:]+([A-Z0-9]+)\b`),
			severity: "critical",
		},
		"device_identifier": {
			re:       regexp.MustCompile(`(?i)\b(?:device|implant|serial)(?:\s+\w+)?[\s#:]+([A-Z0-9]{8,20})\b`),
			severity: "medium",
		},
	}

	cm.pciPatterns = map[string]compiledPattern{
		"visa": {
			re:       regexp.MustCompile(`(?i)\b4[0-9]{3}(?:[-\s]?[0-9]{4}){3}\b`),
			severity: "critical",
		},
		"mastercard": {
			re:       regexp.MustCompile(`(?i)\b5[1-5][0-9]{2}(?:[-\s]?[0-9]{4}){3}\b`),
			severity: "critical",
		},
		"amex": {
			re:       regexp.MustCompile(`(?i)\b3[47][0-9]{2}[-\s]?[0-9]{6}[-\s]?[0-9]{5}\b`),
			severity: "critical",
		},
		"discover": {
			re:       regexp.MustCompile(`(?i)\b6(?:011|5[0-9]{2})[-\s]?(?:[0-9]{4}[-\s]?){2}[0-9]{4}\b`),
			severity: "critical",
		},
		"pan_masked": {
			re:       regexp.MustCompile(`(?i)[*Xx]{4}[-\s][*Xx]{4}[-\s][*Xx]{4}[-\s][0-9]{4}`),
			severity: "critical",
		},
		"cvv": {
			re:       regexp.MustCompile(`(?i)\b(?:CVV|CVC|CSC|CID)[\s:]*([0-9]{3,4})\b`),
			severity: "critical",
		},
		"exp_date": {
			re:       regexp.MustCompile(`(?i)\b(?:exp|expir)[\w\s]*:?\s*(\d{1,2}[/-]\d{2,4})\b`),
			severity: "high",
		},
		"cardholder": {
			re:       regexp.MustCompile(`(?i)\b(?:cardholder|card holder)[\s:]+([A-Z\s]{5,30})\b`),
			severity: "medium",
		},
		"track_data": {
			re:       regexp.MustCompile(`(?i)%[A-Z]?\d{13,19}\^[A-Z\s\/]{2,26}\^\d{4}`),
			severity: "critical",
		},
	}
}
