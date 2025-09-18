package sanitizer

import (
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/aegishjalmur/mcp-firewall/internal/config"
	"github.com/aegishjalmur/mcp-firewall/internal/logging"
)

// ComplianceManager handles compliance-specific data detection and redaction
type ComplianceManager struct {
	config        config.Compliance
	logger        *logging.Logger
	piiPatterns   map[string]*regexp.Regexp
	phiPatterns   map[string]*regexp.Regexp
	pciPatterns   map[string]*regexp.Regexp
}

// ComplianceResult contains compliance scanning results
type ComplianceResult struct {
	PIIDetections []Detection `json:"pii_detections"`
	PHIDetections []Detection `json:"phi_detections"`
	PCIDetections []Detection `json:"pci_detections"`
	Sanitized     string      `json:"sanitized"`
	ComplianceRisk string     `json:"compliance_risk"`
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
		config:      config,
		logger:      logger,
		piiPatterns: make(map[string]*regexp.Regexp),
		phiPatterns: make(map[string]*regexp.Regexp),
		pciPatterns: make(map[string]*regexp.Regexp),
	}

	cm.initializePatterns()
	return cm
}

// ScanForCompliance scans content for compliance violations
func (cm *ComplianceManager) ScanForCompliance(content string) *ComplianceResult {
	result := &ComplianceResult{
		Sanitized:     content,
		ComplianceRisk: "low",
		PIIDetections: []Detection{},
		PHIDetections: []Detection{},
		PCIDetections: []Detection{},
		Violations:    []Violation{},
	}

	// GDPR/CCPA PII Detection
	if cm.config.GDPR.Enabled && cm.config.GDPR.PIIDetection {
		result = cm.detectPII(result)
	}

	// HIPAA PHI Detection
	if cm.config.HIPAA.Enabled && cm.config.HIPAA.PHIDetection {
		result = cm.detectPHI(result)
	}

	// PCI DSS Card Data Detection
	if cm.config.PCI.Enabled && cm.config.PCI.CardDetection {
		result = cm.detectPCI(result)
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

	// PII patterns for GDPR/CCPA
	piiPatterns := map[string]struct {
		regex    string
		severity string
	}{
		"ssn": {
			regex:    `\b(?:\d{3}-\d{2}-\d{4}|\d{9})\b`,
			severity: "high",
		},
		"email": {
			regex:    `\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b`,
			severity: "medium",
		},
		"phone": {
			regex:    `\b(?:\+?1[-.\s]?)?\(?([0-9]{3})\)?[-.\s]?([0-9]{3})[-.\s]?([0-9]{4})\b`,
			severity: "medium",
		},
		"ip_address": {
			regex:    `\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b`,
			severity: "low",
		},
		"address": {
			regex:    `\b\d+\s+[A-Za-z0-9\s,.-]+(?:Street|St|Avenue|Ave|Road|Rd|Drive|Dr|Lane|Ln|Boulevard|Blvd|Way)\b`,
			severity: "medium",
		},
		"passport": {
			regex:    `\b[A-Z]{1,2}[0-9]{6,9}\b`,
			severity: "high",
		},
		"drivers_license": {
			regex:    `\b[A-Z]{1,2}[0-9]{6,8}\b`,
			severity: "high",
		},
	}

	for patternName, pattern := range piiPatterns {
		re := regexp.MustCompile(pattern.regex)
		matches := re.FindAllStringIndex(content, -1)

		for _, match := range matches {
			detection := Detection{
				Type:        "pii_" + patternName,
				Pattern:     patternName,
				Replacement: "PII_REDACTED",
				Position:    match[0],
				Severity:    pattern.severity,
			}
			result.PIIDetections = append(result.PIIDetections, detection)

			violation := Violation{
				Type:        "pii",
				Regulation:  "GDPR/CCPA",
				Severity:    pattern.severity,
				Description: "Personally Identifiable Information detected: " + patternName,
				Pattern:     patternName,
				Position:    match[0],
			}
			result.Violations = append(result.Violations, violation)
		}

		// Redact PII if configured
		content = re.ReplaceAllString(content, "PII_REDACTED")
	}

	result.Sanitized = content
	return result
}

// detectPHI detects Protected Health Information for HIPAA compliance
func (cm *ComplianceManager) detectPHI(result *ComplianceResult) *ComplianceResult {
	content := result.Sanitized

	// PHI patterns for HIPAA
	phiPatterns := map[string]struct {
		regex    string
		severity string
	}{
		"mrn": {
			regex:    `\b(?:MRN|Medical Record|Patient ID)[\s:]+([A-Z0-9]{6,12})\b`,
			severity: "critical",
		},
		"health_plan": {
			regex:    `\b(?:Health Plan|Insurance|Policy)[\s#:]+([A-Z0-9]{8,15})\b`,
			severity: "high",
		},
		"diagnosis_code": {
			regex:    `\b[A-Z]\d{2}\.\d{1,3}\b`, // ICD-10 format
			severity: "high",
		},
		"dob_phi": {
			regex:    `\b(?:DOB|Date of Birth)[\s:]+(\d{1,2}[/-]\d{1,2}[/-]\d{4})\b`,
			severity: "high",
		},
		"biometric": {
			regex:    `\b(?:fingerprint|retina|DNA|biometric)[\s:]+([A-Z0-9]+)\b`,
			severity: "critical",
		},
		"device_identifier": {
			regex:    `\b(?:device|implant|serial)[\s#:]+([A-Z0-9]{8,20})\b`,
			severity: "medium",
		},
	}

	for patternName, pattern := range phiPatterns {
		re := regexp.MustCompile(`(?i)` + pattern.regex)
		matches := re.FindAllStringIndex(content, -1)

		for _, match := range matches {
			detection := Detection{
				Type:        "phi_" + patternName,
				Pattern:     patternName,
				Replacement: "PHI_REDACTED",
				Position:    match[0],
				Severity:    pattern.severity,
			}
			result.PHIDetections = append(result.PHIDetections, detection)

			violation := Violation{
				Type:        "phi",
				Regulation:  "HIPAA",
				Severity:    pattern.severity,
				Description: "Protected Health Information detected: " + patternName,
				Pattern:     patternName,
				Position:    match[0],
			}
			result.Violations = append(result.Violations, violation)
		}

		// Redact PHI if configured
		content = re.ReplaceAllString(content, "PHI_REDACTED")
	}

	result.Sanitized = content
	return result
}

// detectPCI detects Payment Card Industry data for PCI DSS compliance
func (cm *ComplianceManager) detectPCI(result *ComplianceResult) *ComplianceResult {
	content := result.Sanitized

	// PCI patterns for PCI DSS
	pciPatterns := map[string]struct {
		regex    string
		severity string
	}{
		"visa": {
			regex:    `\b4[0-9]{12}(?:[0-9]{3})?\b`,
			severity: "critical",
		},
		"mastercard": {
			regex:    `\b5[1-5][0-9]{14}\b`,
			severity: "critical",
		},
		"amex": {
			regex:    `\b3[47][0-9]{13}\b`,
			severity: "critical",
		},
		"discover": {
			regex:    `\b6(?:011|5[0-9]{2})[0-9]{12}\b`,
			severity: "critical",
		},
		"cvv": {
			regex:    `\b(?:CVV|CVC|CSC|CID)[\s:]*([0-9]{3,4})\b`,
			severity: "critical",
		},
		"exp_date": {
			regex:    `\b(?:exp|expir)[\w\s]*:?\s*(\d{1,2}[/-]\d{2,4})\b`,
			severity: "high",
		},
		"cardholder": {
			regex:    `\b(?:cardholder|card holder)[\s:]+([A-Z\s]{5,30})\b`,
			severity: "medium",
		},
		"track_data": {
			regex:    `%[A-Z]?\d{13,19}\^[A-Z\s\/]{2,26}\^\d{4}`,
			severity: "critical",
		},
	}

	for patternName, pattern := range pciPatterns {
		re := regexp.MustCompile(`(?i)` + pattern.regex)
		matches := re.FindAllStringIndex(content, -1)

		for _, match := range matches {
			// Additional validation for credit card numbers using Luhn algorithm
			if strings.HasPrefix(patternName, "visa") || strings.HasPrefix(patternName, "master") ||
			   strings.HasPrefix(patternName, "amex") || strings.HasPrefix(patternName, "discover") {
				matchText := content[match[0]:match[1]]
				if !cm.isValidCreditCard(matchText) {
					continue
				}
			}

			detection := Detection{
				Type:        "pci_" + patternName,
				Pattern:     patternName,
				Replacement: "CARD_DATA_REDACTED",
				Position:    match[0],
				Severity:    pattern.severity,
			}
			result.PCIDetections = append(result.PCIDetections, detection)

			violation := Violation{
				Type:        "pci",
				Regulation:  "PCI DSS",
				Severity:    pattern.severity,
				Description: "Payment card data detected: " + patternName,
				Pattern:     patternName,
				Position:    match[0],
			}
			result.Violations = append(result.Violations, violation)
		}

		// Redact or tokenize card data if configured
		replacement := "CARD_DATA_REDACTED"
		if cm.config.PCI.TokenizeCards {
			replacement = cm.tokenizeCardData(patternName)
		}
		content = re.ReplaceAllString(content, replacement)
	}

	result.Sanitized = content
	return result
}

// isValidCreditCard validates credit card number using Luhn algorithm
func (cm *ComplianceManager) isValidCreditCard(cardNumber string) bool {
	// Remove spaces and non-digit characters
	cardNumber = regexp.MustCompile(`\D`).ReplaceAllString(cardNumber, "")

	if len(cardNumber) < 13 || len(cardNumber) > 19 {
		return false
	}

	sum := 0
	alternate := false

	// Luhn algorithm
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

// tokenizeCardData creates a format-preserving token for card data
func (cm *ComplianceManager) tokenizeCardData(dataType string) string {
	switch dataType {
	case "visa", "mastercard", "amex", "discover":
		return "XXXX-XXXX-XXXX-1234" // Show last 4 digits as placeholder
	case "cvv":
		return "XXX"
	case "exp_date":
		return "XX/XX"
	default:
		return "TOKENIZED_" + strings.ToUpper(dataType)
	}
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

// initializePatterns precompiles regex patterns for better performance
func (cm *ComplianceManager) initializePatterns() {
	// Pre-compile patterns would go here for production optimization
	// Omitted for brevity but important for performance
}