package sanitizer

import (
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/aegishjalmur/mcp-firewall/internal/config"
	"github.com/aegishjalmur/mcp-firewall/internal/logging"
)

// Manager handles content sanitization and security filtering
type Manager struct {
	config              config.Security
	logger              *logging.Logger
	commandInjectionRe  []*regexp.Regexp
	secretPatterns      []*regexp.Regexp
	piiPatterns         []*regexp.Regexp
	phiPatterns         []*regexp.Regexp
	pciPatterns         []*regexp.Regexp
	homoglyphPatterns   []*regexp.Regexp
	xssPatterns         []*regexp.Regexp
	sqlInjectionPatterns []*regexp.Regexp
}

// SanitizationResult contains the result of content sanitization
type SanitizationResult struct {
	Original        string            `json:"original"`
	Sanitized       string            `json:"sanitized"`
	Detections      []Detection       `json:"detections"`
	Risk            string            `json:"risk"`
	Blocked         bool              `json:"blocked"`
	Metadata        map[string]string `json:"metadata"`
}

// Detection represents a detected security issue
type Detection struct {
	Type        string `json:"type"`
	Pattern     string `json:"pattern"`
	Replacement string `json:"replacement"`
	Position    int    `json:"position"`
	Severity    string `json:"severity"`
}

// New creates a new sanitizer manager
func New(config config.Security, logger *logging.Logger) *Manager {
	m := &Manager{
		config: config,
		logger: logger,
	}

	m.initializePatterns()
	return m
}

// SanitizeContent sanitizes content based on configured security policies
func (m *Manager) SanitizeContent(content string) *SanitizationResult {
	result := &SanitizationResult{
		Original:   content,
		Sanitized:  content,
		Detections: []Detection{},
		Risk:       "low",
		Blocked:    false,
		Metadata:   make(map[string]string),
	}

	// Command injection detection and prevention
	if m.config.CommandInjection.Enabled {
		result = m.detectCommandInjection(result)
	}

	// Secret detection and redaction
	if m.config.SecretDetection.Enabled {
		result = m.detectSecrets(result)
	}

	// Content sanitization
	if m.config.Sanitization.Enabled {
		result = m.sanitizeContent(result)
	}

	// Determine final risk level
	result.Risk = m.calculateRiskLevel(result.Detections)

	// Log security events if detections were made
	if len(result.Detections) > 0 {
		m.logSecurityEvent(result)
	}

	return result
}

// detectCommandInjection detects and neutralizes command injection attempts
func (m *Manager) detectCommandInjection(result *SanitizationResult) *SanitizationResult {
	content := result.Sanitized

	// Common command injection patterns
	patterns := []struct {
		regex       string
		severity    string
		replacement string
	}{
		{`[;&|]{1,2}\s*\w+`, "high", "UNSAFE_COMMAND_REMOVED"},
		{`\$\(.*?\)`, "high", "UNSAFE_COMMAND_REMOVED"},
		{"`.*?`", "high", "UNSAFE_COMMAND_REMOVED"},
		{`\beval\s*\(`, "critical", "UNSAFE_COMMAND_REMOVED"},
		{`\bexec\s*\(`, "critical", "UNSAFE_COMMAND_REMOVED"},
		{`\bsystem\s*\(`, "critical", "UNSAFE_COMMAND_REMOVED"},
		{`\bpassthru\s*\(`, "critical", "UNSAFE_COMMAND_REMOVED"},
		{`\bshell_exec\s*\(`, "critical", "UNSAFE_COMMAND_REMOVED"},
	}

	for _, pattern := range patterns {
		re := regexp.MustCompile(pattern.regex)
		matches := re.FindAllStringIndex(content, -1)

		for _, match := range matches {
			detection := Detection{
				Type:        "command_injection",
				Pattern:     pattern.regex,
				Replacement: pattern.replacement,
				Position:    match[0],
				Severity:    pattern.severity,
			}
			result.Detections = append(result.Detections, detection)
		}

		content = re.ReplaceAllString(content, pattern.replacement)
	}

	result.Sanitized = content
	return result
}

// detectSecrets detects and redacts various types of secrets
func (m *Manager) detectSecrets(result *SanitizationResult) *SanitizationResult {
	content := result.Sanitized

	// Secret patterns
	patterns := []struct {
		name        string
		regex       string
		replacement string
		severity    string
	}{
		{"api_key", `(?i)(api[_-]?key|apikey)\s*[=:]\s*['"]?([a-zA-Z0-9_-]{20,})['"]?`, "UNSAFE_SECRETS_REMOVED", "high"},
		{"jwt_token", `eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*`, "UNSAFE_SECRETS_REMOVED", "high"},
		{"ssh_private_key", `-----BEGIN (RSA |DSA |EC )?PRIVATE KEY-----`, "UNSAFE_SECRETS_REMOVED", "critical"},
		{"password", `(?i)(password|passwd|pwd)\s*[=:]\s*['"]?([^\s'"]{6,})['"]?`, "UNSAFE_SECRETS_REMOVED", "medium"},
		{"aws_access_key", `AKIA[0-9A-Z]{16}`, "UNSAFE_SECRETS_REMOVED", "critical"},
		{"github_token", `ghp_[a-zA-Z0-9]{36}`, "UNSAFE_SECRETS_REMOVED", "high"},
		{"stripe_key", `sk_live_[0-9a-zA-Z]{24}`, "UNSAFE_SECRETS_REMOVED", "critical"},
		{"database_url", `(?i)(mongodb|mysql|postgres|redis)://[^\s'"]*`, "UNSAFE_SECRETS_REMOVED", "high"},
	}

	for _, pattern := range patterns {
		re := regexp.MustCompile(pattern.regex)
		matches := re.FindAllStringIndex(content, -1)

		for _, match := range matches {
			detection := Detection{
				Type:        "secret_" + pattern.name,
				Pattern:     pattern.name,
				Replacement: pattern.replacement,
				Position:    match[0],
				Severity:    pattern.severity,
			}
			result.Detections = append(result.Detections, detection)
		}

		content = re.ReplaceAllString(content, pattern.replacement)
	}

	result.Sanitized = content
	return result
}

// sanitizeContent applies various content sanitization rules
func (m *Manager) sanitizeContent(result *SanitizationResult) *SanitizationResult {
	content := result.Sanitized

	// XSS Prevention
	if m.config.Sanitization.XSSPrevention {
		content = m.sanitizeXSS(content, result)
	}

	// SQL Injection Prevention
	if m.config.Sanitization.SQLInjection {
		content = m.sanitizeSQLInjection(content, result)
	}

	// Homoglyph Detection
	if m.config.Sanitization.HomoglyphFilter {
		content = m.detectHomoglyphs(content, result)
	}

	// Spreadsheet Formula Detection
	if m.config.Sanitization.FormulaDetection {
		content = m.detectSpreadsheetFormulas(content, result)
	}

	result.Sanitized = content
	return result
}

// sanitizeXSS removes potential XSS vectors
func (m *Manager) sanitizeXSS(content string, result *SanitizationResult) string {
	patterns := []struct {
		regex       string
		replacement string
	}{
		{`<script[^>]*>.*?</script>`, "UNSAFE_SCRIPT_REMOVED"},
		{`javascript:`, "UNSAFE_JAVASCRIPT_REMOVED"},
		{`on\w+\s*=`, "UNSAFE_EVENT_HANDLER_REMOVED"},
		{`<iframe[^>]*>.*?</iframe>`, "UNSAFE_IFRAME_REMOVED"},
	}

	for _, pattern := range patterns {
		re := regexp.MustCompile(`(?i)` + pattern.regex)
		if re.MatchString(content) {
			detection := Detection{
				Type:        "xss_attempt",
				Pattern:     pattern.regex,
				Replacement: pattern.replacement,
				Severity:    "high",
			}
			result.Detections = append(result.Detections, detection)
		}
		content = re.ReplaceAllString(content, pattern.replacement)
	}

	return content
}

// sanitizeSQLInjection removes potential SQL injection vectors
func (m *Manager) sanitizeSQLInjection(content string, result *SanitizationResult) string {
	patterns := []struct {
		regex       string
		replacement string
	}{
		{`(?i)\bunion\s+select\b`, "UNSAFE_SQL_REMOVED"},
		{`(?i)\bdrop\s+table\b`, "UNSAFE_SQL_REMOVED"},
		{`(?i)\bdelete\s+from\b`, "UNSAFE_SQL_REMOVED"},
		{`(?i)\binsert\s+into\b`, "UNSAFE_SQL_REMOVED"},
		{`(?i)\bupdate\s+\w+\s+set\b`, "UNSAFE_SQL_REMOVED"},
		{`['"];\s*--`, "UNSAFE_SQL_REMOVED"},
		{`(?i)\bor\s+1\s*=\s*1\b`, "UNSAFE_SQL_REMOVED"},
	}

	for _, pattern := range patterns {
		re := regexp.MustCompile(pattern.regex)
		if re.MatchString(content) {
			detection := Detection{
				Type:        "sql_injection",
				Pattern:     pattern.regex,
				Replacement: pattern.replacement,
				Severity:    "high",
			}
			result.Detections = append(result.Detections, detection)
		}
		content = re.ReplaceAllString(content, pattern.replacement)
	}

	return content
}

// detectHomoglyphs detects suspicious homoglyph characters
func (m *Manager) detectHomoglyphs(content string, result *SanitizationResult) string {
	// Common homoglyph patterns (simplified implementation)
	homoglyphs := map[rune]string{
		'а': "UNSAFE_HOMOGLYPH_REMOVED", // Cyrillic 'a'
		'е': "UNSAFE_HOMOGLYPH_REMOVED", // Cyrillic 'e'
		'о': "UNSAFE_HOMOGLYPH_REMOVED", // Cyrillic 'o'
		'р': "UNSAFE_HOMOGLYPH_REMOVED", // Cyrillic 'p'
	}

	for char, replacement := range homoglyphs {
		if strings.ContainsRune(content, char) {
			detection := Detection{
				Type:        "homoglyph",
				Pattern:     string(char),
				Replacement: replacement,
				Severity:    "medium",
			}
			result.Detections = append(result.Detections, detection)
			content = strings.ReplaceAll(content, string(char), replacement)
		}
	}

	return content
}

// detectSpreadsheetFormulas detects potentially malicious spreadsheet formulas
func (m *Manager) detectSpreadsheetFormulas(content string, result *SanitizationResult) string {
	patterns := []string{`^=`, `^+`, `^-`, `^@`}

	for _, pattern := range patterns {
		re := regexp.MustCompile(pattern)
		if re.MatchString(content) {
			detection := Detection{
				Type:        "spreadsheet_formula",
				Pattern:     pattern,
				Replacement: "UNSAFE_SPREADSHEET_FORMULA",
				Severity:    "medium",
			}
			result.Detections = append(result.Detections, detection)
			content = re.ReplaceAllString(content, "UNSAFE_SPREADSHEET_FORMULA")
		}
	}

	return content
}

// calculateRiskLevel calculates overall risk level based on detections
func (m *Manager) calculateRiskLevel(detections []Detection) string {
	if len(detections) == 0 {
		return "low"
	}

	hasCritical := false
	hasHigh := false

	for _, detection := range detections {
		switch detection.Severity {
		case "critical":
			hasCritical = true
		case "high":
			hasHigh = true
		}
	}

	if hasCritical {
		return "critical"
	}
	if hasHigh {
		return "high"
	}
	return "medium"
}

// logSecurityEvent logs security events for detected threats
func (m *Manager) logSecurityEvent(result *SanitizationResult) {
	event := &logging.SecurityEvent{
		Type:      "content_sanitization",
		Severity:  result.Risk,
		Message:   "Content sanitization performed",
		Timestamp: time.Now(),
		Details: map[string]string{
			"detections_count": strconv.Itoa(len(result.Detections)),
			"risk_level":      result.Risk,
		},
	}

	m.logger.LogSecurityEvent(event)
}

// initializePatterns compiles regex patterns for performance
func (m *Manager) initializePatterns() {
	// This would compile all the regex patterns for better performance
	// Omitted for brevity but would be important for production use
}