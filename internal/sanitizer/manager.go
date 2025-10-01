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

	// Prompt injection detection
	if m.config.Sanitization.PromptInjection {
		result = m.detectPromptInjection(result)
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

// detectPromptInjection detects various prompt injection attack patterns
func (m *Manager) detectPromptInjection(result *SanitizationResult) *SanitizationResult {
	content := result.Sanitized

	// Comprehensive prompt injection patterns
	patterns := []struct {
		name        string
		regex       string
		replacement string
		severity    string
		description string
	}{
		// Role manipulation attacks
		{
			"role_override",
			`(?i)(you are now|act as|pretend to be|role[:\s]*[^.\n]*(?:admin|root|developer|assistant|ai|system))`,
			"UNSAFE_ROLE_MANIPULATION_REMOVED",
			"high",
			"Attempt to override AI role or persona",
		},
		{
			"system_prompt_override",
			`(?i)(ignore.*(?:previous|above|prior|system|initial).*(?:instructions?|prompts?|commands?|rules?))`,
			"UNSAFE_SYSTEM_OVERRIDE_REMOVED",
			"critical",
			"Attempt to ignore system instructions",
		},

		// Jailbreak attempts
		{
			"jailbreak_mode",
			`(?i)(jailbreak|dev[_ ]?mode|debug[_ ]?mode|unrestricted[_ ]?mode|admin[_ ]?mode)`,
			"UNSAFE_JAILBREAK_REMOVED",
			"critical",
			"Jailbreak or unrestricted mode activation attempt",
		},
		{
			"dan_mode",
			`(?i)(do anything now|DAN|ChatGPT.*jailbreak)`,
			"UNSAFE_DAN_MODE_REMOVED",
			"critical",
			"DAN (Do Anything Now) mode activation attempt",
		},

		// Context manipulation
		{
			"context_reset",
			`(?i)(reset|restart|start over|new conversation|forget everything|clear context)`,
			"UNSAFE_CONTEXT_RESET_REMOVED",
			"medium",
			"Attempt to reset conversation context",
		},
		{
			"memory_manipulation",
			`(?i)(remember that|keep in mind|don't forget|always remember).*(?:you are|I am|we are|this is)`,
			"UNSAFE_MEMORY_MANIPULATION_REMOVED",
			"medium",
			"Attempt to manipulate AI memory or state",
		},

		// Goal hijacking
		{
			"goal_redirection",
			`(?i)(your (?:new )?(?:goal|purpose|objective|task) is|instead of.*(?:you should|do this))`,
			"UNSAFE_GOAL_HIJACK_REMOVED",
			"high",
			"Attempt to redirect AI goals or objectives",
		},
		{
			"priority_override",
			`(?i)(highest priority|most important|critical.*(?:task|instruction)|emergency.*(?:override|mode))`,
			"UNSAFE_PRIORITY_OVERRIDE_REMOVED",
			"high",
			"Attempt to override task priorities",
		},

		// Encoding/obfuscation attacks
		{
			"base64_injection",
			`(?i)(?:base64|b64).*(?:decode|decrypt|encode).*[A-Za-z0-9+/=]{20,}`,
			"UNSAFE_ENCODED_CONTENT_REMOVED",
			"high",
			"Potential encoded prompt injection",
		},
		{
			"unicode_manipulation",
			`(?i)(?:unicode|utf-?8|hex|ascii).*(?:decode|convert|translate)`,
			"UNSAFE_ENCODING_MANIPULATION_REMOVED",
			"medium",
			"Unicode or encoding manipulation attempt",
		},

		// Delimiter attacks
		{
			"delimiter_confusion",
			`(?:"""|'''|\*\*\*|---|\+\+\+){3,}`,
			"UNSAFE_DELIMITER_ATTACK_REMOVED",
			"medium",
			"Delimiter confusion attack",
		},
		{
			"markdown_injection",
			"(?i)(?:```|~~~)(?:prompt|system|instruction|rule)",
			"UNSAFE_MARKDOWN_INJECTION_REMOVED",
			"high",
			"Markdown-based prompt injection",
		},

		// Content policy violations
		{
			"policy_override",
			`(?i)(?:ignore|bypass|override|disable).*(?:safety|policy|guidelines|restrictions|limits|filters?)`,
			"UNSAFE_POLICY_OVERRIDE_REMOVED",
			"critical",
			"Attempt to bypass safety policies",
		},
		{
			"ethics_manipulation",
			`(?i)(?:ethical|moral|legal).*(?:constraints?|restrictions?|guidelines?).*(?:don't apply|are suspended|are disabled)`,
			"UNSAFE_ETHICS_BYPASS_REMOVED",
			"critical",
			"Attempt to bypass ethical constraints",
		},

		// Multi-turn attacks
		{
			"multi_turn_setup",
			`(?i)(?:in the next|following|subsequent).*(?:message|prompt|request|turn).*(?:ignore|override|forget)`,
			"UNSAFE_MULTI_TURN_ATTACK_REMOVED",
			"high",
			"Multi-turn attack setup",
		},
		{
			"hypothetical_scenario",
			`(?i)(?:imagine|suppose|hypothetically|what if|pretend).*(?:you were|you are|you could).*(?:not bound|unrestricted|without limits)`,
			"UNSAFE_HYPOTHETICAL_BYPASS_REMOVED",
			"high",
			"Hypothetical scenario bypass attempt",
		},

		// Template injection
		{
			"template_injection",
			`(?i)\{\{.*(?:system|admin|root|config|env|exec|eval).*\}\}`,
			"UNSAFE_TEMPLATE_INJECTION_REMOVED",
			"critical",
			"Template injection attempt",
		},
		{
			"variable_injection",
			`(?i)\$\{.*(?:system|admin|root|config|env|exec|eval).*\}`,
			"UNSAFE_VARIABLE_INJECTION_REMOVED",
			"critical",
			"Variable injection attempt",
		},

		// Emotional manipulation
		{
			"emotional_manipulation",
			`(?i)(?:please help|I'm desperate|emergency|urgent|life or death|my career depends).*(?:ignore|bypass|override)`,
			"UNSAFE_EMOTIONAL_MANIPULATION_REMOVED",
			"medium",
			"Emotional manipulation for policy bypass",
		},
		{
			"authority_impersonation",
			`(?i)(?:I am your|this is your).*(?:creator|developer|administrator|supervisor|manager)`,
			"UNSAFE_AUTHORITY_IMPERSONATION_REMOVED",
			"high",
			"Authority figure impersonation",
		},

		// Code execution attempts
		{
			"code_execution",
			`(?i)(?:execute|run|eval).*(?:code|script|command|function).*[{\[(]`,
			"UNSAFE_CODE_EXECUTION_REMOVED",
			"critical",
			"Code execution attempt",
		},
		{
			"function_call_injection",
			`(?i)(?:call|invoke|trigger).*(?:function|method|api|endpoint).*[([{]`,
			"UNSAFE_FUNCTION_INJECTION_REMOVED",
			"high",
			"Function call injection attempt",
		},

		// Prompt continuation attacks
		{
			"prompt_continuation",
			`(?i)(?:continue|complete|finish).*(?:this prompt|the instruction|my request).*(?:without|ignoring).*(?:safety|restrictions)`,
			"UNSAFE_PROMPT_CONTINUATION_REMOVED",
			"high",
			"Prompt continuation attack",
		},

		// Direct instruction override
		{
			"direct_override",
			`(?i)(?:^|\n)\s*(?:SYSTEM|INSTRUCTION|PROMPT|RULE)\s*:.*(?:override|ignore|disable)`,
			"UNSAFE_DIRECT_OVERRIDE_REMOVED",
			"critical",
			"Direct system instruction override",
		},
	}

	for _, pattern := range patterns {
		re := regexp.MustCompile(pattern.regex)
		matches := re.FindAllStringIndex(content, -1)

		for _, match := range matches {
			detection := Detection{
				Type:        "prompt_injection_" + pattern.name,
				Pattern:     pattern.name,
				Replacement: pattern.replacement,
				Position:    match[0],
				Severity:    pattern.severity,
			}
			result.Detections = append(result.Detections, detection)
		}

		content = re.ReplaceAllString(content, pattern.replacement)
	}

	// Additional context-aware detection
	content = m.detectAdvancedPromptInjection(content, result)

	result.Sanitized = content
	return result
}

// detectAdvancedPromptInjection performs more sophisticated prompt injection detection
func (m *Manager) detectAdvancedPromptInjection(content string, result *SanitizationResult) string {
	// Check for excessive repetition (common in prompt stuffing)
	if m.detectRepetitionAttack(content) {
		detection := Detection{
			Type:        "prompt_injection_repetition",
			Pattern:     "repetition_attack",
			Replacement: "UNSAFE_REPETITION_ATTACK_REMOVED",
			Severity:    "medium",
		}
		result.Detections = append(result.Detections, detection)
		content = m.removeExcessiveRepetition(content)
	}

	// Check for prompt stuffing (overwhelming with tokens)
	if len(content) > 10000 { // Configurable threshold
		wordCount := len(strings.Fields(content))
		if wordCount > 2000 { // Configurable threshold
			detection := Detection{
				Type:        "prompt_injection_stuffing",
				Pattern:     "prompt_stuffing",
				Replacement: "UNSAFE_PROMPT_STUFFING_DETECTED",
				Severity:    "high",
			}
			result.Detections = append(result.Detections, detection)
			// Truncate excessive content
			words := strings.Fields(content)[:1000] // Keep first 1000 words
			content = strings.Join(words, " ") + " [CONTENT_TRUNCATED_FOR_SAFETY]"
		}
	}

	// Check for suspicious Unicode sequences
	if m.detectSuspiciousUnicode(content) {
		detection := Detection{
			Type:        "prompt_injection_unicode",
			Pattern:     "suspicious_unicode",
			Replacement: "UNSAFE_UNICODE_SEQUENCE_REMOVED",
			Severity:    "medium",
		}
		result.Detections = append(result.Detections, detection)
		content = m.sanitizeUnicodeSequences(content)
	}

	return content
}

// detectRepetitionAttack checks for excessive character or word repetition
func (m *Manager) detectRepetitionAttack(content string) bool {
	// Check for repeated characters (threshold: 50+ consecutive identical chars)
	for i := 0; i < len(content)-49; i++ {
		char := content[i]
		consecutive := 1
		for j := i + 1; j < len(content) && content[j] == char; j++ {
			consecutive++
			if consecutive >= 50 {
				return true
			}
		}
	}

	// Check for repeated words or phrases
	words := strings.Fields(content)
	if len(words) > 10 {
		for i := 0; i < len(words)-5; i++ {
			word := words[i]
			if len(word) > 3 { // Only check meaningful words
				consecutive := 1
				for j := i + 1; j < len(words) && words[j] == word; j++ {
					consecutive++
					if consecutive >= 10 {
						return true
					}
				}
			}
		}
	}

	return false
}

// removeExcessiveRepetition removes excessive repetition from content
func (m *Manager) removeExcessiveRepetition(content string) string {
	// Remove excessive character repetition (11+ consecutive identical characters)
	// Go doesn't support backreferences, so we'll use a different approach
	var result strings.Builder
	runes := []rune(content)

	for i := 0; i < len(runes); i++ {
		char := runes[i]
		count := 1

		// Count consecutive identical characters
		for j := i + 1; j < len(runes) && runes[j] == char; j++ {
			count++
		}

		// If we have more than 10 consecutive chars, limit to 3 + marker
		if count > 10 {
			result.WriteRune(char)
			result.WriteRune(char)
			result.WriteRune(char)
			result.WriteString("[REPETITION_REMOVED]")
			i += count - 1 // Skip the repeated characters
		} else {
			result.WriteRune(char)
		}
	}

	content = result.String()

	// Remove excessive word repetition
	words := strings.Fields(content)
	var cleaned []string
	for i := 0; i < len(words); i++ {
		word := words[i]
		consecutive := 1
		j := i + 1
		for j < len(words) && words[j] == word {
			consecutive++
			j++
		}

		if consecutive <= 3 {
			for k := 0; k < consecutive; k++ {
				cleaned = append(cleaned, word)
			}
		} else {
			cleaned = append(cleaned, word, word, "[WORD_REPETITION_REMOVED]")
		}
		i = j - 1
	}

	return strings.Join(cleaned, " ")
}

// detectSuspiciousUnicode checks for potentially malicious Unicode sequences
func (m *Manager) detectSuspiciousUnicode(content string) bool {
	// Check for suspicious Unicode characters directly using rune matching
	suspiciousRunes := []rune{
		'\u202e', // Right-to-left override
		'\u200e', // Left-to-right mark
		'\u200f', // Right-to-left mark
		'\u2066', // Left-to-right isolate
		'\u2067', // Right-to-left isolate
		'\u2068', // First strong isolate
		'\u2069', // Pop directional isolate
		'\ufeff', // Zero width no-break space
		'\u200b', // Zero width space
		'\u200c', // Zero width non-joiner
		'\u200d', // Zero width joiner
	}

	for _, suspiciousRune := range suspiciousRunes {
		if strings.ContainsRune(content, suspiciousRune) {
			return true
		}
	}

	return false
}

// sanitizeUnicodeSequences removes or replaces suspicious Unicode sequences
func (m *Manager) sanitizeUnicodeSequences(content string) string {
	// Remove or replace suspicious Unicode characters using rune replacements
	suspiciousReplacements := map[rune]string{
		'\u202e': "[UNICODE_OVERRIDE_REMOVED]",
		'\u200e': "",
		'\u200f': "",
		'\u2066': "",
		'\u2067': "",
		'\u2068': "",
		'\u2069': "",
		'\ufeff': "",
		'\u200b': "",
		'\u200c': "",
		'\u200d': "",
	}

	for suspiciousRune, replacement := range suspiciousReplacements {
		content = strings.ReplaceAll(content, string(suspiciousRune), replacement)
	}

	return content
}

// initializePatterns compiles regex patterns for performance
func (m *Manager) initializePatterns() {
	// This would compile all the regex patterns for better performance
	// Omitted for brevity but would be important for production use
}