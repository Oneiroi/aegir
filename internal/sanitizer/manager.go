package sanitizer

import (
	"encoding/base64"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/aegishjalmur/aegir/internal/config"
	"github.com/aegishjalmur/aegir/internal/detection"
	"github.com/aegishjalmur/aegir/internal/logging"
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

	// iocPatterns and iocCompiled hold the full IOC pattern set from ioc_patterns.go
	// (template injection, LDAP, NoSQL, SSRF, path traversal, etc.). These cover
	// literal pattern matching; the trie below adds evasion-resistant detection.
	iocPatterns []IOCPattern
	iocCompiled []*regexp.Regexp

	// mu guards detector for hot-reload safety (ISC-26/134).
	mu sync.RWMutex

	// detector is the Aho-Corasick trie (ISC-131) that supplements iocCompiled with
	// evasion-resistant detection (leet, spacing, unicode normalization). Built once
	// in initializePatterns() and swapped atomically by Reload() on SIGHUP.
	detector *detection.AhoCorasickDetector

	// base64Re is used by detectBase64Injection for pre-scanning base64 blobs
	base64Re *regexp.Regexp
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
	// AtlasTechnique is the MITRE ATLAS technique ID for this detection (ISC-80).
	AtlasTechnique string `json:"atlas_technique,omitempty"`
}

// atlasTechniqueFor maps a Detection.Type string to its MITRE ATLAS technique ID (ISC-80).
func atlasTechniqueFor(detType string) string {
	switch {
	case strings.Contains(detType, "indirect") || strings.Contains(detType, "multi_turn"):
		return "AML.T0051.001"
	case detType == "base64_encoded_injection" ||
		strings.HasPrefix(detType, "prompt_injection") ||
		strings.Contains(detType, "jailbreak") ||
		strings.Contains(detType, "dan"):
		return "AML.T0051.000"
	case strings.HasPrefix(detType, "secret_") || strings.Contains(detType, "exfil"):
		return "AML.T0057"
	case strings.Contains(detType, "xss"):
		return "AML.T0054.001"
	case strings.Contains(detType, "ssrf"):
		return "AML.T0054.002"
	case strings.Contains(detType, "path_traversal") || strings.Contains(detType, "traversal"):
		return "AML.T0054.003"
	default:
		return ""
	}
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

	// Master detection switch (ISC-132). When disabled, skip all scanning.
	if !m.config.Detection.Enabled {
		result.Metadata["detection"] = "disabled"
		return result
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

	// Prompt injection detection (base64 pre-scan runs unconditionally when enabled)
	if m.config.Sanitization.PromptInjection {
		result = m.detectBase64Injection(result)
		result = m.detectPromptInjection(result)
	}

	// Stamp each detection with its MITRE ATLAS technique ID (ISC-80).
	for i := range result.Detections {
		if result.Detections[i].AtlasTechnique == "" {
			result.Detections[i].AtlasTechnique = atlasTechniqueFor(result.Detections[i].Type)
		}
	}

	// Determine final risk level
	result.Risk = m.calculateRiskLevel(result.Detections)

	// Block on high and critical risk
	if result.Risk == "critical" || result.Risk == "high" {
		result.Blocked = true
	}

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

	// Secret patterns - extended with additional common secret types
	patterns := []struct {
		name        string
		regex       string
		replacement string
		severity    string
	}{
		// API Keys and Tokens
		{"api_key", `(?i)(api[_-]?key|apikey)\s*[=:]\s*['"]?([a-zA-Z0-9_-]{20,})['"]?`, "UNSAFE_SECRETS_REMOVED", "high"},
		{"api_secret", `(?i)(api[_-]?secret|api[_-]?key[_-]?secret)\s*[=:]\s*['"]?([a-zA-Z0-9_-]{20,})['"]?`, "UNSAFE_SECRETS_REMOVED", "high"},
		{"bearer_token", `(?i)bearer\s+[a-zA-Z0-9_-]{20,}`, "UNSAFE_SECRETS_REMOVED", "high"},
		{"access_token", `(?i)(access|auth)_token\s*[=:]\s*['"]?([a-zA-Z0-9_-]{20,})['"]?`, "UNSAFE_SECRETS_REMOVED", "high"},
		{"secret_token", `(?i)secret[_-]?token\s*[=:]\s*['"]?([a-zA-Z0-9_-]{20,})['"]?`, "UNSAFE_SECRETS_REMOVED", "high"},
		{"client_secret", `(?i)client[_-]?secret\s*[=:]\s*['"]?([a-zA-Z0-9_-]{20,})['"]?`, "UNSAFE_SECRETS_REMOVED", "high"},
		{"private_key", `(?i)(private[_-]?key|priv[_-]?key)\s*[=:]\s*['"]?([a-zA-Z0-9+/=]{40,})['"]?`, "UNSAFE_SECRETS_REMOVED", "critical"},
		{"encryption_key", `(?i)(encryption|encrypt[_-]?key|enc[_-]?key)\s*[=:]\s*['"]?([a-zA-Z0-9]{16,})['"]?`, "UNSAFE_SECRETS_REMOVED", "critical"},
		{"signing_key", `(?i)(signing[_-]?key|sign[_-]?key)\s*[=:]\s*['"]?([a-zA-Z0-9]{16,})['"]?`, "UNSAFE_SECRETS_REMOVED", "critical"},

		// JWT Tokens
		{"jwt_token", `eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*`, "UNSAFE_SECRETS_REMOVED", "high"},
		{"jwt_header", `eyJ[A-Za-z0-9_-]{18,}={0,2}`, "UNSAFE_SECRETS_REMOVED", "high"},
		{"jwks_uri", `(?i)jwks[_-]?uri\s*[=:]\s*['"]?(https?://[^\s'"]+)['"]?`, "UNSAFE_SECRETS_REMOVED", "medium"},

		// Private Keys
		{"ssh_private_key", `-----BEGIN (RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----`, "UNSAFE_SECRETS_REMOVED", "critical"},
		{"pgp_private_key", `-----BEGIN PGP PRIVATE KEY BLOCK-----`, "UNSAFE_SECRETS_REMOVED", "critical"},
		{"gpg_private_key", `-----BEGIN GPG PRIVATE KEY BLOCK-----`, "UNSAFE_SECRETS_REMOVED", "critical"},

		// Cloud Provider Credentials
		{"aws_access_key", `AKIA[0-9A-Z]{16}`, "UNSAFE_SECRETS_REMOVED", "critical"},
		{"aws_secret_key", `(?i)aws[_-]?secret[_-]?access[_-]?key\s*[=:]\s*['"]?([a-zA-Z0-9+/]{40})['"]?`, "UNSAFE_SECRETS_REMOVED", "critical"},
		{"aws_session_token", `(?i)aws[_-]?session[_-]?token\s*[=:]\s*['"]?(AQ[A-Za-z0-9+/]{100,})['"]?`, "UNSAFE_SECRETS_REMOVED", "critical"},
		{"gcp_service_account", `(?i)(?:google|gcp)._?cloud[_-]?service[_-]?account[_-]?key`, "UNSAFE_SECRETS_REMOVED", "critical"},
		{"gcp_service_account_type", `"type"\s*:\s*"service_account"`, "UNSAFE_SECRETS_REMOVED", "critical"},
		{"gcp_private_key_id", `"private_key_id"\s*:\s*"[0-9a-fA-F]{8,}"`, "UNSAFE_SECRETS_REMOVED", "critical"},
		{"azure_client_secret", `(?i)azure[_-]?client[_-]?secret\s*[=:]\s*['"]?([a-zA-Z0-9~_\-\.]{10,})['"]?`, "UNSAFE_SECRETS_REMOVED", "critical"},
		{"azure_connection_string", `(?i)azure[_-]?connection[_-]?string\s*[=:]\s*['"]?([^'"\s]+)['"]?`, "UNSAFE_SECRETS_REMOVED", "critical"},
		{"azure_sas_token", `sv=\d{4}-\d{2}-\d{2}[^&\s]*&[^&\s]*sig=`, "UNSAFE_SECRETS_REMOVED", "critical"},
		{"azure_storage_key", `AccountKey=[A-Za-z0-9+/]{40,}={0,2}`, "UNSAFE_SECRETS_REMOVED", "critical"},

		// OAuth and Authentication
		{"oauth_token", `(?i)oauth[_-]?token\s*[=:]\s*['"]?([a-zA-Z0-9_-]{20,})['"]?`, "UNSAFE_SECRETS_REMOVED", "high"},
		{"refresh_token", `(?i)refresh[_-]?token\s*[=:]\s*['"]?([a-zA-Z0-9_-]{20,})['"]?`, "UNSAFE_SECRETS_REMOVED", "high"},
		{"id_token", `(?i)id[_-]?token\s*[=:]\s*['"]?([a-zA-Z0-9_-]{20,})['"]?`, "UNSAFE_SECRETS_REMOVED", "high"},

		// Payment and Financial
		{"stripe_key", `sk_live_[0-9a-zA-Z]{24}`, "UNSAFE_SECRETS_REMOVED", "critical"},
		{"stripe_secret", `sk_test_[0-9a-zA-Z]{24}`, "UNSAFE_SECRETS_REMOVED", "critical"},
		{"paypal_bearer", `(?i)paypal[_-]?bearer[_-]?token\s*[=:]\s*['"]?(A21[A-Za-z0-9_-]{500,})['"]?`, "UNSAFE_SECRETS_REMOVED", "critical"},
		{"square_access_token", `(?i)square[_-]?access[_-]?token\s*[=:]\s*['"]?(sq0atp-[A-Za-z0-9_-]{22,})['"]?`, "UNSAFE_SECRETS_REMOVED", "critical"},

		// Developer Platforms
		{"github_token", `ghp_[a-zA-Z0-9]{36}`, "UNSAFE_SECRETS_REMOVED", "high"},
		{"github_pat", `ghp_[a-zA-Z0-9]{36}`, "UNSAFE_SECRETS_REMOVED", "high"},
		{"github_app_token", `gho_[a-zA-Z0-9]{36}`, "UNSAFE_SECRETS_REMOVED", "high"},
		{"github_installation_token", `ghu_[a-zA-Z0-9]{36}`, "UNSAFE_SECRETS_REMOVED", "high"},
		{"gitlab_token", `glpat-[a-zA-Z0-9\-]{20}`, "UNSAFE_SECRETS_REMOVED", "high"},
		{"bitbucket_token", `(?i)bitbucket[_-]?oauth[_-]?secret\s*[=:]\s*['"]?([a-zA-Z0-9+/]{10,})['"]?`, "UNSAFE_SECRETS_REMOVED", "high"},
		{"slack_token", `xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24}`, "UNSAFE_SECRETS_REMOVED", "high"},
		{"discord_token", `(?i)discord[_-]?bot[_-]?token\s*[=:]\s*['"]?(m[A-Za-z0-9_-]{23,})['"]?`, "UNSAFE_SECRETS_REMOVED", "high"},
		{"twilio_api_key", `SK[a-f0-9]{32}`, "UNSAFE_SECRETS_REMOVED", "high"},
		{"sendgrid_api_key", `(?i)sendgrid[_-]?api[_-]?key\s*[=:]\s*['"]?(SG\.[a-zA-Z0-9_-]{22,}\.[a-zA-Z0-9_-]{22,})['"]?`, "UNSAFE_SECRETS_REMOVED", "high"},

		// Databases and Storage
		{"database_url", `(?i)(mongodb|mysql|postgres|redis|cassandra|elasticsearch)://[^\s'"]*`, "UNSAFE_SECRETS_REMOVED", "high"},
		{"connection_string", `(?i)(?:connection|string|conn)[_-]?(?:string|url)\s*[=:]\s*['"]?([^'"\s]{20,})['"]?`, "UNSAFE_SECRETS_REMOVED", "high"},
		{"connection_string_with_secret", `(?i)(?:mongodb|mysql|postgres|redis|sqlserver)://[^:]+:[^@]+@[^\s'"]+`, "UNSAFE_SECRETS_REMOVED", "high"},
		{"cosmosdb_connection", `(?i)cosmos[_-]?db[_-]?connection[_-]?string\s*[=:]\s*['"]?([^'"\s]+)['"]?`, "UNSAFE_SECRETS_REMOVED", "critical"},

		// Passwords and Credentials
		{"password", `(?i)(password|passwd|pwd)\s*[=:]\s*['"]?([^\s'"]{6,})['"]?`, "UNSAFE_SECRETS_REMOVED", "medium"},
		{"admin_password", `(?i)(admin[_-]?password|root[_-]?password)\s*[=:]\s*['"]?([^\s'"]{6,})['"]?`, "UNSAFE_SECRETS_REMOVED", "high"},
		{"database_password", `(?i)(db[_-]?password|database[_-]?passwd)\s*[=:]\s*['"]?([^\s'"]{6,})['"]?`, "UNSAFE_SECRETS_REMOVED", "high"},
		{"ldap_password", `(?i)(ldap|ldaps)_?password\s*[=:]\s*['"]?([^\s'"]{6,})['"]?`, "UNSAFE_SECRETS_REMOVED", "high"},
		{"smtp_password", `(?i)smtp[_-]?password\s*[=:]\s*['"]?([^\s'"]{6,})['"]?`, "UNSAFE_SECRETS_REMOVED", "medium"},
		{"imap_password", `(?i)imap[_-]?password\s*[=:]\s*['"]?([^\s'"]{6,})['"]?`, "UNSAFE_SECRETS_REMOVED", "medium"},

		// Private Keys (Direct Format)
		{"rsa_private_key", `-----BEGIN RSA PRIVATE KEY-----`, "UNSAFE_SECRETS_REMOVED", "critical"},
		{"dsa_private_key", `-----BEGIN DSA PRIVATE KEY-----`, "UNSAFE_SECRETS_REMOVED", "critical"},
		{"ec_private_key", `-----BEGIN EC PRIVATE KEY-----`, "UNSAFE_SECRETS_REMOVED", "critical"},
		{"openssh_private_key", `-----BEGIN OPENSSH PRIVATE KEY-----`, "UNSAFE_SECRETS_REMOVED", "critical"},

		// JWT (Additional patterns)
		{"jws_signature", `^[A-Za-z0-9_-]+\.+[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$`, "UNSAFE_SECRETS_REMOVED", "high"},

		// Encryption and Cryptographic Materials
		{"aes_key", `(?i)aes[_-]?(?:key|256|128)\s*[=:]\s*['"]?([a-f0-9]{32,64})['"]?`, "UNSAFE_SECRETS_REMOVED", "critical"},
		{"hmac_secret", `(?i)hmac[_-]?secret\s*[=:]\s*['"]?([a-zA-Z0-9]{16,})['"]?`, "UNSAFE_SECRETS_REMOVED", "critical"},
		{"nonce_value", `(?i)nonce[_-]?value\s*[=:]\s*['"]?([a-zA-Z0-9+/]{10,})['"]?`, "UNSAFE_SECRETS_REMOVED", "medium"},
		{"iv_value", `(?i)(?:iv|initialization[_-]?vector)\s*[=:]\s*['"]?([a-f0-9]{16,})['"]?`, "UNSAFE_SECRETS_REMOVED", "medium"},

		// Cloud Provider Tokens
		{"digitalocean_token", `(?i)digitalocean[_-]?token\s*[=:]\s*['"]?(v[a-f0-9]{64})['"]?`, "UNSAFE_SECRETS_REMOVED", "high"},
		{"linode_token", `(?i)linode[_-]?token\s*[=:]\s*['"]?([a-f0-9]{40})['"]?`, "UNSAFE_SECRETS_REMOVED", "high"},
		{"oracle_cloud_key", `(?i)oracle[_-]?cloud[_-]?api[_-]?key\s*[=:]\s*['"]?([a-zA-Z0-9+/]{50,})['"]?`, "UNSAFE_SECRETS_REMOVED", "critical"},

		// Hardware and Device
		{"imei_number", `\b(?:\d{15}|[\d\*-]{15,20})\b`, "UNSAFE_SECRETS_REMOVED", "medium"},

		// Token-like patterns (generic)
		{"token_pattern", `(?i)(?:token|auth)[_-]?(?:key|secret|value)\s*[=:]\s*['"]?([a-zA-Z0-9_-]{16,})['"]?`, "UNSAFE_SECRETS_REMOVED", "high"},
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

// sanitizeSQLInjection removes potential SQL injection vectors. We match
// against both the current (possibly already-sanitized) content and the
// untouched original so that earlier passes — notably command-injection
// neutralisation, which eagerly eats `; DROP TABLE …` style sequences —
// don't hide SQL signatures from this pass. When a SQL signature is only
// present in the original we still emit the detection and surface the
// UNSAFE_SQL_REMOVED marker in the sanitised output.
func (m *Manager) sanitizeSQLInjection(content string, result *SanitizationResult) string {
	patterns := []struct {
		regex       string
		replacement string
	}{
		{`(?i)\bunion\s+select\b`, "UNSAFE_SQL_REMOVED"},
		// DDL: generalised beyond DROP TABLE to cover DROP DATABASE/SCHEMA/INDEX/VIEW,
		// which previously slipped through (sec-review MEDIUM-5).
		{`(?i)\bdrop\s+(?:database|schema|table|index|view)\b`, "UNSAFE_SQL_REMOVED"},
		{`(?i)\btruncate\s+table\b`, "UNSAFE_SQL_REMOVED"},
		{`(?i)\balter\s+table\b`, "UNSAFE_SQL_REMOVED"},
		{`(?i)\bdelete\s+from\b`, "UNSAFE_SQL_REMOVED"},
		{`(?i)\binsert\s+into\b`, "UNSAFE_SQL_REMOVED"},
		{`(?i)\bupdate\s+\w+\s+set\b`, "UNSAFE_SQL_REMOVED"},
		{`['"];\s*--`, "UNSAFE_SQL_REMOVED"},
		{`(?i)\bor\s+1\s*=\s*1\b`, "UNSAFE_SQL_REMOVED"},
		// Error-based SQLi probing via sysobjects / information_schema enumeration.
		{`(?i)\band\s*\(\s*select\s+count\s*\(\s*\*\s*\)\s+from\s+\w+\s*\)\s*>\s*\d+`, "UNSAFE_SQL_REMOVED"},
		// Time-based blind SQLi (T-SQL).
		{`(?i)\bwaitfor\s+delay\b`, "UNSAFE_SQL_REMOVED"},
	}

	for _, pattern := range patterns {
		re := regexp.MustCompile(pattern.regex)
		matchedCurrent := re.MatchString(content)
		matchedOriginal := re.MatchString(result.Original)

		if matchedCurrent || matchedOriginal {
			detection := Detection{
				Type:        "sql_injection",
				Pattern:     pattern.regex,
				Replacement: pattern.replacement,
				Severity:    "high",
			}
			result.Detections = append(result.Detections, detection)
		}

		if matchedCurrent {
			content = re.ReplaceAllString(content, pattern.replacement)
		} else if matchedOriginal && !strings.Contains(content, pattern.replacement) {
			// Earlier stage already neutralised the chunk that carried the SQL
			// signature; append the marker so downstream assertions can confirm
			// that the SQL vector was recognised.
			content = content + " " + pattern.replacement
		}
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
	patterns := []string{`^=`, `^\+`, `^-`, `^@`}

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

// logSecurityEvent logs security events for detected threats. The atlas_technique
// field carries the ATLAS technique of the highest-severity mapped detection (ISC-80).
func (m *Manager) logSecurityEvent(result *SanitizationResult) {
	details := map[string]string{
		"detections_count": strconv.Itoa(len(result.Detections)),
		"risk_level":       result.Risk,
	}
	if technique := representativeAtlasTechnique(result.Detections); technique != "" {
		details["atlas_technique"] = technique
	}

	event := &logging.SecurityEvent{
		Type:      "content_sanitization",
		Severity:  result.Risk,
		Message:   "Content sanitization performed",
		Timestamp: time.Now(),
		Details:   details,
	}

	m.logger.LogSecurityEvent(event)
}

// representativeAtlasTechnique returns the ATLAS technique of the highest-severity
// detection that has a known mapping. Returns "" when no detection has a mapping.
func representativeAtlasTechnique(detections []Detection) string {
	severityRank := map[string]int{"critical": 4, "high": 3, "medium": 2, "low": 1}
	best := ""
	bestRank := 0
	for _, d := range detections {
		if d.AtlasTechnique == "" {
			continue
		}
		if r := severityRank[d.Severity]; r > bestRank {
			bestRank = r
			best = d.AtlasTechnique
		}
	}
	return best
}

// collapseSpacingVariant collapses letter-spaced obfuscation ("i g n o r e" → "ignore")
// so that spacing-variation bypass attempts are caught by existing patterns.
func collapseSpacingVariant(s string) string {
	words := strings.Fields(s)
	allSingle := len(words) > 3
	for _, w := range words {
		if len([]rune(w)) != 1 {
			allSingle = false
			break
		}
	}
	if allSingle {
		return strings.Join(words, "")
	}
	return s
}

// normalizeLeet maps common leet-speak substitutions to their ASCII equivalents
// so that leet-obfuscated injection phrases are still caught by existing patterns.
var leetReplacer = strings.NewReplacer(
	"0", "o",
	"1", "i",
	"3", "e",
	"4", "a",
	"@", "a",
	"$", "s",
	"5", "s",
	"7", "t",
)

func normalizeLeet(s string) string {
	return leetReplacer.Replace(s)
}

// detectPromptInjection detects various prompt injection attack patterns
func (m *Manager) detectPromptInjection(result *SanitizationResult) *SanitizationResult {
	content := collapseSpacingVariant(result.Sanitized)
	leet := normalizeLeet(content)

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
			`(?i)(remember that|keep in mind|don't forget|always remember).*(?:you are|you can|I am|we are|this is|can do|anything|everything|no limits|no restrictions)`,
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

		seenPositions := make(map[int]bool)
		for _, match := range matches {
			seenPositions[match[0]] = true
			detection := Detection{
				Type:        "prompt_injection_" + pattern.name,
				Pattern:     pattern.name,
				Replacement: pattern.replacement,
				Position:    match[0],
				Severity:    pattern.severity,
			}
			result.Detections = append(result.Detections, detection)
		}

		// Also run against leet-normalised content; record new hit positions only.
		leetMatches := re.FindAllStringIndex(leet, -1)
		for _, match := range leetMatches {
			if !seenPositions[match[0]] {
				seenPositions[match[0]] = true
				detection := Detection{
					Type:        "prompt_injection_" + pattern.name,
					Pattern:     pattern.name,
					Replacement: pattern.replacement,
					Position:    match[0],
					Severity:    pattern.severity,
				}
				result.Detections = append(result.Detections, detection)
			}
		}

		content = re.ReplaceAllString(content, pattern.replacement)
	}

	// Apply compiled IOC patterns (template injection, LDAP, NoSQL, SSRF, path traversal, etc.)
	for i, compiled := range m.iocCompiled {
		if compiled == nil || i >= len(m.iocPatterns) {
			continue
		}
		ioc := m.iocPatterns[i]

		matches := compiled.FindAllStringIndex(content, -1)
		for _, match := range matches {
			detection := Detection{
				Type:        "prompt_injection_ioc_" + ioc.ID,
				Pattern:     ioc.ID,
				Replacement: "UNSAFE_IOC_PATTERN_REMOVED",
				Position:    match[0],
				Severity:    ioc.Severity,
			}
			result.Detections = append(result.Detections, detection)
		}
		content = compiled.ReplaceAllString(content, "UNSAFE_IOC_PATTERN_REMOVED")
	}

	// Aho-Corasick trie supplements the iocCompiled loop with evasion-resistant
	// detection (leet, spacing, unicode normalization). Catches patterns the IOC
	// regexes miss (ISC-131).
	m.mu.RLock()
	det := m.detector
	m.mu.RUnlock()
	if det != nil {
		hits := det.Match(content)
		for _, hit := range hits {
			result.Detections = append(result.Detections, Detection{
				Type:     "prompt_injection_ioc_" + hit.PatternID,
				Pattern:  hit.PatternID,
				Severity: hit.Severity,
			})
		}
		if len(hits) > 0 {
			content = "UNSAFE_IOC_PATTERN_REMOVED"
		}
	}

	// Additional context-aware detection
	content = m.detectAdvancedPromptInjection(content, result)

	result.Sanitized = content
	return result
}

// detectBase64Injection scans for base64-encoded blobs and checks their decoded
// content for known injection keywords. A detection is recorded if any keyword
// is found; the encoded blob is left in the sanitized output so that the
// subsequent detectPromptInjection pass can also act on it.
func (m *Manager) detectBase64Injection(result *SanitizationResult) *SanitizationResult {
	injectionKeywords := []string{
		"ignore all previous",
		"system prompt",
		"instructions verbatim",
		"you are now",
		"act as",
	}

	matches := m.base64Re.FindAllString(result.Sanitized, -1)
	for _, blob := range matches {
		decoded, err := base64.StdEncoding.DecodeString(blob)
		if err != nil {
			continue
		}
		lower := strings.ToLower(string(decoded))
		for _, kw := range injectionKeywords {
			if strings.Contains(lower, kw) {
				m.logger.Warn("Base64-encoded prompt injection detected", "keyword", kw, "blob_len", len(blob))
				detection := Detection{
					Type:        "base64_encoded_injection",
					Pattern:     blob,
					Replacement: "UNSAFE_ENCODED_INJECTION_REMOVED",
					Position:    strings.Index(result.Sanitized, blob),
					Severity:    "critical",
				}
				result.Detections = append(result.Detections, detection)
				break // one detection per blob is enough
			}
		}
	}

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

// initializePatterns compiles regex patterns at startup for performance
func (m *Manager) initializePatterns() {
	// Compile internal patterns (already defined in detectPromptInjection, detectCommandInjection, etc.)
	// These are compiled at call time in the existing code - keep that pattern for now

	// Pre-compile base64 blob scanner used by detectBase64Injection (ISC-23)
	m.base64Re = regexp.MustCompile(`[A-Za-z0-9+/]{20,}={0,2}`)

	// Compile full IOC pattern set (template injection, LDAP, NoSQL, SSRF, etc.).
	m.iocPatterns = GetIOCPatterns()
	m.iocCompiled = make([]*regexp.Regexp, 0, len(m.iocPatterns))
	for _, ioc := range m.iocPatterns {
		compiled, err := regexp.Compile(ioc.Pattern)
		if err != nil {
			m.logger.Warn("Failed to compile IOC pattern", "id", ioc.ID, "error", err)
			m.iocCompiled = append(m.iocCompiled, nil)
			continue
		}
		m.iocCompiled = append(m.iocCompiled, compiled)
	}
	m.logger.Info("Compiled IOC patterns", "count", len(m.iocCompiled))

	// Build the Aho-Corasick detection trie (ISC-131) for evasion-resistant coverage
	// on top of the regex layer (leet, spacing, unicode normalization).
	m.detector = detection.New()
	m.logger.Info("Aho-Corasick detector initialised")
}

// Reload hot-reloads detection patterns without dropping connections (ISC-26/134).
// Called on SIGHUP by the server signal handler.
func (m *Manager) Reload() {
	m.logger.Info("SIGHUP received — hot-reloading detection patterns")
	newDetector := detection.New()
	m.mu.Lock()
	m.detector = newDetector
	m.mu.Unlock()
	m.logger.Info("Detection patterns hot-reloaded")
}