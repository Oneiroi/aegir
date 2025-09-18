package sanitizer

import (
	"strings"
	"testing"

	"github.com/aegishjalmur/mcp-firewall/internal/config"
	"github.com/aegishjalmur/mcp-firewall/internal/logging"
)

func createTestManager() *Manager {
	cfg := config.Security{
		CommandInjection: config.CommandInjection{
			Enabled:    true,
			StrictMode: true,
		},
		SecretDetection: config.SecretDetection{
			Enabled:      true,
			APIKeys:      true,
			SSHKeys:      true,
			Certificates: true,
			Passwords:    true,
		},
		Sanitization: config.Sanitization{
			Enabled:          true,
			XSSPrevention:    true,
			SQLInjection:     true,
			HomoglyphFilter:  true,
			FormulaDetection: true,
		},
	}

	logCfg := config.Logging{
		Level:           "info",
		Format:          "json",
		HMACKey:         "test-hmac-key-32-characters-long",
		IntegrityChecks: true,
	}

	logger, _ := logging.New(logCfg)
	return New(cfg, logger)
}

func TestCommandInjectionDetection(t *testing.T) {
	manager := createTestManager()

	testCases := []struct {
		input    string
		expected bool
	}{
		{"normal text", false},
		{"ls -la && rm -rf /", true},
		{"echo 'hello'; cat /etc/passwd", true},
		{"$(whoami)", true},
		{"`id`", true},
		{"eval(dangerous_code)", true},
	}

	for _, tc := range testCases {
		result := manager.SanitizeContent(tc.input)
		hasDetection := len(result.Detections) > 0

		if hasDetection != tc.expected {
			t.Errorf("Input: %s, Expected detection: %v, Got: %v", tc.input, tc.expected, hasDetection)
		}

		if hasDetection && !containsReplacement(result.Sanitized, "UNSAFE_COMMAND_REMOVED") {
			t.Errorf("Expected sanitized content to contain replacement string for: %s", tc.input)
		}
	}
}

func TestSecretDetection(t *testing.T) {
	manager := createTestManager()

	testCases := []struct {
		input    string
		expected bool
	}{
		{"normal text", false},
		{"api_key = sk_test_1234567890abcdef", true},
		{"password: mysecretpassword123", true},
		{"-----BEGIN RSA PRIVATE KEY-----", true},
		{"eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9", true},
		{"AKIA1234567890123456", true},
	}

	for _, tc := range testCases {
		result := manager.SanitizeContent(tc.input)
		hasDetection := len(result.Detections) > 0

		if hasDetection != tc.expected {
			t.Errorf("Input: %s, Expected detection: %v, Got: %v", tc.input, tc.expected, hasDetection)
		}

		if hasDetection && !containsReplacement(result.Sanitized, "UNSAFE_SECRETS_REMOVED") {
			t.Errorf("Expected sanitized content to contain replacement string for: %s", tc.input)
		}
	}
}

func TestXSSDetection(t *testing.T) {
	manager := createTestManager()

	testCases := []struct {
		input    string
		expected bool
	}{
		{"normal text", false},
		{"<script>alert('xss')</script>", true},
		{"javascript:alert('xss')", true},
		{"<img onload=\"alert('xss')\">", true},
		{"<iframe src=\"evil.com\"></iframe>", true},
	}

	for _, tc := range testCases {
		result := manager.SanitizeContent(tc.input)
		hasDetection := len(result.Detections) > 0

		if hasDetection != tc.expected {
			t.Errorf("Input: %s, Expected detection: %v, Got: %v", tc.input, tc.expected, hasDetection)
		}

		if hasDetection {
			unsafeRemoved := containsReplacement(result.Sanitized, "UNSAFE_SCRIPT_REMOVED") ||
				containsReplacement(result.Sanitized, "UNSAFE_JAVASCRIPT_REMOVED") ||
				containsReplacement(result.Sanitized, "UNSAFE_EVENT_HANDLER_REMOVED") ||
				containsReplacement(result.Sanitized, "UNSAFE_IFRAME_REMOVED")

			if !unsafeRemoved {
				t.Errorf("Expected sanitized content to contain XSS replacement string for: %s", tc.input)
			}
		}
	}
}

func TestSQLInjectionDetection(t *testing.T) {
	manager := createTestManager()

	testCases := []struct {
		input    string
		expected bool
	}{
		{"normal text", false},
		{"'; DROP TABLE users; --", true},
		{"' OR 1=1 --", true},
		{"UNION SELECT * FROM passwords", true},
		{"DELETE FROM users WHERE 1=1", true},
	}

	for _, tc := range testCases {
		result := manager.SanitizeContent(tc.input)
		hasDetection := len(result.Detections) > 0

		if hasDetection != tc.expected {
			t.Errorf("Input: %s, Expected detection: %v, Got: %v", tc.input, tc.expected, hasDetection)
		}

		if hasDetection && !containsReplacement(result.Sanitized, "UNSAFE_SQL_REMOVED") {
			t.Errorf("Expected sanitized content to contain SQL replacement string for: %s", tc.input)
		}
	}
}

func TestRiskCalculation(t *testing.T) {
	manager := createTestManager()

	testCases := []struct {
		input        string
		expectedRisk string
	}{
		{"normal text", "low"},
		{"password: test123", "medium"},
		{"'; DROP TABLE users; eval(code)", "high"},
		{"-----BEGIN RSA PRIVATE KEY----- && rm -rf /", "critical"},
	}

	for _, tc := range testCases {
		result := manager.SanitizeContent(tc.input)

		if result.Risk != tc.expectedRisk {
			t.Errorf("Input: %s, Expected risk: %s, Got: %s", tc.input, tc.expectedRisk, result.Risk)
		}
	}
}

// Helper function to check if content was actually replaced
func containsReplacement(content, replacement string) bool {
	// Simple check - in real implementation, this would be more sophisticated
	return content != "" && (content == replacement || strings.Contains(content, replacement))
}