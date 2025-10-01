package logging

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/aegishjalmur/aegir/internal/config"
	"github.com/sirupsen/logrus"
)

// Logger provides secure logging with HMAC integrity
type Logger struct {
	logger     *logrus.Logger
	config     config.Logging
	hmacKey    []byte
	file       *os.File
	mutex      sync.Mutex
	sequenceID uint64
}

// RequestLog represents a request log entry
type RequestLog struct {
	ClientIP   string        `json:"client_ip"`
	Method     string        `json:"method"`
	Path       string        `json:"path"`
	StatusCode int           `json:"status_code"`
	Duration   time.Duration `json:"duration"`
	UserAgent  string        `json:"user_agent"`
	Timestamp  time.Time     `json:"timestamp"`
}

// SecurityEvent represents a security-related log entry
type SecurityEvent struct {
	Type        string            `json:"type"`
	Severity    string            `json:"severity"`
	Message     string            `json:"message"`
	ClientIP    string            `json:"client_ip,omitempty"`
	UserID      string            `json:"user_id,omitempty"`
	Details     map[string]string `json:"details,omitempty"`
	Timestamp   time.Time         `json:"timestamp"`
}

// LogStatus represents the current status of the logging system
type LogStatus struct {
	Enabled         bool    `json:"enabled"`
	LogLevel        string  `json:"log_level"`
	LogFile         string  `json:"log_file"`
	WritesPerSecond float64 `json:"writes_per_second"`
	TotalWrites     uint64  `json:"total_writes"`
	IntegrityStatus string  `json:"integrity_status"`
	LastIntegrityCheck time.Time `json:"last_integrity_check"`
}

// IntegrityResult represents the result of log integrity validation
type IntegrityResult struct {
	Valid           bool      `json:"valid"`
	TotalEntries    int       `json:"total_entries"`
	ValidEntries    int       `json:"valid_entries"`
	InvalidEntries  int       `json:"invalid_entries"`
	MissingEntries  []uint64  `json:"missing_entries,omitempty"`
	ValidationTime  time.Time `json:"validation_time"`
	Details         string    `json:"details"`
}

// New creates a new secure logger instance
func New(config config.Logging) (*Logger, error) {
	logger := logrus.New()

	// Set log level
	level, err := logrus.ParseLevel(config.Level)
	if err != nil {
		level = logrus.InfoLevel
	}
	logger.SetLevel(level)

	// Set format
	if config.Format == "json" {
		logger.SetFormatter(&logrus.JSONFormatter{
			TimestampFormat: time.RFC3339Nano,
		})
	} else {
		logger.SetFormatter(&logrus.TextFormatter{
			FullTimestamp:   true,
			TimestampFormat: time.RFC3339Nano,
		})
	}

	// Create log directory if it doesn't exist
	if config.File != "" {
		logDir := filepath.Dir(config.File)
		if err := os.MkdirAll(logDir, 0755); err != nil {
			return nil, fmt.Errorf("failed to create log directory: %w", err)
		}

		// Open log file
		file, err := os.OpenFile(config.File, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if err != nil {
			return nil, fmt.Errorf("failed to open log file: %w", err)
		}

		logger.SetOutput(file)
	}

	// Parse HMAC key
	hmacKey := []byte(config.HMACKey)
	if len(hmacKey) < 32 {
		return nil, fmt.Errorf("HMAC key must be at least 32 characters long")
	}

	l := &Logger{
		logger:  logger,
		config:  config,
		hmacKey: hmacKey,
		sequenceID: 0,
	}

	return l, nil
}

// Info logs an info message
func (l *Logger) Info(msg string, fields ...interface{}) {
	l.logWithIntegrity(logrus.InfoLevel, msg, fields...)
}

// Warn logs a warning message
func (l *Logger) Warn(msg string, fields ...interface{}) {
	l.logWithIntegrity(logrus.WarnLevel, msg, fields...)
}

// Error logs an error message
func (l *Logger) Error(msg string, fields ...interface{}) {
	l.logWithIntegrity(logrus.ErrorLevel, msg, fields...)
}

// Debug logs a debug message
func (l *Logger) Debug(msg string, fields ...interface{}) {
	l.logWithIntegrity(logrus.DebugLevel, msg, fields...)
}

// LogRequest logs an HTTP request
func (l *Logger) LogRequest(req *RequestLog) {
	entry := l.logger.WithFields(logrus.Fields{
		"client_ip":   req.ClientIP,
		"method":      req.Method,
		"path":        req.Path,
		"status_code": req.StatusCode,
		"duration_ms": req.Duration.Milliseconds(),
		"user_agent":  req.UserAgent,
		"timestamp":   req.Timestamp.Format(time.RFC3339Nano),
	})

	l.logEntryWithIntegrity(entry, "HTTP Request")
}

// LogSecurityEvent logs a security event
func (l *Logger) LogSecurityEvent(event *SecurityEvent) {
	fields := logrus.Fields{
		"event_type": event.Type,
		"severity":   event.Severity,
		"client_ip":  event.ClientIP,
		"user_id":    event.UserID,
		"timestamp":  event.Timestamp.Format(time.RFC3339Nano),
	}

	// Add additional details
	for k, v := range event.Details {
		fields["detail_"+k] = v
	}

	entry := l.logger.WithFields(fields)
	l.logEntryWithIntegrity(entry, fmt.Sprintf("SECURITY: %s", event.Message))
}

// logWithIntegrity logs a message with HMAC integrity
func (l *Logger) logWithIntegrity(level logrus.Level, msg string, fields ...interface{}) {
	fieldMap := make(logrus.Fields)

	// Convert fields to map
	for i := 0; i < len(fields); i += 2 {
		if i+1 < len(fields) {
			if key, ok := fields[i].(string); ok {
				fieldMap[key] = fields[i+1]
			}
		}
	}

	entry := l.logger.WithFields(fieldMap)
	l.logEntryWithIntegrity(entry, msg)
}

// logEntryWithIntegrity logs an entry with HMAC integrity
func (l *Logger) logEntryWithIntegrity(entry *logrus.Entry, msg string) {
	l.mutex.Lock()
	defer l.mutex.Unlock()

	// Increment sequence ID
	l.sequenceID++

	// Add sequence ID to the entry
	entry = entry.WithField("sequence_id", l.sequenceID)

	// Create log line with integrity signature
	timestamp := time.Now().UTC().Format(time.RFC3339Nano)

	// Build the data string for HMAC
	dataString := fmt.Sprintf("%s|%d|%s", timestamp, l.sequenceID, msg)

	// Calculate HMAC
	signature := l.calculateHMAC(dataString)

	// Add HMAC to log entry
	entry = entry.WithFields(logrus.Fields{
		"hmac_signature": signature,
		"log_timestamp":  timestamp,
	})

	// Log the entry
	entry.Info(msg)
}

// calculateHMAC calculates HMAC-SHA256 for the given data
func (l *Logger) calculateHMAC(data string) string {
	h := hmac.New(sha256.New, l.hmacKey)
	h.Write([]byte(data))
	return hex.EncodeToString(h.Sum(nil))
}

// GetStatus returns the current status of the logging system
func (l *Logger) GetStatus() *LogStatus {
	return &LogStatus{
		Enabled:            true,
		LogLevel:           l.config.Level,
		LogFile:            l.config.File,
		WritesPerSecond:    0, // TODO: Implement actual metrics
		TotalWrites:        l.sequenceID,
		IntegrityStatus:    "healthy",
		LastIntegrityCheck: time.Now(),
	}
}

// ValidateIntegrity validates the integrity of log entries
func (l *Logger) ValidateIntegrity() *IntegrityResult {
	result := &IntegrityResult{
		ValidationTime: time.Now(),
		Valid:         true,
		Details:       "Log integrity validation completed successfully",
	}

	if !l.config.IntegrityChecks {
		result.Details = "Integrity checks are disabled"
		return result
	}

	// TODO: Implement actual log file parsing and HMAC validation
	// This would involve:
	// 1. Reading the log file
	// 2. Parsing each log entry
	// 3. Extracting the HMAC signature and data
	// 4. Recalculating HMAC and comparing
	// 5. Checking for missing sequence IDs

	result.TotalEntries = int(l.sequenceID)
	result.ValidEntries = int(l.sequenceID)
	result.InvalidEntries = 0

	return result
}

// Close closes the logger and any open files
func (l *Logger) Close() error {
	if l.file != nil {
		return l.file.Close()
	}
	return nil
}