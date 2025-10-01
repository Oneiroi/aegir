package dashboard

import (
	"fmt"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/aegishjalmur/mcp-firewall/internal/logging"
)

// AttackCategory represents different types of attacks detected
type AttackCategory string

const (
	AttackPromptInjection     AttackCategory = "prompt_injection"
	AttackJailbreak          AttackCategory = "jailbreak"
	AttackRoleEscalation     AttackCategory = "role_escalation"
	AttackEmotionalManip     AttackCategory = "emotional_manipulation"
	AttackTemplateInjection  AttackCategory = "template_injection"
	AttackCommandInjection   AttackCategory = "command_injection"
	AttackXSS               AttackCategory = "xss"
	AttackSQLInjection      AttackCategory = "sql_injection"
	AttackSecretExposure    AttackCategory = "secret_exposure"
	AttackComplianceViolation AttackCategory = "compliance_violation"
	AttackRateLimit         AttackCategory = "rate_limit"
)

// RequestStats tracks individual request statistics
type RequestStats struct {
	StartTime    time.Time     `json:"start_time"`
	Duration     time.Duration `json:"duration"`
	Method       string        `json:"method"`
	Path         string        `json:"path"`
	StatusCode   int           `json:"status_code"`
	BytesIn      int64         `json:"bytes_in"`
	BytesOut     int64         `json:"bytes_out"`
	UserAgent    string        `json:"user_agent"`
	ClientIP     string        `json:"client_ip"`
	AttacksFound []AttackCategory `json:"attacks_found"`
}

// SystemStats tracks system resource usage
type SystemStats struct {
	MemoryUsage    uint64    `json:"memory_usage_bytes"`
	MemoryPercent  float64   `json:"memory_percent"`
	CPUPercent     float64   `json:"cpu_percent"`
	GoroutineCount int       `json:"goroutine_count"`
	GCCount        uint64    `json:"gc_count"`
	LastGCTime     time.Time `json:"last_gc_time"`
}

// Dashboard represents the main dashboard statistics
type Dashboard struct {
	// Server lifecycle
	StartTime        time.Time `json:"start_time"`
	LastConfigUpdate time.Time `json:"last_config_update"`
	Uptime          string    `json:"uptime"`

	// Request statistics
	TotalRequests       uint64  `json:"total_requests"`
	ActiveRequests      uint64  `json:"active_requests"`
	RequestsPerSecond   float64 `json:"requests_per_second"`
	PeakRequestsPerSec  float64 `json:"peak_requests_per_sec"`
	AvgRequestsPerSec   float64 `json:"avg_requests_per_sec"`

	// Response time statistics
	LongestRequestTime  time.Duration `json:"longest_request_time"`
	AverageRequestTime  time.Duration `json:"average_request_time"`
	MedianRequestTime   time.Duration `json:"median_request_time"`

	// Attack statistics by category
	AttacksBlocked      map[AttackCategory]uint64 `json:"attacks_blocked"`
	TotalAttacksBlocked uint64                    `json:"total_attacks_blocked"`

	// System resources
	SystemStats SystemStats `json:"system_stats"`

	// Recent requests (last 100)
	RecentRequests []RequestStats `json:"recent_requests"`

	// Performance metrics
	BytesProcessed     uint64    `json:"bytes_processed"`
	BytesTransferred   uint64    `json:"bytes_transferred"`
	LastUpdated        time.Time `json:"last_updated"`
}

// StatsCollector collects and maintains dashboard statistics
type StatsCollector struct {
	mu           sync.RWMutex
	dashboard    *Dashboard
	logger       *logging.Logger

	// Internal tracking
	requestTimes      []time.Duration
	requestStartTimes map[string]time.Time
	rpsCalculator     *rpsCalculator
}

// rpsCalculator calculates requests per second with rolling window
type rpsCalculator struct {
	mu       sync.Mutex
	requests []time.Time
	window   time.Duration
}

// NewStatsCollector creates a new statistics collector
func NewStatsCollector(logger *logging.Logger) *StatsCollector {
	now := time.Now()

	return &StatsCollector{
		dashboard: &Dashboard{
			StartTime:           now,
			LastConfigUpdate:    now,
			AttacksBlocked:      make(map[AttackCategory]uint64),
			RecentRequests:      make([]RequestStats, 0, 100),
			LastUpdated:         now,
		},
		logger:            logger,
		requestStartTimes: make(map[string]time.Time),
		requestTimes:      make([]time.Duration, 0, 1000),
		rpsCalculator:     newRPSCalculator(60 * time.Second), // 1-minute window
	}
}

// newRPSCalculator creates a new RPS calculator
func newRPSCalculator(window time.Duration) *rpsCalculator {
	return &rpsCalculator{
		requests: make([]time.Time, 0, 1000),
		window:   window,
	}
}

// RecordRequest starts tracking a new request
func (sc *StatsCollector) RecordRequest(requestID, method, path, clientIP, userAgent string) {
	now := time.Now()

	sc.mu.Lock()
	defer sc.mu.Unlock()

	// Track request start
	sc.requestStartTimes[requestID] = now

	// Increment counters
	atomic.AddUint64(&sc.dashboard.TotalRequests, 1)
	atomic.AddUint64(&sc.dashboard.ActiveRequests, 1)

	// Update RPS calculator
	sc.rpsCalculator.addRequest(now)

	sc.logger.LogSecurityEvent(&logging.SecurityEvent{
		Type:      "request_started",
		Severity:  "info",
		Message:   "Request started",
		ClientIP:  clientIP,
		Details: map[string]string{
			"request_id": requestID,
			"method":     method,
			"path":       path,
		},
		Timestamp: time.Now(),
	})
}

// FinishRequest completes tracking a request
func (sc *StatsCollector) FinishRequest(requestID string, statusCode int, bytesIn, bytesOut int64, attacksFound []AttackCategory) {
	now := time.Now()

	sc.mu.Lock()
	defer sc.mu.Unlock()

	// Get start time
	startTime, exists := sc.requestStartTimes[requestID]
	if !exists {
		return
	}
	delete(sc.requestStartTimes, requestID)

	// Calculate duration
	duration := now.Sub(startTime)

	// Update request times
	sc.requestTimes = append(sc.requestTimes, duration)
	if len(sc.requestTimes) > 1000 {
		sc.requestTimes = sc.requestTimes[100:] // Keep last 900
	}

	// Update longest request time
	if duration > sc.dashboard.LongestRequestTime {
		sc.dashboard.LongestRequestTime = duration
	}

	// Update attack statistics
	for _, attack := range attacksFound {
		sc.dashboard.AttacksBlocked[attack]++
		atomic.AddUint64(&sc.dashboard.TotalAttacksBlocked, 1)
	}

	// Create request stats
	requestStats := RequestStats{
		StartTime:    startTime,
		Duration:     duration,
		StatusCode:   statusCode,
		BytesIn:      bytesIn,
		BytesOut:     bytesOut,
		AttacksFound: attacksFound,
	}

	// Add to recent requests (keep last 100)
	sc.dashboard.RecentRequests = append(sc.dashboard.RecentRequests, requestStats)
	if len(sc.dashboard.RecentRequests) > 100 {
		sc.dashboard.RecentRequests = sc.dashboard.RecentRequests[1:]
	}

	// Update byte counters
	atomic.AddUint64(&sc.dashboard.BytesProcessed, uint64(bytesIn))
	atomic.AddUint64(&sc.dashboard.BytesTransferred, uint64(bytesOut))

	// Decrement active requests
	atomic.AddUint64(&sc.dashboard.ActiveRequests, ^uint64(0)) // Subtract 1

	sc.logger.LogSecurityEvent(&logging.SecurityEvent{
		Type:     "request_completed",
		Severity: "info",
		Message:  "Request completed",
		Details: map[string]string{
			"request_id":    requestID,
			"duration_ms":   fmt.Sprintf("%d", duration.Milliseconds()),
			"status_code":   fmt.Sprintf("%d", statusCode),
			"attacks_found": fmt.Sprintf("%d", len(attacksFound)),
		},
		Timestamp: time.Now(),
	})
}

// RecordAttack records a specific attack detection
func (sc *StatsCollector) RecordAttack(category AttackCategory, details map[string]interface{}) {
	sc.mu.Lock()
	defer sc.mu.Unlock()

	sc.dashboard.AttacksBlocked[category]++
	atomic.AddUint64(&sc.dashboard.TotalAttacksBlocked, 1)

	detailsStr := make(map[string]string)
	for k, v := range details {
		detailsStr[k] = fmt.Sprintf("%v", v)
	}

	sc.logger.LogSecurityEvent(&logging.SecurityEvent{
		Type:      "attack_blocked",
		Severity:  "warning",
		Message:   fmt.Sprintf("Attack blocked: %s", string(category)),
		Details:   detailsStr,
		Timestamp: time.Now(),
	})
}

// UpdateConfigTimestamp updates the last configuration update time
func (sc *StatsCollector) UpdateConfigTimestamp() {
	sc.mu.Lock()
	defer sc.mu.Unlock()

	sc.dashboard.LastConfigUpdate = time.Now()
}

// GetDashboard returns current dashboard statistics
func (sc *StatsCollector) GetDashboard() *Dashboard {
	sc.mu.RLock()
	defer sc.mu.RUnlock()

	// Create a copy of the dashboard
	dashboard := *sc.dashboard

	// Calculate derived statistics
	now := time.Now()
	dashboard.Uptime = now.Sub(dashboard.StartTime).Round(time.Second).String()
	dashboard.LastUpdated = now

	// Calculate average request time
	if len(sc.requestTimes) > 0 {
		var total time.Duration
		for _, rt := range sc.requestTimes {
			total += rt
		}
		dashboard.AverageRequestTime = total / time.Duration(len(sc.requestTimes))

		// Calculate median (simple approach)
		if len(sc.requestTimes) > 0 {
			sorted := make([]time.Duration, len(sc.requestTimes))
			copy(sorted, sc.requestTimes)
			// Simple bubble sort for small arrays
			for i := 0; i < len(sorted); i++ {
				for j := i + 1; j < len(sorted); j++ {
					if sorted[i] > sorted[j] {
						sorted[i], sorted[j] = sorted[j], sorted[i]
					}
				}
			}
			dashboard.MedianRequestTime = sorted[len(sorted)/2]
		}
	}

	// Update RPS statistics
	dashboard.RequestsPerSecond = sc.rpsCalculator.getCurrentRPS()
	dashboard.AvgRequestsPerSec = sc.rpsCalculator.getAverageRPS()
	if dashboard.RequestsPerSecond > dashboard.PeakRequestsPerSec {
		dashboard.PeakRequestsPerSec = dashboard.RequestsPerSecond
	}

	// Update system statistics
	dashboard.SystemStats = sc.getSystemStats()

	return &dashboard
}

// getSystemStats collects current system statistics
func (sc *StatsCollector) getSystemStats() SystemStats {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	return SystemStats{
		MemoryUsage:    m.Alloc,
		MemoryPercent:  float64(m.Alloc) / float64(m.Sys) * 100,
		GoroutineCount: runtime.NumGoroutine(),
		GCCount:        uint64(m.NumGC),
		LastGCTime:     time.Unix(0, int64(m.LastGC)),
	}
}

// addRequest adds a request timestamp to the RPS calculator
func (rps *rpsCalculator) addRequest(timestamp time.Time) {
	rps.mu.Lock()
	defer rps.mu.Unlock()

	// Add new request
	rps.requests = append(rps.requests, timestamp)

	// Remove old requests outside the window
	cutoff := timestamp.Add(-rps.window)
	for i, req := range rps.requests {
		if req.After(cutoff) {
			rps.requests = rps.requests[i:]
			break
		}
	}

	// Prevent memory leak
	if len(rps.requests) > 10000 {
		rps.requests = rps.requests[1000:]
	}
}

// getCurrentRPS calculates current requests per second
func (rps *rpsCalculator) getCurrentRPS() float64 {
	rps.mu.Lock()
	defer rps.mu.Unlock()

	now := time.Now()
	cutoff := now.Add(-rps.window)

	count := 0
	for _, req := range rps.requests {
		if req.After(cutoff) {
			count++
		}
	}

	return float64(count) / rps.window.Seconds()
}

// getAverageRPS calculates average requests per second
func (rps *rpsCalculator) getAverageRPS() float64 {
	rps.mu.Lock()
	defer rps.mu.Unlock()

	if len(rps.requests) < 2 {
		return 0
	}

	oldest := rps.requests[0]
	newest := rps.requests[len(rps.requests)-1]
	duration := newest.Sub(oldest)

	if duration.Seconds() == 0 {
		return 0
	}

	return float64(len(rps.requests)) / duration.Seconds()
}