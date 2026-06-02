package server

import (
	"fmt"
	"testing"
	"time"

	"github.com/aegishjalmur/aegir/internal/config"
	"github.com/aegishjalmur/aegir/internal/logging"
)

// newTestRateLimiter constructs a RateLimiter suitable for unit tests.
// We use a long cleanup interval to keep the background routine from
// interfering with assertions about the clients map.
func newTestRateLimiter(t *testing.T, maxTrackedIPs int) *RateLimiter {
	t.Helper()
	cfg := config.RateLimit{
		Enabled:         true,
		RequestsPerMin:  6000, // 100 rps — irrelevant for cap test, must allow
		BurstSize:       1000,
		CleanupInterval: 3600, // 1 hour, keep idle during the test
		MaxTrackedIPs:   maxTrackedIPs,
	}
	logCfg := config.Logging{
		Level:           "error",
		Format:          "json",
		HMACKey:         "test-hmac-key-32-characters-long",
		IntegrityChecks: false,
	}
	logger, err := logging.New(logCfg)
	if err != nil {
		t.Fatalf("failed to construct logger: %v", err)
	}
	return NewRateLimiter(cfg, logger)
}

// TestRateLimiterMemoryCap verifies that when MaxTrackedIPs is reached,
// GetLimiter evicts the oldest-last-seen entry before inserting a new one,
// keeping the clients map bounded — the fix for BUG-3 (ISC-2).
func TestRateLimiterMemoryCap(t *testing.T) {
	rl := newTestRateLimiter(t, 3)
	defer rl.Stop()

	// Insert three distinct client IPs with strictly increasing lastSeen
	// times so the eviction target is deterministic.
	ips := []string{"10.0.0.1", "10.0.0.2", "10.0.0.3"}
	for _, ip := range ips {
		rl.GetLimiter(ip)
		// Force a measurable gap so lastSeen ordering is stable.
		time.Sleep(2 * time.Millisecond)
	}

	if got := len(rl.clients); got != 3 {
		t.Fatalf("expected 3 clients after initial inserts, got %d", got)
	}

	// Insert a fourth IP — cap is 3, so the oldest (10.0.0.1) must be evicted.
	rl.GetLimiter("10.0.0.4")

	if got := len(rl.clients); got != 3 {
		t.Fatalf("expected len(clients) == 3 after eviction, got %d", got)
	}
	if _, present := rl.clients["10.0.0.1"]; present {
		t.Fatalf("expected oldest entry 10.0.0.1 to be evicted, still present")
	}
	if _, present := rl.clients["10.0.0.4"]; !present {
		t.Fatalf("expected newest entry 10.0.0.4 to be present")
	}
}

// TestGetLimiter_NoEvictionWhenCapDisabled verifies that a zero MaxTrackedIPs
// preserves the previous unbounded behaviour (opt-in cap).
func TestGetLimiter_NoEvictionWhenCapDisabled(t *testing.T) {
	rl := newTestRateLimiter(t, 0)
	defer rl.Stop()

	for i := 0; i < 10; i++ {
		rl.GetLimiter(fmt.Sprintf("10.0.0.%d", i))
	}
	if got := len(rl.clients); got != 10 {
		t.Fatalf("expected 10 clients with cap disabled, got %d", got)
	}
}

// TestRateLimiterRotation verifies that an IP-rotation attack using a large
// number of unique source IPs does not grow the clients map beyond MaxTrackedIPs
// (ISC-3 / BUG-3 fix).  Memory growth is the signal: if the cap is enforced the
// map size stays constant after the first cap-fill.
func TestRateLimiterRotation(t *testing.T) {
	const cap = 100
	rl := newTestRateLimiter(t, cap)
	defer rl.Stop()

	// Simulate an attacker cycling through many unique IPs.
	for i := 0; i < 10_000; i++ {
		rl.GetLimiter(fmt.Sprintf("203.0.113.%d.%d", i/256, i%256))
		// The map must never grow beyond the cap.
		if got := len(rl.clients); got > cap {
			t.Fatalf("clients map grew to %d (cap=%d) after %d inserts — memory not bounded", got, cap, i+1)
		}
	}

	if got := len(rl.clients); got > cap {
		t.Fatalf("final map size %d exceeds cap %d", got, cap)
	}
}
