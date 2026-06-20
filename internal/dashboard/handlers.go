package dashboard

import (
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
)

// DashboardAPI provides HTTP handlers for dashboard endpoints
type DashboardAPI struct {
	collector *StatsCollector
}

// NewDashboardAPI creates a new dashboard API
func NewDashboardAPI(collector *StatsCollector) *DashboardAPI {
	return &DashboardAPI{
		collector: collector,
	}
}

// GetDashboard returns the current dashboard statistics
func (api *DashboardAPI) GetDashboard(c *gin.Context) {
	dashboard := api.collector.GetDashboard()
	c.JSON(http.StatusOK, dashboard)
}

// GetStats returns simplified statistics for quick polling
func (api *DashboardAPI) GetStats(c *gin.Context) {
	dashboard := api.collector.GetDashboard()

	stats := gin.H{
		"uptime":               dashboard.Uptime,
		"total_requests":       dashboard.TotalRequests,
		"active_requests":      dashboard.ActiveRequests,
		"requests_per_second":  dashboard.RequestsPerSecond,
		"total_attacks_blocked": dashboard.TotalAttacksBlocked,
		"memory_usage":         dashboard.SystemStats.MemoryUsage,
		"goroutines":          dashboard.SystemStats.GoroutineCount,
		"last_updated":        dashboard.LastUpdated,
	}

	c.JSON(http.StatusOK, stats)
}

// GetAttackStats returns attack statistics by category
func (api *DashboardAPI) GetAttackStats(c *gin.Context) {
	dashboard := api.collector.GetDashboard()

	attackStats := gin.H{
		"total_attacks":    dashboard.TotalAttacksBlocked,
		"attacks_by_type":  dashboard.AttacksBlocked,
		"last_updated":     dashboard.LastUpdated,
	}

	c.JSON(http.StatusOK, attackStats)
}

// GetPerformanceStats returns performance-related statistics
func (api *DashboardAPI) GetPerformanceStats(c *gin.Context) {
	dashboard := api.collector.GetDashboard()

	perfStats := gin.H{
		"requests": gin.H{
			"total":               dashboard.TotalRequests,
			"active":             dashboard.ActiveRequests,
			"per_second_current": dashboard.RequestsPerSecond,
			"per_second_peak":    dashboard.PeakRequestsPerSec,
			"per_second_average": dashboard.AvgRequestsPerSec,
		},
		"response_times": gin.H{
			"longest_ms": dashboard.LongestRequestTime.Milliseconds(),
			"average_ms": dashboard.AverageRequestTime.Milliseconds(),
			"median_ms":  dashboard.MedianRequestTime.Milliseconds(),
		},
		"throughput": gin.H{
			"bytes_processed":   dashboard.BytesProcessed,
			"bytes_transferred": dashboard.BytesTransferred,
		},
		"system": dashboard.SystemStats,
		"last_updated": dashboard.LastUpdated,
	}

	c.JSON(http.StatusOK, perfStats)
}

// GetRecentRequests returns recent request history
func (api *DashboardAPI) GetRecentRequests(c *gin.Context) {
	dashboard := api.collector.GetDashboard()

	// Get limit from query parameter (default 50, max 100)
	limitStr := c.DefaultQuery("limit", "50")
	limit, err := strconv.Atoi(limitStr)
	if err != nil || limit <= 0 {
		limit = 50
	}
	if limit > 100 {
		limit = 100
	}

	recentRequests := dashboard.RecentRequests
	if len(recentRequests) > limit {
		recentRequests = recentRequests[len(recentRequests)-limit:]
	}

	c.JSON(http.StatusOK, gin.H{
		"requests":     recentRequests,
		"total_count":  len(dashboard.RecentRequests),
		"limit":        limit,
		"last_updated": dashboard.LastUpdated,
	})
}

// GetSystemStats returns system resource statistics
func (api *DashboardAPI) GetSystemStats(c *gin.Context) {
	dashboard := api.collector.GetDashboard()

	c.JSON(http.StatusOK, gin.H{
		"system":       dashboard.SystemStats,
		"uptime":       dashboard.Uptime,
		"start_time":   dashboard.StartTime,
		"last_config_update": dashboard.LastConfigUpdate,
		"last_updated": dashboard.LastUpdated,
	})
}

// GetHealthSummary returns a condensed health summary
func (api *DashboardAPI) GetHealthSummary(c *gin.Context) {
	dashboard := api.collector.GetDashboard()

	// Calculate health status
	healthStatus := "healthy"
	alerts := []string{}

	// Check for high memory usage (>80%)
	if dashboard.SystemStats.MemoryPercent > 80 {
		healthStatus = "warning"
		alerts = append(alerts, "High memory usage")
	}

	// Check for too many goroutines (>1000)
	if dashboard.SystemStats.GoroutineCount > 1000 {
		healthStatus = "warning"
		alerts = append(alerts, "High goroutine count")
	}

	// Check for high attack rate (>100 attacks in last minute)
	recentAttacks := uint64(0)
	oneMinuteAgo := time.Now().Add(-time.Minute)
	for _, req := range dashboard.RecentRequests {
		if req.StartTime.After(oneMinuteAgo) && len(req.AttacksFound) > 0 {
			recentAttacks += uint64(len(req.AttacksFound))
		}
	}
	if recentAttacks > 100 {
		healthStatus = "critical"
		alerts = append(alerts, "High attack rate detected")
	}

	// Check for slow response times (average >5 seconds)
	if dashboard.AverageRequestTime > 5*time.Second {
		healthStatus = "warning"
		alerts = append(alerts, "Slow response times")
	}

	summary := gin.H{
		"status":        healthStatus,
		"uptime":        dashboard.Uptime,
		"alerts":        alerts,
		"quick_stats": gin.H{
			"requests_total":    dashboard.TotalRequests,
			"requests_active":   dashboard.ActiveRequests,
			"attacks_blocked":   dashboard.TotalAttacksBlocked,
			"memory_usage_mb":   dashboard.SystemStats.MemoryUsage / 1024 / 1024,
			"rps_current":      dashboard.RequestsPerSecond,
		},
		"last_updated": dashboard.LastUpdated,
	}

	c.JSON(http.StatusOK, summary)
}

// ResetStats resets certain statistics (admin only)
func (api *DashboardAPI) ResetStats(c *gin.Context) {
	// Get reset type from query parameter
	resetType := c.DefaultQuery("type", "attacks")

	switch resetType {
	case "attacks":
		api.collector.mu.Lock()
		api.collector.dashboard.AttacksBlocked = make(map[AttackCategory]uint64)
		api.collector.dashboard.TotalAttacksBlocked = 0
		api.collector.mu.Unlock()
		c.JSON(http.StatusOK, gin.H{"message": "Attack statistics reset"})

	case "performance":
		api.collector.mu.Lock()
		api.collector.dashboard.LongestRequestTime = 0
		api.collector.dashboard.PeakRequestsPerSec = 0
		api.collector.requestTimes = api.collector.requestTimes[:0]
		api.collector.mu.Unlock()
		c.JSON(http.StatusOK, gin.H{"message": "Performance statistics reset"})

	case "requests":
		api.collector.mu.Lock()
		api.collector.dashboard.RecentRequests = api.collector.dashboard.RecentRequests[:0]
		api.collector.mu.Unlock()
		c.JSON(http.StatusOK, gin.H{"message": "Request history cleared"})

	default:
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid reset type. Options: attacks, performance, requests"})
	}
}

// RegisterRoutes registers all dashboard API routes
func (api *DashboardAPI) RegisterRoutes(router *gin.RouterGroup) {
	dashboard := router.Group("/dashboard")
	{
		// Main dashboard data
		dashboard.GET("/", api.GetDashboard)
		dashboard.GET("/stats", api.GetStats)
		dashboard.GET("/health", api.GetHealthSummary)

		// Specific statistics
		dashboard.GET("/attacks", api.GetAttackStats)
		dashboard.GET("/performance", api.GetPerformanceStats)
		dashboard.GET("/requests", api.GetRecentRequests)
		dashboard.GET("/system", api.GetSystemStats)

		// Admin endpoints
		dashboard.POST("/reset", api.ResetStats)
	}
}