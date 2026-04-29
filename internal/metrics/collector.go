package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// Collector holds all Prometheus metrics
type Collector struct {
	RequestsTotal       prometheus.Counter
	RequestDuration     prometheus.Histogram
	ThreatScoreGauge    prometheus.Gauge
	BlockedRequestsTotal prometheus.Counter
}

// NewCollector creates a new metrics collector and registers metrics
func NewCollector() *Collector {
	return &Collector{
		RequestsTotal: promauto.NewCounter(prometheus.CounterOpts{
			Name: "mcp_firewall_requests_total",
			Help: "Total number of HTTP requests processed",
		}),
		RequestDuration: promauto.NewHistogram(prometheus.HistogramOpts{
			Name:    "mcp_firewall_request_duration_seconds",
			Help:    "HTTP request duration in seconds",
			Buckets: prometheus.DefBuckets,
		}),
		ThreatScoreGauge: promauto.NewGauge(prometheus.GaugeOpts{
			Name: "mcp_firewall_threat_score",
			Help: "Current threat score gauge",
		}),
		BlockedRequestsTotal: promauto.NewCounter(prometheus.CounterOpts{
			Name: "mcp_firewall_blocked_requests_total",
			Help: "Total number of blocked requests",
		}),
	}
}
