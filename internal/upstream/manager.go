package upstream

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/rand"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/aegishjalmur/aegir/internal/config"
	"github.com/aegishjalmur/aegir/internal/logging"
)

// hostResolver is the interface used by secureDialContext for DNS lookups.
// The default implementation wraps net.DefaultResolver; tests may substitute
// a mock to simulate DNS rebinding without real DNS queries.
type hostResolver interface {
	LookupHost(ctx context.Context, host string) ([]string, error)
}

// dnsResolver is the active hostResolver. Tests replace this to inject controlled
// DNS responses (e.g., a hostname that "rebinds" to a restricted IP).
var dnsResolver hostResolver = net.DefaultResolver

// UpstreamTLSConfig holds mTLS and certificate-pinning settings that are
// applied manager-wide (across all upstream services).  These are separate
// from the per-service config.UpstreamTLS fields so that the shared
// config.go file does not need to be modified.
type UpstreamTLSConfig struct {
	// CertPin is the expected SHA-256 fingerprint (lowercase hex, no colons) of
	// the upstream server's leaf certificate.  When non-empty every outbound TLS
	// handshake verifies this value; a mismatch causes an immediate rejection.
	CertPin string

	// ClientCert and ClientKey are PEM-encoded file paths for the client
	// certificate used in mTLS.  Both must be set together or not at all.
	ClientCert string
	ClientKey  string
}

// secureDialContext is a net.Dialer-compatible DialContext that defends against
// DNS rebinding (TOCTOU) attacks by resolving the destination host once,
// validating every resolved IP against the SSRF policy enforced by
// validateResourceURI, and then dialing the validated IP directly so that
// the network stack does not perform a second resolution at connection time.
func secureDialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("invalid address %q: %w", addr, err)
	}

	// Reject internal hostnames at the dial layer too. validateResourceURI
	// already catches these at parse time, but defence-in-depth.
	lower := strings.ToLower(host)
	if lower == "localhost" || strings.HasSuffix(lower, ".localhost") || lower == "metadata.google.internal" {
		return nil, fmt.Errorf("SSRF blocked: internal hostname %q is not allowed", host)
	}

	// If the host is already a literal IP, validate it directly. Otherwise
	// resolve once and validate every returned address.
	var addrs []string
	if ip := net.ParseIP(host); ip != nil {
		if isRestrictedIP(ip) {
			return nil, fmt.Errorf("SSRF blocked: IP %s is in a restricted range", ip.String())
		}
		addrs = []string{ip.String()}
	} else {
		resolved, lookupErr := dnsResolver.LookupHost(ctx, host)
		if lookupErr != nil {
			return nil, fmt.Errorf("dns lookup failed for %q: %w", host, lookupErr)
		}
		if len(resolved) == 0 {
			return nil, fmt.Errorf("dns lookup returned no addresses for %q", host)
		}
		for _, a := range resolved {
			ip := net.ParseIP(a)
			if ip == nil {
				return nil, fmt.Errorf("SSRF blocked: resolver returned unparseable address %q for %q", a, host)
			}
			if isRestrictedIP(ip) {
				return nil, fmt.Errorf("SSRF blocked: hostname %q resolved to restricted IP %s", host, ip.String())
			}
		}
		addrs = resolved
	}

	// Dial the first validated address directly so the kernel cannot perform
	// a second DNS lookup that might return an attacker-controlled IP.
	dialer := &net.Dialer{Timeout: 30 * time.Second}
	return dialer.DialContext(ctx, network, net.JoinHostPort(addrs[0], port))
}

// isRestrictedIP mirrors the SSRF policy enforced by validateResourceURI in
// the server package. Any change here must be mirrored there.
func isRestrictedIP(ip net.IP) bool {
	return ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsPrivate() || ip.IsUnspecified() || ip.IsMulticast()
}

// ServiceState represents the current state of an upstream service
type ServiceState struct {
	Service           *config.UpstreamService
	Healthy           bool
	LastCheck         time.Time
	FailureCount      int
	CircuitState      CircuitState
	LastError         error
	ActiveConnections int64
}

// CircuitState represents the circuit breaker state
type CircuitState int

const (
	CircuitClosed CircuitState = iota
	CircuitOpen
	CircuitHalfOpen
)

// Manager handles upstream service discovery, load balancing, and health checking
type Manager struct {
	config        *config.Upstream
	logger        *logging.Logger
	services      map[string]*ServiceState
	servicesMutex sync.RWMutex
	httpClient    *http.Client
	currentIndex  int
	indexMutex    sync.Mutex
	tlsCfg        UpstreamTLSConfig
	tlsCfgMu      sync.RWMutex
}

// MCPRequest represents a request to forward to upstream services
type MCPRequest struct {
	Method string      `json:"method"`
	Params interface{} `json:"params"`
	ID     interface{} `json:"id"`
}

// MCPResponse represents a response from upstream services
type MCPResponse struct {
	Result interface{} `json:"result,omitempty"`
	Error  *MCPError   `json:"error,omitempty"`
	ID     interface{} `json:"id"`
	// Headers carries the upstream HTTP response's headers (not part of the
	// JSON-RPC envelope, never marshalled back to the client). ISC-169/170:
	// lets the gateway scan for credential-shaped values an upstream server
	// leaked via a response header before anything is forwarded.
	Headers http.Header `json:"-"`
}

// MCPError represents an MCP error
type MCPError struct {
	Code    int         `json:"code"`
	Message string      `json:"message"`
	Data    interface{} `json:"data,omitempty"`
}

// NewManager creates a new upstream service manager
func NewManager(config *config.Upstream, logger *logging.Logger) *Manager {
	m := &Manager{
		config:   config,
		logger:   logger,
		services: make(map[string]*ServiceState),
		httpClient: &http.Client{
			Timeout: time.Duration(config.HealthCheck.Timeout) * time.Second,
			Transport: &http.Transport{
				DialContext: secureDialContext,
			},
		},
	}

	// Initialize services from configuration
	for _, service := range config.Services {
		if service.Enabled {
			m.services[service.Name] = &ServiceState{
				Service:      &service,
				Healthy:      true, // Assume healthy initially
				LastCheck:    time.Now(),
				FailureCount: 0,
				CircuitState: CircuitClosed,
			}
		}
	}

	// Start health checking if enabled
	if config.HealthCheck.Enabled {
		go m.startHealthChecking()
	}

	// Start service discovery if enabled
	if config.Discovery.Enabled {
		go m.startServiceDiscovery()
	}

	return m
}

// ConfigureTLS sets or replaces the manager-wide mTLS / cert-pinning config.
// It validates that the provided client certificate files can actually be
// loaded (when specified) and returns an error without updating state if
// validation fails.  It is safe to call concurrently with ForwardRequest.
func (m *Manager) ConfigureTLS(tlsCfg UpstreamTLSConfig) error {
	// Validate client-cert pair up front so callers get an immediate,
	// actionable error rather than a silent failure at connection time.
	if (tlsCfg.ClientCert != "") != (tlsCfg.ClientKey != "") {
		return fmt.Errorf("upstream mTLS: ClientCert and ClientKey must both be set or both be empty")
	}
	if tlsCfg.ClientCert != "" {
		if _, err := tls.LoadX509KeyPair(tlsCfg.ClientCert, tlsCfg.ClientKey); err != nil {
			return fmt.Errorf("upstream mTLS: failed to load client certificate: %w", err)
		}
	}

	// Normalise the pin to lowercase so comparisons are case-insensitive.
	if tlsCfg.CertPin != "" {
		tlsCfg.CertPin = strings.ToLower(tlsCfg.CertPin)
		// Sanity-check: a SHA-256 hex digest is exactly 64 characters.
		if len(tlsCfg.CertPin) != 64 {
			return fmt.Errorf("upstream mTLS: CertPin must be a 64-character hex-encoded SHA-256 digest, got %d chars", len(tlsCfg.CertPin))
		}
		if _, err := hex.DecodeString(tlsCfg.CertPin); err != nil {
			return fmt.Errorf("upstream mTLS: CertPin is not valid hex: %w", err)
		}
	}

	m.tlsCfgMu.Lock()
	m.tlsCfg = tlsCfg
	m.tlsCfgMu.Unlock()
	return nil
}

// ForwardRequest forwards an MCP request to an appropriate upstream service
func (m *Manager) ForwardRequest(ctx context.Context, req *MCPRequest) (*MCPResponse, error) {
	// Select an upstream service based on load balancing strategy
	service, err := m.selectService(req)
	if err != nil {
		return nil, fmt.Errorf("no available upstream services: %w", err)
	}

	// Forward the request with retries
	return m.forwardWithRetries(ctx, service, req)
}

// selectService selects an upstream service based on the configured load balancing strategy
func (m *Manager) selectService(req *MCPRequest) (*ServiceState, error) {
	m.servicesMutex.RLock()
	defer m.servicesMutex.RUnlock()

	// Filter healthy services
	var healthyServices []*ServiceState
	for _, service := range m.services {
		if service.Healthy && service.CircuitState != CircuitOpen {
			healthyServices = append(healthyServices, service)
		}
	}

	if len(healthyServices) == 0 {
		return nil, fmt.Errorf("no healthy upstream services available")
	}

	switch m.config.LoadBalancing.Strategy {
	case "round_robin":
		return m.selectRoundRobin(healthyServices), nil
	case "weighted":
		return m.selectWeighted(healthyServices), nil
	case "random":
		return m.selectRandom(healthyServices), nil
	case "least_connections":
		// For simplicity, fallback to round robin
		// In production, track active connections per service
		return m.selectRoundRobin(healthyServices), nil
	default:
		return m.selectRoundRobin(healthyServices), nil
	}
}

// selectRoundRobin implements round-robin load balancing
func (m *Manager) selectRoundRobin(services []*ServiceState) *ServiceState {
	m.indexMutex.Lock()
	defer m.indexMutex.Unlock()

	service := services[m.currentIndex%len(services)]
	m.currentIndex++
	return service
}

// selectWeighted implements weighted load balancing
func (m *Manager) selectWeighted(services []*ServiceState) *ServiceState {
	totalWeight := 0
	for _, service := range services {
		totalWeight += service.Service.Weight
	}

	if totalWeight == 0 {
		return m.selectRoundRobin(services)
	}

	r := rand.Intn(totalWeight)
	for _, service := range services {
		r -= service.Service.Weight
		if r <= 0 {
			return service
		}
	}

	return services[0] // fallback
}

// selectRandom implements random load balancing
func (m *Manager) selectRandom(services []*ServiceState) *ServiceState {
	return services[rand.Intn(len(services))]
}

// selectLeastConnections selects the service with the fewest active connections
func (m *Manager) selectLeastConnections(services []*ServiceState) *ServiceState {
	if len(services) == 0 {
		return nil
	}

	minConns := services[0].ActiveConnections
	selected := services[0]

	for _, service := range services[1:] {
		if service.ActiveConnections < minConns {
			minConns = service.ActiveConnections
			selected = service
		}
	}

	return selected
}

// forwardWithRetries forwards a request with retry logic
func (m *Manager) forwardWithRetries(ctx context.Context, service *ServiceState, req *MCPRequest) (*MCPResponse, error) {
	var lastErr error
	maxRetries := 1
	if m.config.Retry.Enabled {
		maxRetries = m.config.Retry.MaxRetries + 1
	}

	for attempt := 0; attempt < maxRetries; attempt++ {
		// Check circuit breaker
		if service.CircuitState == CircuitOpen {
			if time.Since(service.LastCheck) > time.Duration(m.config.CircuitBreaker.RecoveryTimeout)*time.Second {
				service.CircuitState = CircuitHalfOpen
				m.logger.Info("Circuit breaker entering half-open state", "service", service.Service.Name)
			} else {
				return nil, fmt.Errorf("circuit breaker open for service %s", service.Service.Name)
			}
		}

		// Forward the request
		response, err := m.forwardRequest(ctx, service, req)
		if err == nil {
			// Success - reset failure count and close circuit
			service.FailureCount = 0
			service.CircuitState = CircuitClosed
			return response, nil
		}

		lastErr = err
		m.recordFailure(service)

		// Don't retry on the last attempt
		if attempt < maxRetries-1 && m.config.Retry.Enabled {
			// Calculate backoff
			backoff := time.Duration(m.config.Retry.BackoffMs*(attempt+1)) * time.Millisecond
			if maxBackoff := time.Duration(m.config.Retry.MaxBackoffMs) * time.Millisecond; backoff > maxBackoff {
				backoff = maxBackoff
			}

			m.logger.Warn("Request failed, retrying",
				"service", service.Service.Name,
				"attempt", attempt+1,
				"backoff", backoff,
				"error", err)

			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(backoff):
				// Continue to next attempt
			}
		}
	}

	return nil, fmt.Errorf("all retry attempts failed: %w", lastErr)
}

// forwardRequest forwards a single request to an upstream service
func (m *Manager) forwardRequest(ctx context.Context, service *ServiceState, req *MCPRequest) (*MCPResponse, error) {
	// Increment active connections
	service.ActiveConnections++
	defer func() {
		service.ActiveConnections--
	}()

	// Create HTTP client with appropriate timeout and TLS settings
	client := m.createHTTPClient(service)

	// Marshal request
	reqBody, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	// Create HTTP request
	httpReq, err := http.NewRequestWithContext(ctx, "POST", service.Service.URL+"/mcp", bytes.NewBuffer(reqBody))
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP request: %w", err)
	}

	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("User-Agent", "MCP-Firewall/1.0")

	// Forward request
	resp, err := client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	// Parse response
	var mcpResp MCPResponse
	if err := json.NewDecoder(resp.Body).Decode(&mcpResp); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	// Check HTTP status
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("HTTP error %d", resp.StatusCode)
	}

	mcpResp.Headers = resp.Header.Clone()

	return &mcpResp, nil
}

// createHTTPClient creates an HTTP client with appropriate TLS and timeout settings
func (m *Manager) createHTTPClient(service *ServiceState) *http.Client {
	// Apply the same DNS-rebinding-resistant dialer here. This client is the
	// one used by ForwardRequest and checkServiceHealth, so the SSRF policy
	// must be enforced at this layer as well.
	transport := &http.Transport{
		DialContext: secureDialContext,
	}

	// Read manager-wide TLS config under the read-lock so that concurrent
	// ConfigureTLS calls cannot produce a torn read.
	m.tlsCfgMu.RLock()
	managerTLS := m.tlsCfg
	m.tlsCfgMu.RUnlock()

	// TLS is needed if the service requests it OR if the manager has
	// cert-pinning / mTLS configured.
	needTLS := service.Service.TLS.Enabled ||
		managerTLS.CertPin != "" ||
		managerTLS.ClientCert != ""

	if needTLS {
		tlsConfig := &tls.Config{
			InsecureSkipVerify: service.Service.TLS.SkipVerify, //nolint:gosec // controlled by explicit operator config
		}

		if service.Service.TLS.ServerName != "" {
			tlsConfig.ServerName = service.Service.TLS.ServerName
		}

		// Per-service client certificates (from config.UpstreamTLS).
		if service.Service.TLS.ClientCertFile != "" && service.Service.TLS.ClientKeyFile != "" {
			cert, err := tls.LoadX509KeyPair(service.Service.TLS.ClientCertFile, service.Service.TLS.ClientKeyFile)
			if err != nil {
				m.logger.Error("Failed to load client certificates", "error", err)
			} else {
				tlsConfig.Certificates = []tls.Certificate{cert}
			}
		}

		// Manager-wide mTLS client certificate (from UpstreamTLSConfig).
		// Overrides the per-service cert when both are provided.
		if managerTLS.ClientCert != "" && managerTLS.ClientKey != "" {
			cert, err := tls.LoadX509KeyPair(managerTLS.ClientCert, managerTLS.ClientKey)
			if err != nil {
				m.logger.Error("Failed to load manager-level mTLS client certificate", "error", err)
			} else {
				tlsConfig.Certificates = []tls.Certificate{cert}
			}
		}

		// SHA-256 certificate pinning.
		// VerifyPeerCertificate is called after the normal chain verification
		// (or in parallel when InsecureSkipVerify is true).  We pin the leaf
		// certificate — rawCerts[0] — by its DER SHA-256 digest.
		if managerTLS.CertPin != "" {
			expectedPin := managerTLS.CertPin
			logger := m.logger
			serviceName := service.Service.Name

			tlsConfig.VerifyPeerCertificate = func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
				if len(rawCerts) == 0 {
					return fmt.Errorf("upstream_cert_mismatch: no certificates presented by server")
				}
				// Compute SHA-256 of the leaf certificate DER bytes.
				digest := sha256.Sum256(rawCerts[0])
				actual := hex.EncodeToString(digest[:])

				if actual != expectedPin {
					logger.Error("upstream_cert_mismatch",
						"service", serviceName,
						"expected_pin", expectedPin,
						"actual_pin", actual,
					)
					return fmt.Errorf("upstream_cert_mismatch: certificate pin mismatch for service %q: expected %s got %s",
						serviceName, expectedPin, actual)
				}
				return nil
			}
		}

		transport.TLSClientConfig = tlsConfig
	}

	return &http.Client{
		Transport: transport,
		Timeout:   time.Duration(service.Service.Timeout) * time.Second,
	}
}

// recordFailure records a failure for a service and updates circuit breaker state
func (m *Manager) recordFailure(service *ServiceState) {
	service.FailureCount++
	service.LastError = fmt.Errorf("request failed at %v", time.Now())

	if m.config.CircuitBreaker.Enabled {
		if service.FailureCount >= m.config.CircuitBreaker.FailureThreshold {
			service.CircuitState = CircuitOpen
			m.logger.Warn("Circuit breaker opened",
				"service", service.Service.Name,
				"failures", service.FailureCount)
		}
	}
}

// startHealthChecking starts the health checking routine
func (m *Manager) startHealthChecking() {
	ticker := time.NewTicker(time.Duration(m.config.HealthCheck.Interval) * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			m.performHealthChecks()
		}
	}
}

// performHealthChecks performs health checks on all configured services
func (m *Manager) performHealthChecks() {
	m.servicesMutex.Lock()
	defer m.servicesMutex.Unlock()

	for name, service := range m.services {
		healthy := m.checkServiceHealth(service)

		if healthy != service.Healthy {
			m.logger.Info("Service health status changed",
				"service", name,
				"healthy", healthy,
				"previous", service.Healthy)
		}

		service.Healthy = healthy
		service.LastCheck = time.Now()
	}
}

// checkServiceHealth performs a health check on a single service
func (m *Manager) checkServiceHealth(service *ServiceState) bool {
	client := m.createHTTPClient(service)

	// Use health check path or default to service URL
	healthURL := service.Service.URL + m.config.HealthCheck.Path

	ctx, cancel := context.WithTimeout(context.Background(),
		time.Duration(m.config.HealthCheck.Timeout)*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET", healthURL, nil)
	if err != nil {
		return false
	}

	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	// Check if status code is in expected range
	for _, expectedCode := range m.config.HealthCheck.ExpectedCodes {
		if resp.StatusCode == expectedCode {
			return true
		}
	}

	return false
}

// startServiceDiscovery starts the service discovery routine
func (m *Manager) startServiceDiscovery() {
	if !m.config.Discovery.Enabled {
		return
	}

	ticker := time.NewTicker(time.Duration(m.config.Discovery.Interval) * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			m.performServiceDiscovery()
		}
	}
}

// performServiceDiscovery discovers services based on the configured provider
func (m *Manager) performServiceDiscovery() {
	switch m.config.Discovery.Provider {
	case "static":
		// Static configuration - no discovery needed
		return
	case "dns":
		m.discoverViaDNS()
	case "consul":
		m.discoverViaConsul()
	case "kubernetes":
		m.discoverViaKubernetes()
	default:
		m.logger.Warn("Unknown discovery provider", "provider", m.config.Discovery.Provider)
	}
}

// discoverViaDNS implements DNS-based service discovery
func (m *Manager) discoverViaDNS() {
	// DNS-based discovery implementation
	// This would involve DNS SRV record lookups
	m.logger.Debug("DNS-based service discovery not yet implemented")
}

// discoverViaConsul implements Consul-based service discovery
func (m *Manager) discoverViaConsul() {
	// Consul-based discovery implementation
	m.logger.Debug("Consul-based service discovery not yet implemented")
}

// discoverViaKubernetes implements Kubernetes-based service discovery
func (m *Manager) discoverViaKubernetes() {
	// Kubernetes-based discovery implementation
	m.logger.Debug("Kubernetes-based service discovery not yet implemented")
}

// GetServiceStatus returns the current status of all services
func (m *Manager) GetServiceStatus() map[string]interface{} {
	m.servicesMutex.RLock()
	defer m.servicesMutex.RUnlock()

	status := make(map[string]interface{})
	for name, service := range m.services {
		status[name] = map[string]interface{}{
			"healthy":       service.Healthy,
			"last_check":    service.LastCheck,
			"failure_count": service.FailureCount,
			"circuit_state": service.CircuitState,
			"url":           service.Service.URL,
		}
	}

	return status
}
