package config

import (
	"fmt"
	"os"
	"strconv"
	"time"
)

// Config holds all configuration for the MCP Firewall
type Config struct {
	Environment string     `json:"environment"`
	Server      Server     `json:"server"`
	Auth        Auth       `json:"auth"`
	Logging     Logging    `json:"logging"`
	Security    Security   `json:"security"`
	Compliance  Compliance `json:"compliance"`
	Upstream    Upstream   `json:"upstream"`
}

// Server configuration
type Server struct {
	Port         int    `json:"port"`
	Host         string `json:"host"`
	ReadTimeout  int    `json:"read_timeout"`
	WriteTimeout int    `json:"write_timeout"`
	TLS          TLS    `json:"tls"`
}

// TLS configuration
type TLS struct {
	Enabled  bool   `json:"enabled"`
	CertFile string `json:"cert_file"`
	KeyFile  string `json:"key_file"`
	MinTLS   string `json:"min_tls"`
}

// Auth configuration
type Auth struct {
	JWT     JWT     `json:"jwt"`
	OAuth   OAuth   `json:"oauth"`
	APIKeys APIKeys `json:"api_keys"`
	MFA     MFA     `json:"mfa"`
}

// JWT configuration
type JWT struct {
	Secret            string        `json:"secret"`
	Issuer            string        `json:"issuer"`
	ExpirationTime    time.Duration `json:"expiration_time"`
	RefreshExpiration time.Duration `json:"refresh_expiration"`
}

// OAuth configuration
type OAuth struct {
	Enabled      bool   `json:"enabled"`
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
	RedirectURL  string `json:"redirect_url"`
	AuthURL      string `json:"auth_url"`
	TokenURL     string `json:"token_url"`
}

// APIKeys configuration
type APIKeys struct {
	Enabled bool `json:"enabled"`
}

// MFA configuration
type MFA struct {
	Required  bool `json:"required"`
	Providers []string `json:"providers"`
}

// Logging configuration
type Logging struct {
	Level           string `json:"level"`
	Format          string `json:"format"`
	File            string `json:"file"`
	MaxSize         int    `json:"max_size"`
	MaxBackups      int    `json:"max_backups"`
	MaxAge          int    `json:"max_age"`
	Compress        bool   `json:"compress"`
	HMACKey         string `json:"hmac_key"`
	IntegrityChecks bool   `json:"integrity_checks"`
}

// Security configuration
type Security struct {
	RateLimit         RateLimit         `json:"rate_limit"`
	Sanitization      Sanitization      `json:"sanitization"`
	Encryption        Encryption        `json:"encryption"`
	SecretDetection   SecretDetection   `json:"secret_detection"`
	CommandInjection  CommandInjection  `json:"command_injection"`
}

// RateLimit configuration
type RateLimit struct {
	Enabled         bool `json:"enabled"`
	RequestsPerMin  int  `json:"requests_per_min"`
	BurstSize       int  `json:"burst_size"`
	CleanupInterval int  `json:"cleanup_interval"`
}

// Sanitization configuration
type Sanitization struct {
	Enabled           bool `json:"enabled"`
	XSSPrevention     bool `json:"xss_prevention"`
	SQLInjection      bool `json:"sql_injection"`
	HomoglyphFilter   bool `json:"homoglyph_filter"`
	FormulaDetection  bool `json:"formula_detection"`
	PromptInjection   bool `json:"prompt_injection"`
}

// Encryption configuration
type Encryption struct {
	Algorithm    string `json:"algorithm"`
	KeySize      int    `json:"key_size"`
	KeyRotation  int    `json:"key_rotation_days"`
	HardwareHSM  bool   `json:"hardware_hsm"`
	CloudKMS     string `json:"cloud_kms"`
}

// SecretDetection configuration
type SecretDetection struct {
	Enabled       bool     `json:"enabled"`
	APIKeys       bool     `json:"api_keys"`
	SSHKeys       bool     `json:"ssh_keys"`
	Certificates  bool     `json:"certificates"`
	Passwords     bool     `json:"passwords"`
	CustomPatterns []string `json:"custom_patterns"`
}

// CommandInjection configuration
type CommandInjection struct {
	Enabled           bool     `json:"enabled"`
	BlockList         []string `json:"block_list"`
	AllowList         []string `json:"allow_list"`
	StrictMode        bool     `json:"strict_mode"`
}

// Compliance configuration
type Compliance struct {
	HIPAA HIPAAConfig `json:"hipaa"`
	PCI   PCIConfig   `json:"pci"`
	GDPR  GDPRConfig  `json:"gdpr"`
	SOC2  SOC2Config  `json:"soc2"`
}

// HIPAAConfig for HIPAA compliance
type HIPAAConfig struct {
	Enabled     bool `json:"enabled"`
	PHIDetection bool `json:"phi_detection"`
	Encryption  bool `json:"encryption"`
	AuditTrail  bool `json:"audit_trail"`
}

// PCIConfig for PCI DSS compliance
type PCIConfig struct {
	Enabled        bool `json:"enabled"`
	CardDetection  bool `json:"card_detection"`
	TokenizeCards  bool `json:"tokenize_cards"`
	EncryptStorage bool `json:"encrypt_storage"`
}

// GDPRConfig for GDPR compliance
type GDPRConfig struct {
	Enabled       bool   `json:"enabled"`
	PIIDetection  bool   `json:"pii_detection"`
	RightToErasure bool  `json:"right_to_erasure"`
	DataPortability bool `json:"data_portability"`
	ConsentTracking bool `json:"consent_tracking"`
	Region         string `json:"region"`
}

// SOC2Config for SOC 2 compliance
type SOC2Config struct {
	Enabled bool `json:"enabled"`
	Type2   bool `json:"type2"`
}

// Upstream configuration for MCP service discovery and proxying
type Upstream struct {
	Services         []UpstreamService `json:"services"`
	Discovery        Discovery         `json:"discovery"`
	LoadBalancing    LoadBalancing     `json:"load_balancing"`
	HealthCheck      HealthCheck       `json:"health_check"`
	CircuitBreaker   CircuitBreaker    `json:"circuit_breaker"`
	Retry            RetryConfig       `json:"retry"`
}

// UpstreamService represents a backend MCP service
type UpstreamService struct {
	Name        string            `json:"name"`
	URL         string            `json:"url"`
	Transport   string            `json:"transport"` // http, stdio, sse
	Weight      int               `json:"weight"`
	Priority    int               `json:"priority"`
	Tags        []string          `json:"tags"`
	Metadata    map[string]string `json:"metadata"`
	Enabled     bool              `json:"enabled"`
	TLS         UpstreamTLS       `json:"tls"`
	Timeout     int               `json:"timeout_seconds"`
}

// UpstreamTLS configuration for upstream connections
type UpstreamTLS struct {
	Enabled            bool   `json:"enabled"`
	SkipVerify         bool   `json:"skip_verify"`
	ClientCertFile     string `json:"client_cert_file"`
	ClientKeyFile      string `json:"client_key_file"`
	CACertFile         string `json:"ca_cert_file"`
	ServerName         string `json:"server_name"`
}

// Discovery configuration for service discovery
type Discovery struct {
	Enabled   bool   `json:"enabled"`
	Provider  string `json:"provider"`  // consul, dns, static, kubernetes
	Endpoint  string `json:"endpoint"`
	Namespace string `json:"namespace"`
	Interval  int    `json:"interval_seconds"`
}

// LoadBalancing configuration
type LoadBalancing struct {
	Strategy    string `json:"strategy"`     // round_robin, weighted, least_connections, random
	StickyKey   string `json:"sticky_key"`  // header or cookie name for sticky sessions
	HashKey     string `json:"hash_key"`    // for consistent hashing
}

// HealthCheck configuration
type HealthCheck struct {
	Enabled         bool   `json:"enabled"`
	Interval        int    `json:"interval_seconds"`
	Timeout         int    `json:"timeout_seconds"`
	HealthyThreshold   int    `json:"healthy_threshold"`
	UnhealthyThreshold int    `json:"unhealthy_threshold"`
	Path            string `json:"path"`
	ExpectedCodes   []int  `json:"expected_codes"`
}

// CircuitBreaker configuration
type CircuitBreaker struct {
	Enabled           bool  `json:"enabled"`
	FailureThreshold  int   `json:"failure_threshold"`
	RecoveryTimeout   int   `json:"recovery_timeout_seconds"`
	HalfOpenRequests  int   `json:"half_open_requests"`
}

// RetryConfig for upstream request retries
type RetryConfig struct {
	Enabled     bool  `json:"enabled"`
	MaxRetries  int   `json:"max_retries"`
	BackoffMs   int   `json:"backoff_ms"`
	MaxBackoffMs int   `json:"max_backoff_ms"`
}

// Load loads configuration from environment variables and defaults
func Load() (*Config, error) {
	cfg := &Config{
		Environment: getEnv("MCP_ENV", "development"),
		Server: Server{
			Port:         getEnvAsInt("PORT", 8443),
			Host:         getEnv("HOST", "localhost"),
			ReadTimeout:  getEnvAsInt("READ_TIMEOUT", 10),
			WriteTimeout: getEnvAsInt("WRITE_TIMEOUT", 10),
			TLS: TLS{
				Enabled:  getEnvAsBool("TLS_ENABLED", true),
				CertFile: getEnv("TLS_CERT_FILE", "certs/cert.pem"),
				KeyFile:  getEnv("TLS_KEY_FILE", "certs/key.pem"),
				MinTLS:   getEnv("TLS_MIN_VERSION", "1.3"),
			},
		},
		Auth: Auth{
			JWT: JWT{
				Secret:            getEnv("JWT_SECRET", generateRandomSecret()),
				Issuer:            getEnv("JWT_ISSUER", "mcp-firewall"),
				ExpirationTime:    time.Duration(getEnvAsInt("JWT_EXPIRATION", 3600)) * time.Second,
				RefreshExpiration: time.Duration(getEnvAsInt("JWT_REFRESH_EXPIRATION", 86400)) * time.Second,
			},
			OAuth: OAuth{
				Enabled:      getEnvAsBool("OAUTH_ENABLED", false),
				ClientID:     getEnv("OAUTH_CLIENT_ID", ""),
				ClientSecret: getEnv("OAUTH_CLIENT_SECRET", ""),
				RedirectURL:  getEnv("OAUTH_REDIRECT_URL", ""),
				AuthURL:      getEnv("OAUTH_AUTH_URL", ""),
				TokenURL:     getEnv("OAUTH_TOKEN_URL", ""),
			},
			APIKeys: APIKeys{
				Enabled: getEnvAsBool("API_KEYS_ENABLED", true),
			},
			MFA: MFA{
				Required:  getEnvAsBool("MFA_REQUIRED", false),
				Providers: []string{"totp", "sms"},
			},
		},
		Logging: Logging{
			Level:           getEnv("LOG_LEVEL", "info"),
			Format:          getEnv("LOG_FORMAT", "json"),
			File:            getEnv("LOG_FILE", "logs/mcp-firewall.log"),
			MaxSize:         getEnvAsInt("LOG_MAX_SIZE", 100),
			MaxBackups:      getEnvAsInt("LOG_MAX_BACKUPS", 10),
			MaxAge:          getEnvAsInt("LOG_MAX_AGE", 30),
			Compress:        getEnvAsBool("LOG_COMPRESS", true),
			HMACKey:         getEnv("LOG_HMAC_KEY", generateRandomSecret()),
			IntegrityChecks: getEnvAsBool("LOG_INTEGRITY_CHECKS", true),
		},
		Security: Security{
			RateLimit: RateLimit{
				Enabled:         getEnvAsBool("RATE_LIMIT_ENABLED", true),
				RequestsPerMin:  getEnvAsInt("RATE_LIMIT_RPM", 100),
				BurstSize:       getEnvAsInt("RATE_LIMIT_BURST", 20),
				CleanupInterval: getEnvAsInt("RATE_LIMIT_CLEANUP", 300),
			},
			Sanitization: Sanitization{
				Enabled:          getEnvAsBool("SANITIZATION_ENABLED", true),
				XSSPrevention:    getEnvAsBool("XSS_PREVENTION", true),
				SQLInjection:     getEnvAsBool("SQL_INJECTION_PREVENTION", true),
				HomoglyphFilter:  getEnvAsBool("HOMOGLYPH_FILTER", true),
				FormulaDetection: getEnvAsBool("FORMULA_DETECTION", true),
				PromptInjection:  getEnvAsBool("PROMPT_INJECTION_PREVENTION", true),
			},
			Encryption: Encryption{
				Algorithm:   getEnv("ENCRYPTION_ALGORITHM", "AES-256-GCM"),
				KeySize:     getEnvAsInt("ENCRYPTION_KEY_SIZE", 256),
				KeyRotation: getEnvAsInt("KEY_ROTATION_DAYS", 90),
				HardwareHSM: getEnvAsBool("HARDWARE_HSM", false),
				CloudKMS:    getEnv("CLOUD_KMS", ""),
			},
			SecretDetection: SecretDetection{
				Enabled:      getEnvAsBool("SECRET_DETECTION_ENABLED", true),
				APIKeys:      getEnvAsBool("DETECT_API_KEYS", true),
				SSHKeys:      getEnvAsBool("DETECT_SSH_KEYS", true),
				Certificates: getEnvAsBool("DETECT_CERTIFICATES", true),
				Passwords:    getEnvAsBool("DETECT_PASSWORDS", true),
			},
			CommandInjection: CommandInjection{
				Enabled:    getEnvAsBool("COMMAND_INJECTION_PREVENTION", true),
				StrictMode: getEnvAsBool("COMMAND_INJECTION_STRICT", true),
			},
		},
		Compliance: Compliance{
			HIPAA: HIPAAConfig{
				Enabled:     getEnvAsBool("HIPAA_ENABLED", false),
				PHIDetection: getEnvAsBool("PHI_DETECTION", false),
				Encryption:  getEnvAsBool("HIPAA_ENCRYPTION", false),
				AuditTrail:  getEnvAsBool("HIPAA_AUDIT", false),
			},
			PCI: PCIConfig{
				Enabled:        getEnvAsBool("PCI_ENABLED", false),
				CardDetection:  getEnvAsBool("CARD_DETECTION", false),
				TokenizeCards:  getEnvAsBool("TOKENIZE_CARDS", false),
				EncryptStorage: getEnvAsBool("PCI_ENCRYPT_STORAGE", false),
			},
			GDPR: GDPRConfig{
				Enabled:        getEnvAsBool("GDPR_ENABLED", false),
				PIIDetection:   getEnvAsBool("PII_DETECTION", false),
				RightToErasure: getEnvAsBool("RIGHT_TO_ERASURE", false),
				DataPortability: getEnvAsBool("DATA_PORTABILITY", false),
				ConsentTracking: getEnvAsBool("CONSENT_TRACKING", false),
				Region:         getEnv("GDPR_REGION", "EU"),
			},
			SOC2: SOC2Config{
				Enabled: getEnvAsBool("SOC2_ENABLED", false),
				Type2:   getEnvAsBool("SOC2_TYPE2", false),
			},
		},
		Upstream: Upstream{
			Services: []UpstreamService{
				{
					Name:      getEnv("UPSTREAM_SERVICE_NAME", "default-mcp-service"),
					URL:       getEnv("UPSTREAM_SERVICE_URL", "http://localhost:8080"),
					Transport: getEnv("UPSTREAM_TRANSPORT", "http"),
					Weight:    getEnvAsInt("UPSTREAM_WEIGHT", 100),
					Priority:  getEnvAsInt("UPSTREAM_PRIORITY", 1),
					Enabled:   getEnvAsBool("UPSTREAM_ENABLED", true),
					Timeout:   getEnvAsInt("UPSTREAM_TIMEOUT", 30),
					TLS: UpstreamTLS{
						Enabled:    getEnvAsBool("UPSTREAM_TLS_ENABLED", false),
						SkipVerify: getEnvAsBool("UPSTREAM_TLS_SKIP_VERIFY", false),
					},
				},
			},
			Discovery: Discovery{
				Enabled:  getEnvAsBool("DISCOVERY_ENABLED", false),
				Provider: getEnv("DISCOVERY_PROVIDER", "static"),
				Interval: getEnvAsInt("DISCOVERY_INTERVAL", 30),
			},
			LoadBalancing: LoadBalancing{
				Strategy: getEnv("LOAD_BALANCING_STRATEGY", "round_robin"),
			},
			HealthCheck: HealthCheck{
				Enabled:            getEnvAsBool("HEALTH_CHECK_ENABLED", true),
				Interval:           getEnvAsInt("HEALTH_CHECK_INTERVAL", 30),
				Timeout:            getEnvAsInt("HEALTH_CHECK_TIMEOUT", 5),
				HealthyThreshold:   getEnvAsInt("HEALTH_CHECK_HEALTHY_THRESHOLD", 2),
				UnhealthyThreshold: getEnvAsInt("HEALTH_CHECK_UNHEALTHY_THRESHOLD", 3),
				Path:               getEnv("HEALTH_CHECK_PATH", "/health"),
				ExpectedCodes:      []int{200, 204},
			},
			CircuitBreaker: CircuitBreaker{
				Enabled:          getEnvAsBool("CIRCUIT_BREAKER_ENABLED", true),
				FailureThreshold: getEnvAsInt("CIRCUIT_BREAKER_FAILURE_THRESHOLD", 5),
				RecoveryTimeout:  getEnvAsInt("CIRCUIT_BREAKER_RECOVERY_TIMEOUT", 60),
				HalfOpenRequests: getEnvAsInt("CIRCUIT_BREAKER_HALF_OPEN_REQUESTS", 3),
			},
			Retry: RetryConfig{
				Enabled:      getEnvAsBool("RETRY_ENABLED", true),
				MaxRetries:   getEnvAsInt("RETRY_MAX_RETRIES", 3),
				BackoffMs:    getEnvAsInt("RETRY_BACKOFF_MS", 100),
				MaxBackoffMs: getEnvAsInt("RETRY_MAX_BACKOFF_MS", 1000),
			},
		},
	}

	return cfg, nil
}

// Helper functions for environment variable parsing
func getEnv(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}

func getEnvAsInt(key string, fallback int) int {
	if value := os.Getenv(key); value != "" {
		if intVal, err := strconv.Atoi(value); err == nil {
			return intVal
		}
	}
	return fallback
}

func getEnvAsBool(key string, fallback bool) bool {
	if value := os.Getenv(key); value != "" {
		if boolVal, err := strconv.ParseBool(value); err == nil {
			return boolVal
		}
	}
	return fallback
}

func generateRandomSecret() string {
	// In production, this should be loaded from a secure source
	// For now, return a placeholder that must be replaced
	return "CHANGE_ME_IN_PRODUCTION_" + fmt.Sprintf("%d", time.Now().Unix())
}