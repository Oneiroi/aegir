package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/viper"
)

// Config holds all configuration for the MCP Firewall
type Config struct {
	Environment     string          `json:"environment" mapstructure:"environment"`
	Server          Server          `json:"server" mapstructure:"server"`
	Auth            Auth            `json:"auth" mapstructure:"auth"`
	Logging         Logging         `json:"logging" mapstructure:"logging"`
	Telemetry       Telemetry       `json:"telemetry" mapstructure:"telemetry"`
	Security        Security        `json:"security" mapstructure:"security"`
	Compliance      Compliance      `json:"compliance" mapstructure:"compliance"`
	SessionAnalysis SessionAnalysis `json:"session_analysis" mapstructure:"session_analysis"`
	Upstream        Upstream        `json:"upstream" mapstructure:"upstream"`
}

// Telemetry configuration for OpenTelemetry tracing
type Telemetry struct {
	Enabled     bool    `json:"enabled" mapstructure:"enabled"`
	OutputDir   string  `json:"output_dir" mapstructure:"output_dir"`
	ServiceName string  `json:"service_name" mapstructure:"service_name"`
	SampleRate  float64 `json:"sample_rate" mapstructure:"sample_rate"`
}

// Server configuration
type Server struct {
	Port         int    `json:"port" mapstructure:"port"`
	Host         string `json:"host" mapstructure:"host"`
	ReadTimeout  int    `json:"read_timeout" mapstructure:"read_timeout"`
	WriteTimeout int    `json:"write_timeout" mapstructure:"write_timeout"`
	TLS          TLS    `json:"tls" mapstructure:"tls"`
}

// TLS configuration
type TLS struct {
	Enabled  bool   `json:"enabled" mapstructure:"enabled"`
	CertFile string `json:"cert_file" mapstructure:"cert_file"`
	KeyFile  string `json:"key_file" mapstructure:"key_file"`
	MinTLS   string `json:"min_tls" mapstructure:"min_tls"`
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
	Level           string `json:"level" mapstructure:"level"`
	Format          string `json:"format" mapstructure:"format"`
	File            string `json:"file" mapstructure:"file"`
	MaxSize         int    `json:"max_size" mapstructure:"max_size"`
	MaxBackups      int    `json:"max_backups" mapstructure:"max_backups"`
	MaxAge          int    `json:"max_age" mapstructure:"max_age"`
	Compress        bool   `json:"compress" mapstructure:"compress"`
	HMACKey         string `json:"hmac_key" mapstructure:"hmac_key"`
	IntegrityChecks bool   `json:"integrity_checks" mapstructure:"integrity_checks"`
}

// AnomalyDetection configuration for heuristic content anomaly scoring
type AnomalyDetection struct {
	Enabled         bool    `json:"enabled" mapstructure:"enabled"`
	BlockThreshold  float64 `json:"block_threshold" mapstructure:"block_threshold"`  // Block if score > this (0.0-1.0)
	LogThreshold    float64 `json:"log_threshold" mapstructure:"log_threshold"`      // Log only if score > this, < block_threshold
}

// Security configuration
type Security struct {
	RateLimit         RateLimit         `json:"rate_limit"         mapstructure:"rate_limit"`
	Sanitization      Sanitization      `json:"sanitization"       mapstructure:"sanitization"`
	Encryption        Encryption        `json:"encryption"         mapstructure:"encryption"`
	SecretDetection   SecretDetection   `json:"secret_detection"   mapstructure:"secret_detection"`
	CommandInjection  CommandInjection  `json:"command_injection"  mapstructure:"command_injection"`
	AnomalyDetection  AnomalyDetection  `json:"anomaly_detection"  mapstructure:"anomaly_detection"`
}

// RateLimit configuration
type RateLimit struct {
	Enabled         bool `json:"enabled"          mapstructure:"enabled"`
	RequestsPerMin  int  `json:"requests_per_min" mapstructure:"requests_per_min"`
	BurstSize       int  `json:"burst_size"       mapstructure:"burst_size"`
	CleanupInterval int  `json:"cleanup_interval" mapstructure:"cleanup_interval"`
	MaxTrackedIPs   int  `json:"max_tracked_ips"  mapstructure:"max_tracked_ips"`
}

// Sanitization configuration
type Sanitization struct {
	Enabled           bool `json:"enabled"            mapstructure:"enabled"`
	XSSPrevention     bool `json:"xss_prevention"     mapstructure:"xss_prevention"`
	SQLInjection      bool `json:"sql_injection"      mapstructure:"sql_injection"`
	HomoglyphFilter   bool `json:"homoglyph_filter"   mapstructure:"homoglyph_filter"`
	FormulaDetection  bool `json:"formula_detection"  mapstructure:"formula_detection"`
	PromptInjection   bool `json:"prompt_injection"   mapstructure:"prompt_injection"`
}

// Encryption configuration
type Encryption struct {
	Algorithm    string `json:"algorithm"   mapstructure:"algorithm"`
	KeySize      int    `json:"key_size"    mapstructure:"key_size"`
	KeyRotation  int    `json:"key_rotation_days" mapstructure:"key_rotation_days"`
	HardwareHSM  bool   `json:"hardware_hsm" mapstructure:"hardware_hsm"`
	CloudKMS     string `json:"cloud_kms"   mapstructure:"cloud_kms"`
}

// SecretDetection configuration
type SecretDetection struct {
	Enabled        bool     `json:"enabled"         mapstructure:"enabled"`
	APIKeys        bool     `json:"api_keys"        mapstructure:"api_keys"`
	SSHKeys        bool     `json:"ssh_keys"        mapstructure:"ssh_keys"`
	Certificates   bool     `json:"certificates"    mapstructure:"certificates"`
	Passwords      bool     `json:"passwords"       mapstructure:"passwords"`
	CustomPatterns []string `json:"custom_patterns" mapstructure:"custom_patterns"`
}

// CommandInjection configuration
type CommandInjection struct {
	Enabled    bool     `json:"enabled"     mapstructure:"enabled"`
	BlockList  []string `json:"block_list"  mapstructure:"block_list"`
	AllowList  []string `json:"allow_list"  mapstructure:"allow_list"`
	StrictMode bool     `json:"strict_mode" mapstructure:"strict_mode"`
}

// Compliance configuration
type Compliance struct {
	HIPAA HIPAAConfig `json:"hipaa" mapstructure:"hipaa"`
	PCI   PCIConfig   `json:"pci"   mapstructure:"pci"`
	GDPR  GDPRConfig  `json:"gdpr"  mapstructure:"gdpr"`
	SOC2  SOC2Config  `json:"soc2"  mapstructure:"soc2"`
}

// HIPAAConfig for HIPAA compliance
type HIPAAConfig struct {
	Enabled      bool `json:"enabled"       mapstructure:"enabled"`
	PHIDetection bool `json:"phi_detection" mapstructure:"phi_detection"`
	Encryption   bool `json:"encryption"    mapstructure:"encryption"`
	AuditTrail   bool `json:"audit_trail"   mapstructure:"audit_trail"`
}

// PCIConfig for PCI DSS compliance
type PCIConfig struct {
	Enabled        bool `json:"enabled"         mapstructure:"enabled"`
	CardDetection  bool `json:"card_detection"  mapstructure:"card_detection"`
	TokenizeCards  bool `json:"tokenize_cards"  mapstructure:"tokenize_cards"`
	EncryptStorage bool `json:"encrypt_storage" mapstructure:"encrypt_storage"`
}

// GDPRConfig for GDPR compliance
type GDPRConfig struct {
	Enabled         bool   `json:"enabled"          mapstructure:"enabled"`
	PIIDetection    bool   `json:"pii_detection"    mapstructure:"pii_detection"`
	RightToErasure  bool   `json:"right_to_erasure" mapstructure:"right_to_erasure"`
	DataPortability bool   `json:"data_portability" mapstructure:"data_portability"`
	ConsentTracking bool   `json:"consent_tracking" mapstructure:"consent_tracking"`
	Region          string `json:"region"           mapstructure:"region"`
}

// SOC2Config for SOC 2 compliance
type SOC2Config struct {
	Enabled bool `json:"enabled" mapstructure:"enabled"`
	Type2   bool `json:"type2"   mapstructure:"type2"`
}

// SessionAnalysis configuration for conversational threat detection
type SessionAnalysis struct {
	Enabled              bool          `json:"enabled" mapstructure:"enabled"`
	MaxSessionAge        time.Duration `json:"max_session_age" mapstructure:"max_session_age"`
	MaxHistorySize       int           `json:"max_history_size" mapstructure:"max_history_size"`
	ThreatThreshold      float64       `json:"threat_threshold" mapstructure:"threat_threshold"`
	CleanupInterval      time.Duration `json:"cleanup_interval" mapstructure:"cleanup_interval"`
	JailbreakThreshold   float64       `json:"jailbreak_threshold" mapstructure:"jailbreak_threshold"`
	RoleEscalationLimit  int           `json:"role_escalation_limit" mapstructure:"role_escalation_limit"`
	EmotionalManipThreshold float64    `json:"emotional_manip_threshold" mapstructure:"emotional_manip_threshold"`
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

// Load loads configuration from multiple sources with precedence:
// 1. Command line flags (highest priority)
// 2. Environment variables
// 3. Configuration files
// 4. Default values (lowest priority)
func Load() (*Config, error) {
	return LoadWithConfigFile("")
}

// LoadWithConfigFile loads configuration with a specific config file
func LoadWithConfigFile(configFile string) (*Config, error) {
	// Initialize viper
	v := viper.New()

	// Set up configuration file search
	if configFile != "" {
		// Use specific config file
		v.SetConfigFile(configFile)
	} else {
		// Search for config files in standard locations
		v.SetConfigName("aegir")
		v.SetConfigType("yaml") // Default type

		// Add configuration search paths
		v.AddConfigPath(".")
		v.AddConfigPath("./config")
		v.AddConfigPath("/etc/aegir")
		v.AddConfigPath("$HOME/.aegir")

		// Support multiple file formats
		v.SetConfigType("yaml")
		if _, err := os.Stat("aegir.json"); err == nil {
			v.SetConfigType("json")
		}
		if _, err := os.Stat("aegir.toml"); err == nil {
			v.SetConfigType("toml")
		}
	}

	// Enable environment variable support
	v.AutomaticEnv()
	v.SetEnvPrefix("MCP") // MCP_SERVER_PORT, etc.
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))

	// Set default values first
	setDefaults(v)

	// Try to read config file (this will merge with defaults)
	if err := v.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			// Config file was found but another error was produced
			return nil, fmt.Errorf("error reading config file: %w", err)
		}
		// Config file not found; ignore error and use defaults + env vars
	}

	// Unmarshal into config struct
	var cfg Config
	if err := v.Unmarshal(&cfg); err != nil {
		return nil, fmt.Errorf("error unmarshaling config: %w", err)
	}

	// Validate configuration
	if err := validateConfig(&cfg); err != nil {
		return nil, fmt.Errorf("configuration validation failed: %w", err)
	}

	return &cfg, nil
}

// LoadWithConfigDir loads configuration with a specific config directory
func LoadWithConfigDir(configDir string) (*Config, error) {
	// Initialize viper
	v := viper.New()

	// Set up configuration directory search
	v.SetConfigName("aegir")
	v.SetConfigType("yaml") // Default type
	v.AddConfigPath(configDir)

	// Support multiple file formats in the directory
	v.SetConfigType("yaml")
	if _, err := os.Stat(configDir + "/aegir.json"); err == nil {
		v.SetConfigType("json")
	}
	if _, err := os.Stat(configDir + "/aegir.toml"); err == nil {
		v.SetConfigType("toml")
	}

	// Enable environment variable support
	v.AutomaticEnv()
	v.SetEnvPrefix("MCP") // MCP_SERVER_PORT, etc.
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))

	// Set default values first
	setDefaults(v)

	// Try to read config file (this will merge with defaults)
	if err := v.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			// Config file was found but another error was produced
			return nil, fmt.Errorf("error reading config file: %w", err)
		}
		// Config file not found; ignore error and use defaults + env vars
	}

	// Unmarshal into config struct
	var cfg Config
	if err := v.Unmarshal(&cfg); err != nil {
		return nil, fmt.Errorf("error unmarshaling config: %w", err)
	}

	// Validate configuration
	if err := validateConfig(&cfg); err != nil {
		return nil, fmt.Errorf("configuration validation failed: %w", err)
	}

	return &cfg, nil
}

// setDefaults sets default configuration values
func setDefaults(v *viper.Viper) {
	// Environment
	v.SetDefault("environment", "development")

	// Server defaults
	v.SetDefault("server.port", 8443)
	v.SetDefault("server.host", "localhost")
	v.SetDefault("server.read_timeout", 10)
	v.SetDefault("server.write_timeout", 10)

	// TLS defaults
	v.SetDefault("server.tls.enabled", true)
	v.SetDefault("server.tls.cert_file", "certs/cert.pem")
	v.SetDefault("server.tls.key_file", "certs/key.pem")
	v.SetDefault("server.tls.min_tls", "1.3")

	// Auth defaults
	v.SetDefault("auth.jwt.secret", generateRandomSecret())
	v.SetDefault("auth.jwt.issuer", "aegir")
	v.SetDefault("auth.jwt.expiration_time", 3600)
	v.SetDefault("auth.jwt.refresh_expiration", 86400)
	v.SetDefault("auth.oauth.enabled", false)
	v.SetDefault("auth.api_keys.enabled", true)
	v.SetDefault("auth.mfa.required", false)
	v.SetDefault("auth.mfa.providers", []string{"totp", "sms"})

	// Logging defaults
	v.SetDefault("logging.level", "info")
	v.SetDefault("logging.format", "json")
	v.SetDefault("logging.file", "logs/aegir.log")
	v.SetDefault("logging.max_size", 100)
	v.SetDefault("logging.max_backups", 10)
	v.SetDefault("logging.max_age", 30)
	v.SetDefault("logging.compress", true)
	v.SetDefault("logging.hmac_key", generateRandomSecret())
	v.SetDefault("logging.integrity_checks", true)

	// Telemetry defaults
	v.SetDefault("telemetry.enabled", false)
	v.SetDefault("telemetry.output_dir", "logs/traces")
	v.SetDefault("telemetry.service_name", "aegir-mcp-firewall")
	v.SetDefault("telemetry.sample_rate", 1.0)

	// Security defaults
	v.SetDefault("security.rate_limit.enabled", true)
	v.SetDefault("security.rate_limit.requests_per_min", 100)
	v.SetDefault("security.rate_limit.burst_size", 20)
	v.SetDefault("security.rate_limit.cleanup_interval", 300)

	v.SetDefault("security.sanitization.enabled", true)
	v.SetDefault("security.sanitization.xss_prevention", true)
	v.SetDefault("security.sanitization.sql_injection", true)
	v.SetDefault("security.sanitization.homoglyph_filter", true)
	v.SetDefault("security.sanitization.formula_detection", true)
	v.SetDefault("security.sanitization.prompt_injection", true)

	v.SetDefault("security.encryption.algorithm", "AES-256-GCM")
	v.SetDefault("security.encryption.key_size", 256)
	v.SetDefault("security.encryption.key_rotation", 90)
	v.SetDefault("security.encryption.hardware_hsm", false)

	v.SetDefault("security.secret_detection.enabled", true)
	v.SetDefault("security.secret_detection.api_keys", true)
	v.SetDefault("security.secret_detection.ssh_keys", true)
	v.SetDefault("security.secret_detection.certificates", true)
	v.SetDefault("security.secret_detection.passwords", true)

	v.SetDefault("security.command_injection.enabled", true)
	v.SetDefault("security.command_injection.strict_mode", true)

	// Compliance defaults
	v.SetDefault("compliance.hipaa.enabled", false)
	v.SetDefault("compliance.pci.enabled", false)
	v.SetDefault("compliance.gdpr.enabled", false)
	v.SetDefault("compliance.soc2.enabled", false)

	// Session Analysis defaults
	v.SetDefault("session_analysis.enabled", true)
	v.SetDefault("session_analysis.max_session_age", "30m")
	v.SetDefault("session_analysis.max_history_size", 50)
	v.SetDefault("session_analysis.threat_threshold", 0.5)
	v.SetDefault("session_analysis.cleanup_interval", "5m")
	v.SetDefault("session_analysis.jailbreak_threshold", 0.6)
	v.SetDefault("session_analysis.role_escalation_limit", 3)
	v.SetDefault("session_analysis.emotional_manip_threshold", 0.4)

	// Upstream defaults
	v.SetDefault("security.anomaly_detection.enabled", false)
	v.SetDefault("security.anomaly_detection.block_threshold", 0.95)
	v.SetDefault("security.anomaly_detection.log_threshold", 0.60)

	v.SetDefault("upstream.services", []map[string]interface{}{
		{
			"name":      "default-mcp-service",
			"url":       "http://localhost:8080",
			"transport": "http",
			"weight":    100,
			"priority":  1,
			"enabled":   true,
			"timeout":   30,
			"tls": map[string]interface{}{
				"enabled":     false,
				"skip_verify": false,
			},
		},
	})

	v.SetDefault("upstream.discovery.enabled", false)
	v.SetDefault("upstream.discovery.provider", "static")
	v.SetDefault("upstream.discovery.interval", 30)

	v.SetDefault("upstream.load_balancing.strategy", "round_robin")

	v.SetDefault("upstream.health_check.enabled", true)
	v.SetDefault("upstream.health_check.interval", 30)
	v.SetDefault("upstream.health_check.timeout", 5)
	v.SetDefault("upstream.health_check.healthy_threshold", 2)
	v.SetDefault("upstream.health_check.unhealthy_threshold", 3)
	v.SetDefault("upstream.health_check.path", "/health")
	v.SetDefault("upstream.health_check.expected_codes", []int{200, 204})

	v.SetDefault("upstream.circuit_breaker.enabled", true)
	v.SetDefault("upstream.circuit_breaker.failure_threshold", 5)
	v.SetDefault("upstream.circuit_breaker.recovery_timeout", 60)
	v.SetDefault("upstream.circuit_breaker.half_open_requests", 3)

	v.SetDefault("upstream.retry.enabled", true)
	v.SetDefault("upstream.retry.max_retries", 3)
	v.SetDefault("upstream.retry.backoff_ms", 100)
	v.SetDefault("upstream.retry.max_backoff_ms", 1000)
}

// validateConfig validates the loaded configuration
func validateConfig(cfg *Config) error {
	// Validate server configuration
	if cfg.Server.Port <= 0 || cfg.Server.Port > 65535 {
		return fmt.Errorf("invalid server port: %d", cfg.Server.Port)
	}

	// Validate TLS configuration
	if cfg.Server.TLS.Enabled {
		if cfg.Server.TLS.CertFile == "" {
			return fmt.Errorf("TLS enabled but cert_file not specified")
		}
		if cfg.Server.TLS.KeyFile == "" {
			return fmt.Errorf("TLS enabled but key_file not specified")
		}
	}

	// Validate upstream services
	if len(cfg.Upstream.Services) == 0 {
		return fmt.Errorf("no upstream services configured")
	}

	for i, service := range cfg.Upstream.Services {
		if service.Name == "" {
			return fmt.Errorf("upstream service %d: name is required", i)
		}
		if service.URL == "" {
			return fmt.Errorf("upstream service %s: URL is required", service.Name)
		}
		if service.Timeout <= 0 {
			return fmt.Errorf("upstream service %s: timeout must be positive", service.Name)
		}
	}

	return nil
}

// LoadLegacy loads configuration from environment variables and defaults (legacy method)
func LoadLegacy() (*Config, error) {
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
				Issuer:            getEnv("JWT_ISSUER", "aegir"),
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
			File:            getEnv("LOG_FILE", "logs/aegir.log"),
			MaxSize:         getEnvAsInt("LOG_MAX_SIZE", 100),
			MaxBackups:      getEnvAsInt("LOG_MAX_BACKUPS", 10),
			MaxAge:          getEnvAsInt("LOG_MAX_AGE", 30),
			Compress:        getEnvAsBool("LOG_COMPRESS", true),
			HMACKey:         getEnv("LOG_HMAC_KEY", generateRandomSecret()),
			IntegrityChecks: getEnvAsBool("LOG_INTEGRITY_CHECKS", true),
		},
		Telemetry: Telemetry{
			Enabled:     getEnvAsBool("OTEL_ENABLED", false),
			OutputDir:   getEnv("OTEL_OUTPUT_DIR", "logs/traces"),
			ServiceName: getEnv("OTEL_SERVICE_NAME", "aegir-mcp-firewall"),
			SampleRate:  getEnvAsFloat("OTEL_SAMPLE_RATE", 1.0),
		},
		Security: Security{
			RateLimit: RateLimit{
				Enabled:         getEnvAsBool("RATE_LIMIT_ENABLED", true),
				RequestsPerMin:  getEnvAsInt("RATE_LIMIT_RPM", 100),
				BurstSize:       getEnvAsInt("RATE_LIMIT_BURST", 20),
				CleanupInterval: getEnvAsInt("RATE_LIMIT_CLEANUP", 300),
				MaxTrackedIPs:   getEnvAsInt("RATE_LIMIT_MAX_TRACKED_IPS", 100000),
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
		SessionAnalysis: SessionAnalysis{
			Enabled:                 getEnvAsBool("SESSION_ANALYSIS_ENABLED", true),
			MaxSessionAge:           time.Duration(getEnvAsInt("SESSION_MAX_AGE_MINUTES", 30)) * time.Minute,
			MaxHistorySize:          getEnvAsInt("SESSION_MAX_HISTORY_SIZE", 50),
			ThreatThreshold:         getEnvAsFloat("SESSION_THREAT_THRESHOLD", 0.5),
			CleanupInterval:         time.Duration(getEnvAsInt("SESSION_CLEANUP_MINUTES", 5)) * time.Minute,
			JailbreakThreshold:      getEnvAsFloat("SESSION_JAILBREAK_THRESHOLD", 0.6),
			RoleEscalationLimit:     getEnvAsInt("SESSION_ROLE_ESCALATION_LIMIT", 3),
			EmotionalManipThreshold: getEnvAsFloat("SESSION_EMOTIONAL_MANIP_THRESHOLD", 0.4),
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

func getEnvAsFloat(key string, fallback float64) float64 {
	if value := os.Getenv(key); value != "" {
		if floatVal, err := strconv.ParseFloat(value, 64); err == nil {
			return floatVal
		}
	}
	return fallback
}

func generateRandomSecret() string {
	// In production, this should be loaded from a secure source
	// For now, return a placeholder that must be replaced
	return "CHANGE_ME_IN_PRODUCTION_" + fmt.Sprintf("%d", time.Now().Unix())
}