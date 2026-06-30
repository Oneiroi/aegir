package config

import (
	cryptorand "crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
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
	Judge           JudgeConfig     `json:"judge"    mapstructure:"judge"`
}

// JudgeConfig configures the optional LLM judge backend (M009).
// When Enabled is false, SUSPICIOUS verdicts are forwarded without LLM analysis.
type JudgeConfig struct {
	Enabled   bool   `json:"enabled"    mapstructure:"enabled"`
	BaseURL   string `json:"base_url"   mapstructure:"base_url"`
	Model     string `json:"model"      mapstructure:"model"`
	APIKey    string `json:"api_key"    mapstructure:"api_key"`
	TimeoutMs int    `json:"timeout_ms" mapstructure:"timeout_ms"`

	// Provider selects the judge wire-protocol adapter (M013, ISC-138):
	// "ollama" (default), "openai" (OpenAI-compatible: OMLX/LM Studio/LiteLLM),
	// or "anthropic" (Messages API). Empty defaults to ollama.
	Provider string `json:"provider" mapstructure:"provider"`

	// Fallbacks is an ordered list of backends tried on TRANSPORT error of the
	// primary (ISC-141). Never consulted on a judge verdict or refusal.
	Fallbacks []JudgeFallback `json:"fallbacks" mapstructure:"fallbacks"`

	// ExposeReasoning, when true, emits the judge's verdict reason to the
	// client (the X-Aegir-Judge-Reason header and the BLOCK error Data field)
	// for debugging and audit. DEFAULT FALSE — the client-isolation principle
	// requires that judge reasoning never reach the client. The reason text can
	// quote the inspected payload verbatim, so emitting it is a KNOWN GDPR (and
	// HIPAA/PCI) violation when that payload contains regulated data. Enabling
	// this logs a loud startup WARNING. Use only in trusted debug environments.
	ExposeReasoning bool `json:"expose_reasoning" mapstructure:"expose_reasoning"`
}

// JudgeFallback is one ordered failover backend for the judge (M013, ISC-141).
// Mirrors judge.FallbackConfig; kept in the config package to avoid a
// config→judge import dependency (server.go translates between them).
type JudgeFallback struct {
	BaseURL  string `json:"base_url" mapstructure:"base_url"`
	Model    string `json:"model"    mapstructure:"model"`
	APIKey   string `json:"api_key"  mapstructure:"api_key"`
	Provider string `json:"provider" mapstructure:"provider"`
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
	JWT      JWT      `json:"jwt"`
	OAuth    OAuth    `json:"oauth"`
	APIKeys  APIKeys  `json:"api_keys"`
	MFA      MFA      `json:"mfa"`
	WebAuthn WebAuthn `json:"webauthn" mapstructure:"webauthn"`
}

// WebAuthn configuration for FIDO2/WebAuthn MFA.
// Leave RPID empty to disable WebAuthn entirely.
type WebAuthn struct {
	// RPID is the Relying Party identifier, e.g. "example.com".
	RPID string `json:"rpid" mapstructure:"rpid"`
	// RPOrigin is the fully-qualified origin of the Relying Party, e.g. "https://example.com".
	RPOrigin string `json:"rp_origin" mapstructure:"rp_origin"`
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
	Enabled        bool    `json:"enabled"          mapstructure:"enabled"`
	BlockThreshold float64 `json:"block_threshold"  mapstructure:"block_threshold"` // Block if score > this (0.0-1.0)
	LogThreshold   float64 `json:"log_threshold"    mapstructure:"log_threshold"`   // Log only if score > this, < block_threshold
	// Profiles allows per-context threshold overrides (ISC-20). The active
	// profile is selected via the X-Aegir-Profile request header or the
	// upstream.profile config key. Example profiles: "finance", "assistant".
	// Each profile may override block_threshold and log_threshold.
	Profiles       map[string]AnomalyProfile `json:"profiles" mapstructure:"profiles"`
}

// AnomalyProfile holds per-context threshold overrides for anomaly detection (ISC-20/21).
type AnomalyProfile struct {
	BlockThreshold  *float64 `json:"block_threshold"  mapstructure:"block_threshold"`
	LogThreshold    *float64 `json:"log_threshold"    mapstructure:"log_threshold"`
	// EntropyThreshold allows per-upstream entropy tuning (ISC-21).
	EntropyThreshold *float64 `json:"entropy_threshold" mapstructure:"entropy_threshold"`
}

// Detection is the master switch for ALL pattern-based detection performed by
// the sanitizer (ISC-132). When Enabled is false, SanitizeContent
// short-circuits and returns a clean result with no scanning. Defaults to true
// — a security gateway must scan by default. Configured via
// security.detection.enabled in aegir.yaml.
type Detection struct {
	Enabled        bool   `json:"enabled"          mapstructure:"enabled"`
	ResponsePolicy string `json:"response_policy"  mapstructure:"response_policy"` // block, allow, flag
}

// Security configuration
type Security struct {
	RateLimit         RateLimit         `json:"rate_limit"         mapstructure:"rate_limit"`
	Sanitization      Sanitization      `json:"sanitization"       mapstructure:"sanitization"`
	Encryption        Encryption        `json:"encryption"         mapstructure:"encryption"`
	SecretDetection   SecretDetection   `json:"secret_detection"   mapstructure:"secret_detection"`
	CommandInjection  CommandInjection  `json:"command_injection"  mapstructure:"command_injection"`
	AnomalyDetection  AnomalyDetection  `json:"anomaly_detection"  mapstructure:"anomaly_detection"`
	Detection         Detection         `json:"detection"          mapstructure:"detection"`
	HumanApproval    HumanApprovalConfig `json:"human_approval"   mapstructure:"human_approval"`
	// AllowedOrigins is the list of browser origins permitted to call HTTP MCP
	// endpoints. Requests bearing an Origin header not in this list are blocked
	// with 403. Requests without an Origin header (non-browser clients) pass
	// unconditionally. Empty list means all origins are allowed. (ISC-120)
	AllowedOrigins   []string            `json:"allowed_origins"  mapstructure:"allowed_origins"`
	// ReconRateLimit tracks per-session tools/list call frequency and fires a
	// tools_list_recon_suspected log event when the threshold is exceeded. (ISC-121)
	ReconRateLimit   ReconRateLimitConfig `json:"recon_rate_limit" mapstructure:"recon_rate_limit"`
	// OAuthScopeAudit parses JWT bearer tokens on incoming requests and fires
	// excessive_scope_detected when any prohibited scope is present. (ISC-122)
	OAuthScopeAudit  OAuthScopeAuditConfig `json:"oauth_scope_audit" mapstructure:"oauth_scope_audit"`
}

// OAuthScopeAuditConfig configures JWT scope auditing (ISC-122).
type OAuthScopeAuditConfig struct {
	Enabled          bool     `json:"enabled"           mapstructure:"enabled"`
	ProhibitedScopes []string `json:"prohibited_scopes" mapstructure:"prohibited_scopes"`
}

// ReconRateLimitConfig configures per-session tools/list frequency detection (ISC-121).
type ReconRateLimitConfig struct {
	Enabled             bool `json:"enabled"               mapstructure:"enabled"`
	ToolsListMaxPerMin  int  `json:"tools_list_max_per_min" mapstructure:"tools_list_max_per_min"`
}

// HumanApprovalConfig gates destructive tool calls behind an external webhook
// (ISC-119). Tools whose names match any prefix in Patterns are held; the
// webhook is called with the tool name, arguments, and session context and must
// respond with {"approved":true} within Timeout or the call is blocked.
type HumanApprovalConfig struct {
	Enabled    bool          `json:"enabled"     mapstructure:"enabled"`
	Patterns   []string      `json:"patterns"    mapstructure:"patterns"`
	WebhookURL string        `json:"webhook_url" mapstructure:"webhook_url"`
	Timeout    time.Duration `json:"timeout"     mapstructure:"timeout"`
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
	HIPAA          HIPAAConfig       `json:"hipaa"            mapstructure:"hipaa"`
	PCI            PCIConfig         `json:"pci"              mapstructure:"pci"`
	GDPR           GDPRConfig        `json:"gdpr"             mapstructure:"gdpr"`
	SOC2           SOC2Config        `json:"soc2"             mapstructure:"soc2"`
	// ResponsePolicy maps violation type (e.g. "pii", "phi", "pci") to the action
	// taken when that data type is found in a response: "block", "redact", or
	// "log-only". Absent types fall back to "redact". Configured via
	// compliance.response_policy in aegir.yaml (ISC-28).
	ResponsePolicy map[string]string `json:"response_policy"  mapstructure:"response_policy"`
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
// bindJudgeEnv explicitly registers MCP_JUDGE_* → judge.* mappings on the
// supplied Viper instance. This works around a long-standing Viper limitation
// (github.com/spf13/viper#584) where Unmarshal ignores keys discovered solely
// via AutomaticEnv — i.e. keys whose value is only in the environment and
// absent from the config file and defaults cannot be unmarshalled.
// BindEnv makes the mapping explicit and queryable by Unmarshal.
func bindJudgeEnv(v *viper.Viper) {
	pairs := [][2]string{
		{"judge.enabled", "MCP_JUDGE_ENABLED"},
		{"judge.provider", "MCP_JUDGE_PROVIDER"},
		{"judge.base_url", "MCP_JUDGE_BASE_URL"},
		{"judge.model", "MCP_JUDGE_MODEL"},
		{"judge.api_key", "MCP_JUDGE_API_KEY"},
		{"judge.timeout_ms", "MCP_JUDGE_TIMEOUT_MS"},
	}
	for _, p := range pairs {
		_ = v.BindEnv(p[0], p[1])
	}
}

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

	// Explicit BindEnv for runtime-critical keys: Viper's Unmarshal does not
	// consult AutomaticEnv for keys whose values come solely from env vars
	// (github.com/spf13/viper#584). BindEnv registers the mapping explicitly
	// so Unmarshal can see it regardless of whether the key exists in the file.
	bindJudgeEnv(v)

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

	// Explicit BindEnv for runtime-critical keys: Viper's Unmarshal does not
	// consult AutomaticEnv for keys whose values come solely from env vars
	// (github.com/spf13/viper#584). BindEnv registers the mapping explicitly
	// so Unmarshal can see it regardless of whether the key exists in the file.
	bindJudgeEnv(v)

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

	// Master detection switch (ISC-132). A security gateway must scan by
	// default — without this default the sanitizer short-circuits and forwards
	// all traffic unscanned. See sanitizer.Manager.SanitizeContent.
	v.SetDefault("security.detection.enabled", true)
	v.SetDefault("security.detection.response_policy", "block")

	// Judge reasoning must never reach the client by default (client-isolation
	// principle; GDPR/HIPAA/PCI). Opt-in only, for trusted debug environments.
	v.SetDefault("judge.expose_reasoning", false)

	// Judge backend defaults (M013): local-first Ollama unless overridden.
	v.SetDefault("judge.provider", "ollama")

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

	// Detection master switch (ISC-132) — defaults on so existing deployments keep full coverage.
	v.SetDefault("security.detection_enabled", true)

	// Compliance defaults
	v.SetDefault("compliance.hipaa.enabled", false)
	v.SetDefault("compliance.pci.enabled", false)
	v.SetDefault("compliance.gdpr.enabled", false)
	v.SetDefault("compliance.soc2.enabled", false)
	// Per-data-type response policy defaults (ISC-28): redact all regulated types by default.
	v.SetDefault("compliance.response_policy", map[string]interface{}{
		"pii": "redact",
		"phi": "redact",
		"pci": "redact",
	})

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

	// CSRF/Origin validation defaults (ISC-120): empty list = allow all origins.
	v.SetDefault("security.allowed_origins", []string{})

	// Recon rate limit defaults (ISC-121).
	v.SetDefault("security.recon_rate_limit.enabled", true)
	v.SetDefault("security.recon_rate_limit.tools_list_max_per_min", 10)

	// OAuth scope audit defaults (ISC-122).
	v.SetDefault("security.oauth_scope_audit.enabled", true)
	v.SetDefault("security.oauth_scope_audit.prohibited_scopes", []string{"*", "admin", "write:all"})

	// Human approval gate defaults (ISC-119): disabled by default; common destructive prefixes.
	v.SetDefault("security.human_approval.enabled", false)
	v.SetDefault("security.human_approval.patterns", []string{"delete_", "drop_", "purge_", "format_", "overwrite_"})
	v.SetDefault("security.human_approval.webhook_url", "")
	v.SetDefault("security.human_approval.timeout", 30*time.Second)

	// Judge defaults — opt-in; disabled by default so pattern-only deployments work without Ollama
	v.SetDefault("judge.enabled", false)
	v.SetDefault("judge.base_url", "http://localhost:11434")
	v.SetDefault("judge.model", "llama3")
	v.SetDefault("judge.timeout_ms", 5000)

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
			Detection: Detection{
				Enabled:        getEnvAsBool("DETECTION_ENABLED", true),
				ResponsePolicy: getEnv("DETECTION_RESPONSE_POLICY", "block"),
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

// devSecret is generated once per process so that restarts within a single
// development run do not silently rotate the signing key and break audit chains.
// The "CHANGE_ME_IN_PRODUCTION_" prefix is intentional: the secret guard in
// secret_guard.go will refuse to start unless AEGIR_ALLOW_INSECURE_JWT_SECRET
// is set, making this safe to ship as a default. In production, set the
// JWT_SECRET (and LOG_HMAC_KEY) environment variables to stable, operator-managed
// values — never rely on this ephemeral fallback for audit continuity.
var (
	devSecretOnce  sync.Once
	devSecretValue string
)

func generateRandomSecret() string {
	devSecretOnce.Do(func() {
		b := make([]byte, 32)
		if _, err := cryptorand.Read(b); err != nil {
			devSecretValue = "CHANGE_ME_IN_PRODUCTION_fallback"
			return
		}
		devSecretValue = "CHANGE_ME_IN_PRODUCTION_" + hex.EncodeToString(b)
	})
	return devSecretValue
}