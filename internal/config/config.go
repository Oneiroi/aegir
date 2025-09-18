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
	Enabled          bool `json:"enabled"`
	XSSPrevention    bool `json:"xss_prevention"`
	SQLInjection     bool `json:"sql_injection"`
	HomoglyphFilter  bool `json:"homoglyph_filter"`
	FormulaDetection bool `json:"formula_detection"`
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