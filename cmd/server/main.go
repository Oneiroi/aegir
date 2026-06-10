package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/aegishjalmur/aegir/internal/config"
	"github.com/aegishjalmur/aegir/internal/server"
	"github.com/aegishjalmur/aegir/internal/telemetry"
	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"
)

func main() {
	// Parse command-line flags
	var transport = flag.String("transport", "http", "Transport mode: http, stdio, or sse")
	var configFile = flag.String("config", "", "Configuration file path (YAML, JSON, or TOML)")
	var configDir = flag.String("config-dir", "", "Configuration directory to search for config files")
	var envFile = flag.String("env", ".env", "Environment file path")
	var showVersion = flag.Bool("version", false, "Show version information")
	var showConfig = flag.Bool("show-config", false, "Show current configuration and exit")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "MCP Security Firewall - Enterprise-grade security proxy for Model Context Protocol\n\n")
		fmt.Fprintf(os.Stderr, "Usage: %s [options]\n\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "Options:\n")
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\nConfiguration:\n")
		fmt.Fprintf(os.Stderr, "  The server loads configuration from multiple sources in this order:\n")
		fmt.Fprintf(os.Stderr, "  1. Command line flags (highest priority)\n")
		fmt.Fprintf(os.Stderr, "  2. Environment variables\n")
		fmt.Fprintf(os.Stderr, "  3. Configuration files (YAML, JSON, TOML)\n")
		fmt.Fprintf(os.Stderr, "  4. Default values (lowest priority)\n\n")
		fmt.Fprintf(os.Stderr, "  Default config file search paths:\n")
		fmt.Fprintf(os.Stderr, "  - ./aegir.yaml\n")
		fmt.Fprintf(os.Stderr, "  - ./config/aegir.yaml\n")
		fmt.Fprintf(os.Stderr, "  - /etc/aegir/aegir.yaml\n")
		fmt.Fprintf(os.Stderr, "  - $HOME/.aegir/aegir.yaml\n\n")
		fmt.Fprintf(os.Stderr, "Examples:\n")
		fmt.Fprintf(os.Stderr, "  %s --transport http\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  %s --config /path/to/config.yaml\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  %s --config-dir /etc/aegir\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  %s --show-config\n", os.Args[0])
	}

	flag.Parse()

	// Show version if requested
	if *showVersion {
		fmt.Printf("MCP Security Firewall v1.0.0\n")
		fmt.Printf("Enterprise-grade security proxy for Model Context Protocol\n")
		fmt.Printf("Build: %s\n", getBuildInfo())
		os.Exit(0)
	}

	// Load environment variables
	if err := godotenv.Load(*envFile); err != nil {
		log.Printf("Warning: Environment file %s not found", *envFile)
	}

	// Load configuration with file support
	var cfg *config.Config
	var err error

	if *configFile != "" {
		cfg, err = config.LoadWithConfigFile(*configFile)
		if err != nil {
			log.Fatalf("Failed to load configuration from %s: %v", *configFile, err)
		}
		log.Printf("Loaded configuration from: %s", *configFile)
	} else if *configDir != "" {
		cfg, err = config.LoadWithConfigDir(*configDir)
		if err != nil {
			log.Fatalf("Failed to load configuration from directory %s: %v", *configDir, err)
		}
		log.Printf("Loaded configuration from directory: %s", *configDir)
	} else {
		cfg, err = config.Load()
		if err != nil {
			log.Fatalf("Failed to load configuration: %v", err)
		}
	}

	// Show configuration if requested
	if *showConfig {
		showCurrentConfig(cfg)
		os.Exit(0)
	}

	// Handle different transport modes
	switch *transport {
	case "stdio":
		runSTDIOMode(cfg)
	case "http", "sse":
		runHTTPMode(cfg, *transport)
	default:
		log.Fatalf("Invalid transport mode: %s. Valid options: http, stdio, sse", *transport)
	}
}

// initTelemetry initialises the OTEL provider and returns a shutdown function.
func initTelemetry(cfg *config.Config) func() {
	tp, err := telemetry.New(telemetry.Config{
		Enabled:     cfg.Telemetry.Enabled,
		OutputDir:   cfg.Telemetry.OutputDir,
		ServiceName: cfg.Telemetry.ServiceName,
		SampleRate:  cfg.Telemetry.SampleRate,
	})
	if err != nil {
		log.Printf("Warning: failed to initialise OTEL: %v — tracing disabled", err)
		return func() {}
	}
	if cfg.Telemetry.Enabled {
		log.Printf("OTEL tracing enabled, writing spans to %s", cfg.Telemetry.OutputDir)
	}
	return func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := tp.Shutdown(ctx); err != nil {
			log.Printf("Warning: OTEL shutdown error: %v", err)
		}
	}
}

// runSTDIOMode runs the server in STDIO mode
func runSTDIOMode(cfg *config.Config) {
	log.Println("Starting MCP Firewall in STDIO mode")

	shutdownTelemetry := initTelemetry(cfg)
	defer shutdownTelemetry()

	// Initialize components for STDIO mode
	mcpServer, err := server.New(cfg)
	if err != nil {
		log.Fatalf("Failed to create server: %v", err)
	}

	// Create STDIO transport
	stdioTransport := server.NewMCPSTDIOTransport(
		mcpServer.GetLogger(),
		mcpServer.GetSanitizer(),
		mcpServer.GetComplianceManager(),
	)

	// Start STDIO transport
	ctx := context.Background()
	if err := stdioTransport.Start(ctx); err != nil {
		log.Fatalf("STDIO transport failed: %v", err)
	}

	log.Println("STDIO mode exited")
}

// runHTTPMode runs the server in HTTP/HTTPS mode (with optional SSE support)
func runHTTPMode(cfg *config.Config, transport string) {
	// Set Gin mode based on environment
	if cfg.Environment == "production" {
		gin.SetMode(gin.ReleaseMode)
	}

	shutdownTelemetry := initTelemetry(cfg)
	defer shutdownTelemetry()

	// Initialize the MCP firewall server
	mcpServer, err := server.New(cfg)
	if err != nil {
		log.Fatalf("Failed to create server: %v", err)
	}

	// Create HTTP server with TLS configuration
	srv := &http.Server{
		Addr:      fmt.Sprintf(":%d", cfg.Server.Port),
		Handler:   mcpServer.Handler(),
		TLSConfig: createTLSConfig(cfg),
		// Security timeouts
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       60 * time.Second,
		ReadHeaderTimeout: 5 * time.Second,
	}

	// Start server in a goroutine
	go func() {
		log.Printf("Starting MCP Firewall server in %s mode on port %d", transport, cfg.Server.Port)

		if cfg.Server.TLS.Enabled {
			if err := srv.ListenAndServeTLS(cfg.Server.TLS.CertFile, cfg.Server.TLS.KeyFile); err != nil && err != http.ErrServerClosed {
				log.Fatalf("Failed to start HTTPS server: %v", err)
			}
		} else {
			log.Println("WARNING: Running without TLS - not recommended for production")
			if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				log.Fatalf("Failed to start HTTP server: %v", err)
			}
		}
	}()

	// Signal loop: SIGHUP hot-reloads detection patterns (ISC-26/134);
	// SIGINT/SIGTERM trigger graceful shutdown.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)

	for {
		sig := <-sigCh
		switch sig {
		case syscall.SIGHUP:
			log.Println("SIGHUP received — hot-reloading detection patterns")
			mcpServer.GetSanitizer().Reload()
			log.Println("Detection patterns reloaded")
		case syscall.SIGINT, syscall.SIGTERM:
			log.Println("Shutting down server...")
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			if err := srv.Shutdown(ctx); err != nil {
				log.Fatalf("Server forced to shutdown: %v", err)
			}
			log.Println("Server exited")
			return
		}
	}
}

func createTLSConfig(cfg *config.Config) *tls.Config {
	return &tls.Config{
		MinVersion: tls.VersionTLS13, // Enforce TLS 1.3 minimum
		CipherSuites: []uint16{
			tls.TLS_AES_256_GCM_SHA384,
			tls.TLS_CHACHA20_POLY1305_SHA256,
			tls.TLS_AES_128_GCM_SHA256,
		},
		PreferServerCipherSuites: true,
		CurvePreferences: []tls.CurveID{
			tls.X25519,
			tls.CurveP384,
			tls.CurveP256,
		},
	}
}

func getBuildInfo() string {
	return "development"
}

func showCurrentConfig(cfg *config.Config) {
	fmt.Printf("=== MCP Firewall Configuration ===\n\n")
	fmt.Printf("Environment: %s\n", cfg.Environment)
	fmt.Printf("Server Port: %d\n", cfg.Server.Port)
	fmt.Printf("TLS Enabled: %v\n", cfg.Server.TLS.Enabled)

	if cfg.Server.TLS.Enabled {
		fmt.Printf("TLS Cert File: %s\n", cfg.Server.TLS.CertFile)
		fmt.Printf("TLS Key File: %s\n", cfg.Server.TLS.KeyFile)
	}

	fmt.Printf("\nSecurity Settings:\n")
	fmt.Printf("  Rate Limiting: %v\n", cfg.Security.RateLimit.Enabled)
	if cfg.Security.RateLimit.Enabled {
		fmt.Printf("    Requests per minute: %d\n", cfg.Security.RateLimit.RequestsPerMin)
	}

	fmt.Printf("  Sanitization: %v\n", cfg.Security.Sanitization.Enabled)
	fmt.Printf("  XSS Prevention: %v\n", cfg.Security.Sanitization.XSSPrevention)
	fmt.Printf("  SQL Injection Prevention: %v\n", cfg.Security.Sanitization.SQLInjection)

	fmt.Printf("\nCompliance:\n")
	fmt.Printf("  GDPR: %v\n", cfg.Compliance.GDPR.Enabled)
	fmt.Printf("  HIPAA: %v\n", cfg.Compliance.HIPAA.Enabled)
	fmt.Printf("  PCI: %v\n", cfg.Compliance.PCI.Enabled)

	fmt.Printf("\nLogging:\n")
	fmt.Printf("  Level: %s\n", cfg.Logging.Level)
	fmt.Printf("  Format: %s\n", cfg.Logging.Format)
	fmt.Printf("  Integrity Checks: %v\n", cfg.Logging.IntegrityChecks)

	fmt.Printf("\nSession Analysis:\n")
	fmt.Printf("  Multi-turn Attack Detection: %v\n", cfg.SessionAnalysis.Enabled)
	if cfg.SessionAnalysis.Enabled {
		fmt.Printf("    Max Session Age: %v\n", cfg.SessionAnalysis.MaxSessionAge)
		fmt.Printf("    Threat Threshold: %.2f\n", cfg.SessionAnalysis.ThreatThreshold)
	}
}