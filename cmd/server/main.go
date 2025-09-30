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

	"github.com/aegishjalmur/mcp-firewall/internal/config"
	"github.com/aegishjalmur/mcp-firewall/internal/server"
	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"
)

func main() {
	// Parse command-line flags
	var transport = flag.String("transport", "http", "Transport mode: http, stdio, or sse")
	flag.Parse()

	// Load environment variables
	if err := godotenv.Load(); err != nil {
		log.Println("Warning: .env file not found")
	}

	// Load configuration
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
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

// runSTDIOMode runs the server in STDIO mode
func runSTDIOMode(cfg *config.Config) {
	log.Println("Starting MCP Firewall in STDIO mode")

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

	// Wait for interrupt signal to gracefully shutdown the server
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	log.Println("Shutting down server...")

	// Graceful shutdown with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		log.Fatalf("Server forced to shutdown: %v", err)
	}

	log.Println("Server exited")
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