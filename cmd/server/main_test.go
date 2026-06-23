package main

import (
	"bytes"
	"context"
	"flag"
	"os"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aegishjalmur/aegir/internal/config"
)

func TestTransportModeSelection(t *testing.T) {
	// The dev config ships a placeholder JWT secret; opt into it so the
	// production secret guard (CheckProductionSecrets) doesn't block startup.
	t.Setenv("AEGIR_ALLOW_INSECURE_JWT_SECRET", "true")

	// Test data for different transport modes
	tests := []struct {
		name            string
		transport       string
		expectError     bool
		errorContains   string
		expectedOutput  string
	}{
		{
			name:           "HTTP mode",
			transport:      "http",
			expectError:    false,
			expectedOutput: "Starting MCP Firewall server in http mode",
		},
		{
			name:           "SSE mode",
			transport:      "sse",
			expectError:    false,
			expectedOutput: "Starting MCP Firewall server in sse mode",
		},
		{
			name:           "STDIO mode",
			transport:      "stdio",
			expectError:    false,
			expectedOutput: "Starting MCP Firewall in STDIO mode",
		},
		{
			name:          "Invalid mode",
			transport:     "invalid",
			expectError:   true,
			errorContains: "Invalid transport mode: invalid",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Build the binary for testing
			cmd := exec.Command("go", "build", "-o", "test-aegir", ".")
			if err := cmd.Run(); err != nil {
				t.Fatalf("Failed to build test binary: %v", err)
			}
			defer os.Remove("./test-aegir")

			// Prepare command with transport flag
			args := []string{"./test-aegir", "-transport", tt.transport}

			// For STDIO mode, provide input to prevent hanging
			var stdin *bytes.Buffer
			if tt.transport == "stdio" {
				stdin = bytes.NewBufferString(`{"method":"initialize","params":{"protocolVersion":"2025-06-18"},"id":"1"}`)
			}

			// Create context with timeout to prevent hanging
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()

			testCmd := exec.CommandContext(ctx, args[0], args[1:]...)
			if stdin != nil {
				testCmd.Stdin = stdin
			}

			var stdout, stderr bytes.Buffer
			testCmd.Stdout = &stdout
			testCmd.Stderr = &stderr

			// Run the command
			_ = testCmd.Run()

			if tt.expectError {
				// For error cases, check stderr for expected error message
				stderrStr := stderr.String()
				if !strings.Contains(stderrStr, tt.errorContains) {
					t.Errorf("Expected error containing '%s', got stderr: %s", tt.errorContains, stderrStr)
				}
			} else {
				// For success cases, check if the expected output appears in stderr (where logs go)
				stderrStr := stderr.String()
				if !strings.Contains(stderrStr, tt.expectedOutput) {
					t.Errorf("Expected output containing '%s', got stderr: %s", tt.expectedOutput, stderrStr)
				}

				// For STDIO mode, also check stdout for the response
				if tt.transport == "stdio" {
					stdoutStr := stdout.String()
					if !strings.Contains(stdoutStr, `"protocolVersion":"2025-06-18"`) {
						t.Errorf("Expected MCP response in stdout, got: %s", stdoutStr)
					}
				}
			}
		})
	}
}

func TestCommandLineFlags(t *testing.T) {
	// Save original command line args
	oldArgs := os.Args
	defer func() { os.Args = oldArgs }()

	// Test help flag
	os.Args = []string{"cmd", "-h"}

	// Reset flag package state
	flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ContinueOnError)

	// Capture output
	var buf bytes.Buffer
	flag.CommandLine.SetOutput(&buf)

	// Parse flags
	transport := flag.String("transport", "http", "Transport mode: http, stdio, or sse")
	err := flag.CommandLine.Parse(os.Args[1:])

	// Should get help output
	if err != flag.ErrHelp {
		output := buf.String()
		if !strings.Contains(output, "Transport mode: http, stdio, or sse") {
			t.Error("Help message should contain transport mode description")
		}
	}

	// Test valid transport flag
	os.Args = []string{"cmd", "-transport", "stdio"}
	flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ContinueOnError)
	transport = flag.String("transport", "http", "Transport mode: http, stdio, or sse")
	err = flag.CommandLine.Parse(os.Args[1:])

	if err != nil {
		t.Errorf("Failed to parse valid transport flag: %v", err)
	}
	if *transport != "stdio" {
		t.Errorf("Expected transport 'stdio', got: %s", *transport)
	}
}

func TestEnvironmentVariableHandling(t *testing.T) {
	// Test with missing .env file (should not cause fatal error)
	tests := []struct {
		name        string
		envVars     map[string]string
		expectError bool
	}{
		{
			name: "Default environment",
			envVars: map[string]string{
				"MCP_ENV": "test",
			},
			expectError: false,
		},
		{
			name: "Production environment",
			envVars: map[string]string{
				"MCP_ENV":        "production",
				"MCP_SERVER_PORT": "9443",
			},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Set environment variables
			for key, value := range tt.envVars {
				os.Setenv(key, value)
				defer os.Unsetenv(key)
			}

			// Build and run the binary with a quick exit
			cmd := exec.Command("go", "build", "-o", "test-aegir-env", ".")
			if err := cmd.Run(); err != nil {
				t.Fatalf("Failed to build test binary: %v", err)
			}
			defer os.Remove("./test-aegir-env")

			// Create context with very short timeout since we just want to test startup
			ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
			defer cancel()

			// Run with STDIO mode and immediate input to cause quick exit
			testCmd := exec.CommandContext(ctx, "./test-aegir-env", "-transport", "stdio")
			testCmd.Stdin = strings.NewReader("")  // Empty input causes EOF and exit

			var stderr bytes.Buffer
			testCmd.Stderr = &stderr

			// Run the command (expect timeout or clean exit)
			_ = testCmd.Run()

			// Check that it doesn't fail due to configuration issues
			stderrStr := stderr.String()
			if strings.Contains(stderrStr, "Failed to load configuration") {
				t.Errorf("Configuration loading failed: %s", stderrStr)
			}
			if strings.Contains(stderrStr, "Failed to create server") {
				t.Errorf("Server creation failed: %s", stderrStr)
			}
		})
	}
}

func TestTLSConfigurationCreation(t *testing.T) {
	// Test that we can create TLS config without errors
	cfg := &config.Config{
		Server: config.Server{
			TLS: config.TLS{
				Enabled:  true,
				CertFile: "../../certs/cert.pem",
				KeyFile:  "../../certs/key.pem",
			},
		},
	}

	tlsConfig := createTLSConfig(cfg)

	if tlsConfig == nil {
		t.Error("TLS config should not be nil")
	}

	// Verify TLS 1.3 minimum
	if tlsConfig.MinVersion != 0x0304 { // TLS 1.3
		t.Errorf("Expected TLS 1.3 minimum (0x0304), got: 0x%04x", tlsConfig.MinVersion)
	}

	// Verify cipher suites are set
	if len(tlsConfig.CipherSuites) == 0 {
		t.Error("Expected cipher suites to be configured")
	}

	// Verify curve preferences are set
	if len(tlsConfig.CurvePreferences) == 0 {
		t.Error("Expected curve preferences to be configured")
	}
}

func TestGracefulShutdown(t *testing.T) {
	// Build the binary
	cmd := exec.Command("go", "build", "-o", "test-aegir-shutdown", ".")
	if err := cmd.Run(); err != nil {
		t.Fatalf("Failed to build test binary: %v", err)
	}
	defer os.Remove("./test-aegir-shutdown")

	// Start the server in HTTP mode
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	testCmd := exec.CommandContext(ctx, "./test-aegir-shutdown", "-transport", "http")
	testCmd.Env = append(os.Environ(),
		"MCP_SERVER_TLS_ENABLED=false",
		// Dev config ships a placeholder JWT secret; opt past the production guard.
		"AEGIR_ALLOW_INSECURE_JWT_SECRET=true")

	stderr := &syncBuffer{}
	testCmd.Stderr = stderr

	// Start the command
	if err := testCmd.Start(); err != nil {
		t.Fatalf("Failed to start test binary: %v", err)
	}

	// Wait until the server has actually logged that it started before
	// signalling shutdown. Route registration + init routinely take longer than
	// a fixed sleep on a loaded host, which previously raced this assertion.
	const startupMsg = "Starting MCP Firewall server in http mode"
	deadline := time.Now().Add(15 * time.Second)
	for !strings.Contains(stderr.String(), startupMsg) {
		if time.Now().After(deadline) {
			t.Fatalf("server did not log startup within timeout; stderr:\n%s", stderr.String())
		}
		time.Sleep(50 * time.Millisecond)
	}

	// Send interrupt signal
	if err := testCmd.Process.Signal(os.Interrupt); err != nil {
		t.Fatalf("Failed to send interrupt signal: %v", err)
	}

	// Wait for graceful shutdown
	err := testCmd.Wait()

	// The process should exit cleanly (context cancellation is expected)
	if err != nil && !strings.Contains(err.Error(), "signal: interrupt") {
		t.Errorf("Unexpected error during shutdown: %v", err)
	}
}

// syncBuffer is a goroutine-safe buffer: the test polls stderr while the child
// process writes to it concurrently, so a plain bytes.Buffer would data-race.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}