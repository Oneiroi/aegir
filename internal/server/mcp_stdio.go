package server

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"

	"github.com/aegishjalmur/aegir/internal/logging"
	"github.com/aegishjalmur/aegir/internal/sanitizer"
)

// MCPSTDIOTransport handles STDIO-based MCP communication
type MCPSTDIOTransport struct {
	logger            *logging.Logger
	sanitizer         *sanitizer.Manager
	complianceManager *sanitizer.ComplianceManager
	reader            *bufio.Scanner
	writer            io.Writer
}

// NewMCPSTDIOTransport creates a new STDIO transport instance
func NewMCPSTDIOTransport(logger *logging.Logger, sanitizerMgr *sanitizer.Manager, complianceMgr *sanitizer.ComplianceManager) *MCPSTDIOTransport {
	return &MCPSTDIOTransport{
		logger:            logger,
		sanitizer:         sanitizerMgr,
		complianceManager: complianceMgr,
		reader:            bufio.NewScanner(os.Stdin),
		writer:            os.Stdout,
	}
}

// Start begins the STDIO transport loop
func (s *MCPSTDIOTransport) Start(ctx context.Context) error {
	s.logger.Info("Starting MCP STDIO transport")

	// Set up signal handling for graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// Create a context that cancels on signal
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	go func() {
		<-sigChan
		s.logger.Info("Received shutdown signal, stopping STDIO transport")
		cancel()
	}()

	// Main message processing loop
	for {
		select {
		case <-ctx.Done():
			s.logger.Info("STDIO transport context cancelled, shutting down")
			return ctx.Err()
		default:
			// Read a line from stdin
			if !s.reader.Scan() {
				if err := s.reader.Err(); err != nil {
					s.logger.Error("STDIO read error", "error", err)
					return err
				}
				// EOF reached
				s.logger.Info("STDIO input stream closed")
				return nil
			}

			line := s.reader.Text()
			if line == "" {
				continue
			}

			// Process the message
			if err := s.processMessage(line); err != nil {
				s.logger.Error("Message processing error", "error", err)
				// Continue processing other messages even if one fails
			}
		}
	}
}

// processMessage processes a single MCP message received via STDIO
func (s *MCPSTDIOTransport) processMessage(message string) error {
	s.logger.Debug("Processing STDIO message", "message", message)

	// Parse the JSON-RPC message
	var mcpRequest MCPRequest
	if err := json.Unmarshal([]byte(message), &mcpRequest); err != nil {
		// Send error response
		errorResponse := MCPResponse{
			Error: &MCPError{
				Code:    -32700, // Parse error
				Message: "Parse error: " + err.Error(),
			},
			ID: nil,
		}
		return s.sendResponse(errorResponse)
	}

	// Apply security filtering
	sanitized := s.sanitizer.SanitizeContent(message)
	if sanitized.Blocked {
		// Send blocked response
		errorResponse := MCPResponse{
			Error: &MCPError{
				Code:    -32000,
				Message: "Request blocked by security policy",
			},
			ID: mcpRequest.ID,
		}
		return s.sendResponse(errorResponse)
	}

	// Create a new MCP proxy for request handling
	proxy := &MCPProxy{
		logger:            s.logger,
		sanitizer:         s.sanitizer,
		complianceManager: s.complianceManager,
	}

	// Process the MCP request
	response := proxy.processMCPMethod(context.Background(), &mcpRequest)

	// Send the response
	return s.sendResponse(*response)
}

// sendResponse sends a response via STDIO
func (s *MCPSTDIOTransport) sendResponse(response MCPResponse) error {
	responseJSON, err := json.Marshal(response)
	if err != nil {
		s.logger.Error("Failed to marshal response", "error", err)
		return err
	}

	// Write response to stdout
	_, err = fmt.Fprintf(s.writer, "%s\n", responseJSON)
	if err != nil {
		s.logger.Error("Failed to write response", "error", err)
		return err
	}

	s.logger.Debug("Sent STDIO response", "response", string(responseJSON))
	return nil
}

// Stop gracefully stops the STDIO transport
func (s *MCPSTDIOTransport) Stop() error {
	s.logger.Info("Stopping MCP STDIO transport")
	return nil
}