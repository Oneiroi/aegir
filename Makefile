.PHONY: build run run-stdio run-sse test clean dev dev-stdio lint certs

# Build the application
build:
	go build -o bin/mcp-firewall ./cmd/server

# Run the application (default: HTTP mode)
run: build certs
	./bin/mcp-firewall

# Run in STDIO mode
run-stdio: build
	./bin/mcp-firewall -transport stdio

# Run in SSE mode (same as HTTP with SSE endpoints)
run-sse: build certs
	./bin/mcp-firewall -transport sse

# Run in development mode with hot reload
dev: certs
	go run ./cmd/server

# Run in development mode with STDIO transport
dev-stdio:
	go run ./cmd/server -transport stdio

# Run tests
test:
	go test -v ./...

# Clean build artifacts
clean:
	rm -rf bin/

# Lint the code
lint:
	golangci-lint run

# Install dependencies
deps:
	go mod download
	go mod tidy

# Generate certificates for development
certs:
	mkdir -p certs
	openssl req -x509 -newkey rsa:4096 -keyout certs/key.pem -out certs/cert.pem -days 365 -nodes -subj "/C=US/ST=CA/L=SF/O=MCP-Firewall/CN=localhost"