.PHONY: build run test clean dev lint

# Build the application
build:
	go build -o bin/mcp-firewall ./cmd/server

# Run the application
run: build
	./bin/mcp-firewall

# Run in development mode with hot reload
dev:
	go run ./cmd/server

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