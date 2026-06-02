# Aegir MCP Firewall — task runner
# https://just.systems/man/en/

default: build

# Build the binary
build:
    go build -o bin/aegir ./cmd/server

# Build and run (HTTP mode)
run: build certs
    ./bin/aegir

# Build and run with STDIO transport
run-stdio: build
    ./bin/aegir -transport stdio

# Build and run with SSE transport
run-sse: build certs
    ./bin/aegir -transport sse

# Run from source (no build step)
dev: certs
    go run ./cmd/server

# Run from source with STDIO transport
dev-stdio:
    go run ./cmd/server -transport stdio

# TLS + rate-limiting disabled for quick testing
demo: build
    TLS_ENABLED=false RATE_LIMIT_ENABLED=false go run ./cmd/server

# Run all tests
test:
    go test -v ./...

# Remove build artifacts
clean:
    rm -f bin/aegir bin/mcp-firewall

# Run linter
lint:
    golangci-lint run

# Download and tidy dependencies
deps:
    go mod download
    go mod tidy

# Generate self-signed TLS certs for development (skips if both files exist)
certs:
    #!/usr/bin/env bash
    if [[ -f certs/key.pem && -f certs/cert.pem ]]; then exit 0; fi
    mkdir -p certs
    openssl req -x509 -newkey rsa:4096 \
        -keyout certs/key.pem -out certs/cert.pem \
        -days 365 -nodes \
        -subj "/C=US/ST=CA/L=SF/O=Aegir/CN=localhost"

# Force-regenerate TLS certs
certs-force:
    mkdir -p certs
    openssl req -x509 -newkey rsa:4096 \
        -keyout certs/key.pem -out certs/cert.pem \
        -days 365 -nodes \
        -subj "/C=US/ST=CA/L=SF/O=Aegir/CN=localhost"

# Fetch a default admin JWT (server must be running on :8443)
token:
    curl -k -X POST https://localhost:8443/auth/login \
        -H "Content-Type: application/json" \
        -d '{"username": "admin", "password": "admin123"}'

# Run the full demo flow — builds, starts server + mock upstream, loops test scenarios
demo-flow:
    ./bin/demo-flow-test.sh
