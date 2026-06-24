# Aegir MCP Firewall — task runner
# https://just.systems/man/en/

default: build

# Build the binary
build:
    go build -o bin/aegir ./cmd/server

# Build and run (HTTP mode). AEGIR_ALLOW_INSECURE_JWT_SECRET permits the dev
# secret in aegir.yaml; production runs ./bin/aegir without it and fails closed.
run: build certs
    AEGIR_ALLOW_INSECURE_JWT_SECRET=true ./bin/aegir

# Build and run with STDIO transport
run-stdio: build
    AEGIR_ALLOW_INSECURE_JWT_SECRET=true ./bin/aegir -transport stdio

# Build and run with SSE transport
run-sse: build certs
    AEGIR_ALLOW_INSECURE_JWT_SECRET=true ./bin/aegir -transport sse

# Run from source (no build step)
dev: certs
    AEGIR_ALLOW_INSECURE_JWT_SECRET=true go run ./cmd/server

# Run from source with STDIO transport
dev-stdio:
    AEGIR_ALLOW_INSECURE_JWT_SECRET=true go run ./cmd/server -transport stdio

# TLS + rate-limiting disabled for quick testing
demo: build
    AEGIR_ALLOW_INSECURE_JWT_SECRET=true TLS_ENABLED=false RATE_LIMIT_ENABLED=false go run ./cmd/server

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

# Build the MCP echo server (benign upstream for red-team testing)
build-echo:
    go build -o bin/echo-server ./cmd/echoserver

# Start the echo server on :8080 (use as upstream when red-teaming Aegir)
echo-server: build-echo
    ./bin/echo-server

# Run the full demo flow — builds, starts server + mock upstream, loops test scenarios
demo-flow:
    AEGIR_ALLOW_INSECURE_JWT_SECRET=true ./bin/demo-flow-test.sh

# CI/ISC-84 probe: one-shot demo run — exits 0 when all flows pass
demo-flow-test:
    AEGIR_ALLOW_INSECURE_JWT_SECRET=true ./bin/demo-flow-test.sh --once

# Latency benchmark — built-in scenarios (server must be running, AEGIR_BENCH_TOKEN must be set)
# Usage: AEGIR_BENCH_TOKEN=$(just token | jq -r .access_token) just bench
bench:
    go run ./benchmark --target https://localhost:8443 --insecure --judge-provider "${AEGIR_BENCH_JUDGE:-ollama}"

# Latency benchmark with redteam attack catalog (local only, not committed)
# Usage: just bench-redteam
bench-redteam:
    go run ./benchmark \
        --target https://localhost:8443 \
        --insecure \
        --judge-provider "${AEGIR_BENCH_JUDGE:-ollama}" \
        --payload-file <(python3 -c " \
            import yaml, sys; \
            cat = yaml.safe_load(open('redteam/aegir/attack_catalog.yaml')); \
            [print(a['payload']) for a in cat.get('attacks', []) if a.get('payload')] \
        ")

# Latency benchmark with custom payload file
# Usage: just bench-file PAYLOADS=/path/to/payloads.txt
bench-file PAYLOADS='':
    go run ./benchmark \
        --target https://localhost:8443 \
        --insecure \
        --judge-provider "${AEGIR_BENCH_JUDGE:-ollama}" \
        --payload-file "{{PAYLOADS}}"
