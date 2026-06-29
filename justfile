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

# Run with OMLX (Apple Silicon MLX) as the LLM judge backend.
# OMLX must already be serving: omlx serve --port 8000
# Judge config is Aegir-side via MCP_* Viper overrides (prefix "MCP", not "AEGIR").
# Model override: OMLX_MODEL=gemma-4-31B-it-8bit just run-judge-omlx
run-judge-omlx: build certs
    #!/usr/bin/env bash
    AEGIR_ALLOW_INSECURE_JWT_SECRET=true \
    MCP_JUDGE_ENABLED=true \
    MCP_JUDGE_PROVIDER=openai \
    MCP_JUDGE_BASE_URL=http://localhost:8000/v1 \
    MCP_JUDGE_MODEL="${OMLX_MODEL:-gemma-4-26B-A4B-it-8bit}" \
    ./bin/aegir

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
# Requires Aegir started with AEGIR_ADMIN_PASSWORD=admin123 (or set AEGIR_ADMIN_PASSWORD to match startup log)
token:
    #!/usr/bin/env bash
    PASSWORD="${AEGIR_ADMIN_PASSWORD:-admin123}"
    curl -sk -X POST https://localhost:8443/auth/login \
        -H "Content-Type: application/json" \
        -d "{\"username\": \"admin\", \"password\": \"$PASSWORD\"}"

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
# AEGIR_BENCH_JUDGE is a report label only — it does NOT configure which judge Aegir uses.
# To benchmark with OMLX as judge: start Aegir via 'just run-judge-omlx' first, then run bench.
# Usage: AEGIR_BENCH_TOKEN=$(just token | jq -r .access_token) [AEGIR_BENCH_JUDGE=omlx] just bench
bench:
    go run ./benchmark --target https://localhost:8443 --insecure --judge-provider "${AEGIR_BENCH_JUDGE:-ollama}"

# Latency benchmark against local corpus files (redteam/aegir/*.jsonl, not committed)
# Falls back to benign_corpus.jsonl if adversarial.jsonl hasn't been generated yet.
# To generate adversarial.jsonl first: cd redteam/aegir && python3 harvest.py
# AEGIR_BENCH_JUDGE is a report label only — start Aegir via 'just run-judge-omlx' to actually use OMLX.
# Usage: AEGIR_BENCH_TOKEN=$(just token | jq -r .access_token) just bench-redteam
bench-redteam:
    #!/usr/bin/env bash
    set -e
    if [ -f redteam/aegir/corpus/adversarial.jsonl ]; then
        CORPUS=redteam/aegir/corpus/adversarial.jsonl
    else
        echo "No adversarial corpus found — using benign_corpus.jsonl (run harvest.py to generate attack corpus)"
        CORPUS=redteam/aegir/benign_corpus.jsonl
    fi
    go run ./benchmark --target https://localhost:8443 --insecure --judge-provider "${AEGIR_BENCH_JUDGE:-ollama}" --payload-file "$CORPUS"

# Latency benchmark with custom payload file
# Usage: just bench-file PAYLOADS=/path/to/payloads.txt
bench-file PAYLOADS='':
    go run ./benchmark \
        --target https://localhost:8443 \
        --insecure \
        --judge-provider "${AEGIR_BENCH_JUDGE:-ollama}" \
        --payload-file "{{PAYLOADS}}"
