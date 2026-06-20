# Multi-stage build: Stage 1 - Builder
FROM golang:1.21-alpine AS builder

WORKDIR /build

# Install build dependencies
RUN apk add --no-cache git make

# Copy go mod files
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy source code
COPY . .

# Build the binary
RUN go build -o /build/bin/aegir ./cmd/server

# Multi-stage build: Stage 2 - Final image
FROM alpine:latest

# Install ca-certificates for TLS/HTTPS support
RUN apk add --no-cache ca-certificates

WORKDIR /app

# Copy binary from builder stage
COPY --from=builder /build/bin/aegir /app/aegir

# Copy config file (renamed from example to default config)
COPY aegir.yaml /app/config.yaml

# Expose HTTPS port
EXPOSE 8443

# Set the entrypoint to run the aegir binary
ENTRYPOINT ["/app/aegir"]
