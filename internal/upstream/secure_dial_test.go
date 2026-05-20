package upstream

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"
)

// TestSecureDialContext_BlocksLoopbackIP verifies that a direct dial to the
// loopback literal IP is rejected with the SSRF error before any TCP
// connection is attempted. This is the canonical DNS-rebinding payload:
// attacker-controlled DNS resolves to 127.0.0.1 at connection time.
func TestSecureDialContext_BlocksLoopbackIP(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	_, err := secureDialContext(ctx, "tcp", "127.0.0.1:8080")
	if err == nil {
		t.Fatalf("expected SSRF error for 127.0.0.1, got nil")
	}
	if !strings.Contains(err.Error(), "SSRF") {
		t.Fatalf("expected error to contain \"SSRF\", got %q", err.Error())
	}
	if !strings.Contains(err.Error(), "restricted range") {
		t.Fatalf("expected error to mention restricted range, got %q", err.Error())
	}
}

// TestSecureDialContext_BlocksInternalHostname verifies that metadata.google.internal
// is rejected by string match before any DNS lookup happens.
func TestSecureDialContext_BlocksInternalHostname(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	_, err := secureDialContext(ctx, "tcp", "metadata.google.internal:80")
	if err == nil {
		t.Fatalf("expected SSRF error for metadata.google.internal, got nil")
	}
	if !strings.Contains(err.Error(), "SSRF") {
		t.Fatalf("expected error to contain \"SSRF\", got %q", err.Error())
	}
	if !strings.Contains(err.Error(), "internal hostname") {
		t.Fatalf("expected error to mention internal hostname, got %q", err.Error())
	}
}

// TestSecureDialContext_BlocksLocalhostLiteral verifies the literal "localhost"
// host is rejected at the dial layer (defence-in-depth alongside hostname
// validation in validateResourceURI).
func TestSecureDialContext_BlocksLocalhostLiteral(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	_, err := secureDialContext(ctx, "tcp", "localhost:80")
	if err == nil {
		t.Fatalf("expected SSRF error for localhost, got nil")
	}
	if !strings.Contains(err.Error(), "SSRF") {
		t.Fatalf("expected error to contain \"SSRF\", got %q", err.Error())
	}
}

// TestSecureDialContext_BlocksPrivateIP verifies that an RFC1918 literal IP
// is rejected (this is the canonical DNS-rebinding payload — attacker domain
// resolves to 192.168.x.x at connection time).
func TestSecureDialContext_BlocksPrivateIP(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	_, err := secureDialContext(ctx, "tcp", "192.168.1.1:80")
	if err == nil {
		t.Fatalf("expected SSRF error for 192.168.1.1, got nil")
	}
	if !strings.Contains(err.Error(), "SSRF") {
		t.Fatalf("expected error to contain \"SSRF\", got %q", err.Error())
	}
	if !strings.Contains(err.Error(), "restricted range") {
		t.Fatalf("expected error to mention restricted range, got %q", err.Error())
	}
}

// TestSecureDialContext_BlocksLinkLocalMetadataIP verifies that the GCE/AWS
// metadata service IP (link-local 169.254.169.254) is rejected even if the
// hostname check is somehow bypassed.
func TestSecureDialContext_BlocksLinkLocalMetadataIP(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	_, err := secureDialContext(ctx, "tcp", "169.254.169.254:80")
	if err == nil {
		t.Fatalf("expected SSRF error for 169.254.169.254, got nil")
	}
	if !strings.Contains(err.Error(), "SSRF") {
		t.Fatalf("expected error to contain \"SSRF\", got %q", err.Error())
	}
}

// TestIsRestrictedIP_PublicAddressAllowed verifies the policy function returns
// false for a known-public IP (example.com / 93.184.216.34). Avoids a live
// network call.
func TestIsRestrictedIP_PublicAddressAllowed(t *testing.T) {
	ip := net.ParseIP("93.184.216.34")
	if ip == nil {
		t.Fatal("failed to parse public test IP")
	}
	if isRestrictedIP(ip) {
		t.Fatalf("93.184.216.34 should not be classified as restricted")
	}
}

// TestIsRestrictedIP_Categories spot-checks every category enforced by the
// SSRF policy so a regression in any branch is caught.
func TestIsRestrictedIP_Categories(t *testing.T) {
	cases := []struct {
		name string
		ip   string
	}{
		{"loopback v4", "127.0.0.1"},
		{"loopback v6", "::1"},
		{"link-local unicast", "169.254.1.1"},
		{"private 10/8", "10.0.0.1"},
		{"private 192.168/16", "192.168.1.1"},
		{"private 172.16/12", "172.16.0.1"},
		{"unspecified v4", "0.0.0.0"},
		{"multicast", "224.0.0.1"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ip := net.ParseIP(c.ip)
			if ip == nil {
				t.Fatalf("failed to parse %s", c.ip)
			}
			if !isRestrictedIP(ip) {
				t.Fatalf("%s (%s) should be restricted but was allowed", c.name, c.ip)
			}
		})
	}
}
