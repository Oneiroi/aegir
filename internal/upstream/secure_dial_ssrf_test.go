package upstream

import (
	"context"
	"fmt"
	"testing"
)

// errResolver simulates a failing resolver to exercise the fail-closed
// path of the package-level dial guard.
type errResolver struct{}

func (errResolver) LookupHost(ctx context.Context, host string) ([]string, error) {
	return nil, fmt.Errorf("simulated dns failure")
}

// TestSecureDialContext_DenylistFailsClosed pins item 6 (amended: static
// denylist): an unresolvable name under a reserved internal suffix is
// rejected by the dial guard, not dialed.
func TestSecureDialContext_DenylistFailsClosed(t *testing.T) {
	old := dnsResolver
	dnsResolver = errResolver{}
	defer func() { dnsResolver = old }()

	for _, h := range []string{"host.internal:80", "box.localhost:80", "svc.local:80"} {
		if _, err := secureDialContext(context.Background(), "tcp", h); err == nil {
			t.Errorf("expected the dial guard to reject %q, got nil", h)
		}
	}
}

// TestSecureDialContext_DNSFailClosed pins the adjacent behavior: any
// name whose lookup fails is rejected (no dial attempt on an
// unresolvable host).
func TestSecureDialContext_DNSFailClosed(t *testing.T) {
	old := dnsResolver
	dnsResolver = errResolver{}
	defer func() { dnsResolver = old }()

	if _, err := secureDialContext(context.Background(), "tcp", "no-such-host.example.net:80"); err == nil {
		t.Fatal("expected a dns-failure error, got nil")
	}
}
