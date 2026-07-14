package statesign

import "testing"

func TestSignAndVerifyRoundTrip(t *testing.T) {
	s := NewSigner([]byte("test-signing-key-32-bytes-long!!"))
	token, err := s.Sign(Claims{TaskID: "task-1", Identity: "alice", Tenant: "acme"})
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	claims, ok := s.Verify(token)
	if !ok {
		t.Fatalf("expected a freshly signed token to verify")
	}
	if claims.TaskID != "task-1" || claims.Identity != "alice" || claims.Tenant != "acme" {
		t.Errorf("unexpected claims: %+v", claims)
	}
}

// TestUnsignedResumeStateRejected verifies ISC-175: a client-supplied token
// with no valid signature (garbage, or missing the signature segment
// entirely) is rejected outright.
func TestUnsignedResumeStateRejected(t *testing.T) {
	s := NewSigner([]byte("test-signing-key-32-bytes-long!!"))

	cases := []string{
		"",
		"not-a-token-at-all",
		"eyJ0YXNrX2lkIjoidGFzay0xIn0", // payload with no signature segment
		"eyJ0YXNrX2lkIjoidGFzay0xIn0.",
		".somesignature",
	}
	for _, tc := range cases {
		if _, ok := s.Verify(tc); ok {
			t.Errorf("expected unsigned/malformed token %q to be rejected", tc)
		}
	}
}

// TestTamperedTaskIdRejected verifies ISC-175: a token whose payload has been
// altered after signing (e.g. swapping in a different task_id) fails
// verification even though it is otherwise well-formed.
func TestTamperedTaskIdRejected(t *testing.T) {
	s := NewSigner([]byte("test-signing-key-32-bytes-long!!"))
	token, err := s.Sign(Claims{TaskID: "task-1", Identity: "alice"})
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	// Forge a token for a different, higher-privilege task ID by signing it
	// with a *different* (attacker-guessed/weak) key, simulating an attacker
	// who doesn't have the real key trying to mint their own token.
	forged, err := NewSigner([]byte("attacker-guessed-key")).Sign(Claims{TaskID: "task-99-admin", Identity: "alice"})
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}
	if _, ok := s.Verify(forged); ok {
		t.Fatalf("expected a token signed with the wrong key to be rejected")
	}

	// Also verify naive tampering: truncate/mutate the payload segment of a
	// legitimately-signed token and confirm the signature no longer matches.
	tampered := token[:len(token)-1] + "X"
	if tampered == token {
		t.Fatalf("test setup error: tampering did not change the token")
	}
	if _, ok := s.Verify(tampered); ok {
		t.Fatalf("expected a tampered token to be rejected")
	}
}

// TestCrossTenantResumeDenied verifies ISC-176: a token issued to one
// identity cannot be redeemed by a different identity, even with a fully
// valid signature from the real key.
func TestCrossTenantResumeDenied(t *testing.T) {
	s := NewSigner([]byte("test-signing-key-32-bytes-long!!"))
	token, err := s.Sign(Claims{TaskID: "task-1", Identity: "alice", Tenant: "tenant-a"})
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	if _, ok := s.VerifyForIdentity(token, "bob"); ok {
		t.Fatalf("expected identity 'bob' to be denied a token issued to 'alice'")
	}

	claims, ok := s.VerifyForIdentity(token, "alice")
	if !ok {
		t.Fatalf("expected the issuing identity 'alice' to redeem its own token")
	}
	if claims.Tenant != "tenant-a" {
		t.Errorf("expected tenant 'tenant-a', got %q", claims.Tenant)
	}
}
