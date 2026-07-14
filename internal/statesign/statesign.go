// Package statesign issues and verifies HMAC-signed client-state / task-ID
// tokens (ISC-175/176).
//
// The MCP 2026-07-28 spec's stateless model requires clients to hand back
// state objects and task identifiers the server trusts to resume a workflow.
// With Mcp-Session-Id removed, a predictable or unsigned ID lets an attacker
// hijack another identity's workflow — the gateway must issue tokens it can
// cryptographically prove it minted, bound to the identity that requested
// them, and reject anything else outright rather than attempt to resume it.
package statesign

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"strings"
)

// Claims is the signed payload embedded in a state/task token.
type Claims struct {
	TaskID   string `json:"task_id"`
	Identity string `json:"identity"`
	Tenant   string `json:"tenant,omitempty"`
}

// Signer issues and verifies tokens keyed on a shared HMAC secret.
type Signer struct {
	key []byte
}

// NewSigner constructs a Signer with the given HMAC key. An empty key is
// accepted (verification then only proves internal consistency, not secrecy)
// but callers should always supply a real key outside of tests.
func NewSigner(key []byte) *Signer {
	return &Signer{key: key}
}

// Sign issues an opaque, tamper-evident token:
// base64url(json(claims)) + "." + base64url(hmac-sha256(payload)).
func (s *Signer) Sign(c Claims) (string, error) {
	payload, err := json.Marshal(c)
	if err != nil {
		return "", err
	}
	encodedPayload := base64.RawURLEncoding.EncodeToString(payload)
	sig := s.sign(encodedPayload)
	return encodedPayload + "." + sig, nil
}

func (s *Signer) sign(encodedPayload string) string {
	mac := hmac.New(sha256.New, s.key)
	mac.Write([]byte(encodedPayload))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

// Verify checks a token's signature and decodes its claims. Returns ok=false
// for any malformed, unsigned, or tampered token — there is no partial trust
// of a token that fails verification.
func (s *Signer) Verify(token string) (claims Claims, ok bool) {
	parts := strings.SplitN(token, ".", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return Claims{}, false
	}
	encodedPayload, sig := parts[0], parts[1]

	expectedSig := s.sign(encodedPayload)
	if subtle.ConstantTimeCompare([]byte(sig), []byte(expectedSig)) != 1 {
		return Claims{}, false
	}

	payload, err := base64.RawURLEncoding.DecodeString(encodedPayload)
	if err != nil {
		return Claims{}, false
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return Claims{}, false
	}
	return claims, true
}

// VerifyForIdentity verifies the token's signature AND enforces identity
// isolation (ISC-176): a token issued to one identity is rejected outright
// when redeemed by a different identity, even with a fully valid signature.
func (s *Signer) VerifyForIdentity(token, requestingIdentity string) (claims Claims, ok bool) {
	claims, ok = s.Verify(token)
	if !ok {
		return Claims{}, false
	}
	if requestingIdentity == "" || claims.Identity != requestingIdentity {
		return Claims{}, false
	}
	return claims, true
}
