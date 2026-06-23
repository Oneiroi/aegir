package config

import (
	"strings"
	"testing"
)

func cfgWithSecret(secret string) *Config {
	c := &Config{}
	c.Auth.JWT.Secret = secret
	c.Logging.HMACKey = "f3a9c1e7b54d20986a1cdef0773b22aa9911ccef" // strong default so JWT tests don't fail on HMAC path
	return c
}

func cfgWithHMACKey(jwtSecret, hmacKey string) *Config {
	c := &Config{}
	c.Auth.JWT.Secret = jwtSecret
	c.Logging.HMACKey = hmacKey
	return c
}

func TestCheckProductionSecrets_RejectsWeak(t *testing.T) {
	t.Setenv(InsecureSecretsAllowedEnv, "") // ensure no override

	weak := []struct {
		name, secret string
	}{
		{"shipped dev yaml secret", "simple-dev-key-change-for-production"},
		{"shipped dev toml secret", "dev-secret-key-change-in-production"},
		{"json placeholder", "REPLACE_WITH_SECURE_SECRET_MIN_32_CHARS"},
		{"release placeholder", "CHANGE_ME_GENERATE_32B_RANDOM_SECRET"},
		{"empty", ""},
		{"whitespace only", "   "},
		{"too short", "short"},
		{"changeme", "changeme"},
	}
	for _, tc := range weak {
		t.Run(tc.name, func(t *testing.T) {
			if err := CheckProductionSecrets(cfgWithSecret(tc.secret)); err == nil {
				t.Fatalf("expected production guard to REJECT secret %q, but it passed", tc.secret)
			}
		})
	}
}

func TestCheckProductionSecrets_AcceptsStrong(t *testing.T) {
	t.Setenv(InsecureSecretsAllowedEnv, "")

	ok := []struct {
		name, secret string
	}{
		// The exact secret the auth unit tests use must keep passing.
		{"unit-test secret", "test-secret-key-for-unit-tests-only!"},
		{"random-ish 32+ chars", "f3a9c1e7b54d20986a1cdef0773b22aa9911ccef"},
	}
	for _, tc := range ok {
		t.Run(tc.name, func(t *testing.T) {
			if err := CheckProductionSecrets(cfgWithSecret(tc.secret)); err != nil {
				t.Fatalf("expected production guard to ACCEPT secret %q, got error: %v", tc.secret, err)
			}
		})
	}
}

func TestCheckProductionSecrets_OverrideAllowsWeak(t *testing.T) {
	t.Setenv(InsecureSecretsAllowedEnv, "true")
	if err := CheckProductionSecrets(cfgWithSecret("simple-dev-key-change-for-production")); err != nil {
		t.Fatalf("override env should downgrade to warning and allow startup, got error: %v", err)
	}
}

func TestCheckProductionSecrets_HMACKeyGuarded(t *testing.T) {
	t.Setenv(InsecureSecretsAllowedEnv, "")
	strongJWT := "f3a9c1e7b54d20986a1cdef0773b22aa9911ccef"

	weak := []struct {
		name, hmacKey string
	}{
		{"empty hmac key", ""},
		{"placeholder hmac key", "CHANGE_ME_IN_PRODUCTION_abc123"},
		{"short hmac key", "tooshort"},
	}
	for _, tc := range weak {
		t.Run(tc.name, func(t *testing.T) {
			if err := CheckProductionSecrets(cfgWithHMACKey(strongJWT, tc.hmacKey)); err == nil {
				t.Fatalf("expected guard to REJECT HMAC key %q, but it passed", tc.hmacKey)
			}
		})
	}

	// Strong HMAC key should be accepted.
	strong := cfgWithHMACKey(strongJWT, "d4a9c1e7b54d20986a1cdef0773b22aa9911beef")
	if err := CheckProductionSecrets(strong); err != nil {
		t.Fatalf("expected guard to ACCEPT strong HMAC key, got error: %v", err)
	}
}

func TestJWTSecretWeakness_Reasons(t *testing.T) {
	if got := jwtSecretWeakness(""); !strings.Contains(got, "empty") {
		t.Errorf("empty secret reason = %q, want it to mention empty", got)
	}
	if got := jwtSecretWeakness("test-secret-key-for-unit-tests-only!"); got != "" {
		t.Errorf("legit test secret should be accepted, got reason %q", got)
	}
}
