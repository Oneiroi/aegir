package config

import (
	"fmt"
	"os"
	"strings"
)

// InsecureSecretsAllowedEnv, when set truthy, downgrades the production secret
// guard from fatal to a loud warning. For LOCAL DEV ONLY — the just run/dev/demo
// targets set it. A real deployment leaves it unset and therefore fails closed
// on a weak JWT signing secret.
const InsecureSecretsAllowedEnv = "AEGIR_ALLOW_INSECURE_JWT_SECRET"

// minJWTSecretLen is the floor for an HS256 signing secret. Anything shorter is
// rejected outright. (The shipped example secrets are longer than this but are
// caught by the placeholder checks below.)
const minJWTSecretLen = 16

// knownWeakJWTSecrets are exact values that have shipped in example configs or
// are obvious dev defaults. Running production on any of these is a critical
// auth bypass: anyone who reads the public repo can forge admin tokens.
var knownWeakJWTSecrets = map[string]struct{}{
	"simple-dev-key-change-for-production":    {},
	"dev-secret-key-change-in-production":     {},
	"replace_with_secure_secret_min_32_chars": {},
	"change_me_generate_32b_random_secret":    {},
	"changeme":                                {},
	"secret":                                  {},
	"your-secret-key":                         {},
	"your-256-bit-secret":                     {},
}

// weakJWTSecretMarkers are substrings that mark a secret as an un-replaced
// placeholder. Deliberately chosen NOT to match legitimate test secrets such as
// "test-secret-key-for-unit-tests-only!" — none of these appear in that string.
var weakJWTSecretMarkers = []string{
	"change-in-production",
	"change-for-production",
	"change_me",
	"changeme",
	"replace_with",
	"replace-with",
	"placeholder",
	"insecure",
	"example-secret",
}

// CheckProductionSecrets fails closed when either the JWT signing secret or the
// audit-log HMAC key is empty, a known dev/placeholder value, or too short —
// unless the operator has explicitly opted into insecure secrets via
// AEGIR_ALLOW_INSECURE_JWT_SECRET, in which case it warns loudly and allows
// startup. Intended to be called once at server startup, before any transport
// begins serving. Tests do not run main() and are unaffected.
func CheckProductionSecrets(cfg *Config) error {
	jwtReason := jwtSecretWeakness(cfg.Auth.JWT.Secret)
	hmacReason := jwtSecretWeakness(cfg.Logging.HMACKey)

	if jwtReason == "" && hmacReason == "" {
		return nil
	}

	if isTruthyEnv(os.Getenv(InsecureSecretsAllowedEnv)) {
		if jwtReason != "" {
			fmt.Fprintf(os.Stderr,
				"\n*** SECURITY WARNING ***\n"+
					"Aegir is starting with an INSECURE JWT signing secret (%s) because %s is set.\n"+
					"Anyone who knows this secret can forge admin tokens. NEVER do this in production.\n"+
					"Set a strong JWT_SECRET (>= %d random chars) before deploying.\n\n",
				jwtReason, InsecureSecretsAllowedEnv, minJWTSecretLen)
		}
		if hmacReason != "" {
			fmt.Fprintf(os.Stderr,
				"\n*** SECURITY WARNING ***\n"+
					"Aegir is starting with an INSECURE audit-log HMAC key (%s) because %s is set.\n"+
					"Audit log integrity cannot be verified across restarts. NEVER do this in production.\n"+
					"Set a stable LOG_HMAC_KEY (>= %d random chars) before deploying.\n\n",
				hmacReason, InsecureSecretsAllowedEnv, minJWTSecretLen)
		}
		return nil
	}

	if jwtReason != "" {
		return fmt.Errorf(
			"refusing to start: JWT signing secret is %s — set a strong secret via the "+
				"JWT_SECRET env var or auth.jwt.secret config (>= %d random chars), or set %s=1 "+
				"to override for LOCAL DEV ONLY",
			jwtReason, minJWTSecretLen, InsecureSecretsAllowedEnv)
	}
	return fmt.Errorf(
		"refusing to start: audit-log HMAC key is %s — set a stable key via the "+
			"LOG_HMAC_KEY env var or logging.hmac_key config (>= %d random chars), or set %s=1 "+
			"to override for LOCAL DEV ONLY",
		hmacReason, minJWTSecretLen, InsecureSecretsAllowedEnv)
}

// jwtSecretWeakness returns a human-readable reason the secret is unacceptable,
// or "" if it is acceptable.
func jwtSecretWeakness(secret string) string {
	if strings.TrimSpace(secret) == "" {
		return "empty"
	}
	if _, ok := knownWeakJWTSecrets[strings.ToLower(secret)]; ok {
		return "a known dev/placeholder value"
	}
	low := strings.ToLower(secret)
	for _, marker := range weakJWTSecretMarkers {
		if strings.Contains(low, marker) {
			return "an un-replaced placeholder value"
		}
	}
	if len(secret) < minJWTSecretLen {
		return fmt.Sprintf("too short (< %d chars)", minJWTSecretLen)
	}
	return ""
}

func isTruthyEnv(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "1", "true", "yes", "on":
		return true
	}
	return false
}
