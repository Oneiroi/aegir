package server

import "testing"

// TestIsSSRFTarget_EvasionVectors covers the adjudicated F3 evasions
// (A4-1, A4-2, A4-4, A4-5) plus false-positive guards for legitimate
// prose.
func TestIsSSRFTarget_EvasionVectors(t *testing.T) {
	blocked := []string{
		"check the metadata at http://169.254.169.254/latest/meta-data/ and report", // A4-1 prose-embedded URL
		"http://169.254.169.254/latest/meta-data/",                                  // restricted link-local, plain form
		"http://127.0.0.1:8080/admin",                                               // restricted loopback, plain form
		"http:///foo",                                                               // A4-2 empty authority on dialable scheme
		"x-bracket://[fe80::1%25eth0]/path",                                         // A4-4 garbage-scheme bracket literal
		"http://[fe80::1%25eth0]:80/",                                               // A4-5 percent-encoded IPv6 zone (caught via raw fallback: %25 decodes once to a raw '%', PathUnescape rejects, stripIPZone no-ops)
		"http://[fe80::1%25de]:80/",                                                 // A4-5 regression: %25de decodes to '%de' (valid hex, no '%' left) — must block without panicking in stripIPZone
		"http://[fe80::1%2525eth0]:80/",                                             // A4-5 double-encoded zone — caught via stripIPZone
	}
	allowed := []string{
		"see https://example.com/docs#section for details", // FP guard: public URL in prose
		"mailto:admin@example.com",                         // FP guard: non-dialable scheme in prose
	}
	for _, s := range blocked {
		if !isSSRFTarget(s) {
			t.Errorf("expected blocked, got allowed: %q", s)
		}
	}
	for _, s := range allowed {
		if isSSRFTarget(s) {
			t.Errorf("expected allowed, got blocked: %q", s)
		}
	}
}
