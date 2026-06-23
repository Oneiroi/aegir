package config

import (
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
)

// TestNoHardcodedCredentials is the durable probe for ISC-95: no hardcoded
// credentials in any source file. It walks internal/ and cmd/ and fails on
// known default-credential literals or pre-populated password input fields
// (the regression fixed in internal/dashboard/web.go, which shipped
// value="admin123"). Detection-pattern definitions in the sanitizer are not
// credentials and do not match these checks.
func TestNoHardcodedCredentials(t *testing.T) {
	root := repoRoot(t)

	// Known default/example credential literals that must never ship in source.
	bannedLiterals := []string{
		"admin123", "password123", "passw0rd", "changeme123",
		"letmein", "root123", "secret123", "admin:admin",
	}
	// A password input that carries a non-empty hardcoded value (either attr order).
	prefilledPassword := regexp.MustCompile(
		`type="password"[^>]*value="[^"]+"|value="[^"]+"[^>]*type="password"`)

	for _, sub := range []string{"internal", "cmd"} {
		walkDir := filepath.Join(root, sub)
		err := filepath.Walk(walkDir, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			if info.IsDir() {
				return nil
			}
			ext := filepath.Ext(path)
			if ext != ".go" && ext != ".html" && ext != ".tmpl" {
				return nil
			}
			if strings.HasSuffix(path, "_test.go") {
				return nil // probes/fixtures legitimately contain example creds
			}
			data, readErr := os.ReadFile(path)
			if readErr != nil {
				return readErr
			}
			rel, _ := filepath.Rel(root, path)
			for i, line := range strings.Split(string(data), "\n") {
				low := strings.ToLower(line)
				for _, lit := range bannedLiterals {
					if strings.Contains(low, lit) {
						t.Errorf("%s:%d hardcoded credential literal %q", rel, i+1, lit)
					}
				}
				if prefilledPassword.MatchString(line) {
					t.Errorf("%s:%d password input ships a hardcoded value", rel, i+1)
				}
			}
			return nil
		})
		if err != nil {
			t.Fatalf("walk %s: %v", walkDir, err)
		}
	}
}

// repoRoot returns the module root by walking up from this test file until go.mod.
func repoRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot determine caller path")
	}
	dir := filepath.Dir(file)
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("go.mod not found above test file")
		}
		dir = parent
	}
}
