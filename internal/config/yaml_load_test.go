package config

import (
	"os"
	"path/filepath"
	"testing"
)

// TestYAMLConfigLoad is the ISC-88 probe: aegir.yaml is accepted as a config
// file and its values are loaded correctly. Writes a minimal valid aegir.yaml
// to a temp file, loads it via LoadWithConfigFile, and verifies key fields.
func TestYAMLConfigLoad(t *testing.T) {
	yamlContent := `
server:
  port: 9443
  host: "127.0.0.1"
security:
  jwt_secret: "test-secret-min-32-chars-long!!"
  detection:
    enabled: true
    response_policy: "log-only"
logging:
  level: "debug"
`
	dir := t.TempDir()
	path := filepath.Join(dir, "aegir.yaml")
	if err := os.WriteFile(path, []byte(yamlContent), 0o600); err != nil {
		t.Fatalf("write aegir.yaml: %v", err)
	}

	cfg, err := LoadWithConfigFile(path)
	if err != nil {
		t.Fatalf("ISC-88: LoadWithConfigFile(%q): %v", path, err)
	}

	if cfg.Server.Port != 9443 {
		t.Errorf("ISC-88: server.port = %d, want 9443", cfg.Server.Port)
	}
	if cfg.Server.Host != "127.0.0.1" {
		t.Errorf("ISC-88: server.host = %q, want 127.0.0.1", cfg.Server.Host)
	}
	if !cfg.Security.Detection.Enabled {
		t.Error("ISC-88: security.detection.enabled should be true from YAML")
	}
	if cfg.Security.Detection.ResponsePolicy != "log-only" {
		t.Errorf("ISC-88: detection.response_policy = %q, want log-only", cfg.Security.Detection.ResponsePolicy)
	}
	if cfg.Logging.Level != "debug" {
		t.Errorf("ISC-88: logging.level = %q, want debug", cfg.Logging.Level)
	}
}
