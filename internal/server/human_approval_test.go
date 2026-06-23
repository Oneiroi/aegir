package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/aegishjalmur/aegir/internal/config"
)

// TestHumanApprovalGate is the ISC-119 probe: tools/call for a destructive
// operation is blocked unless the configured webhook responds with approved=true.
func TestHumanApprovalGate(t *testing.T) {
	t.Run("approved_by_webhook", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]bool{"approved": true})
		}))
		defer srv.Close()

		proxy := &MCPProxy{
			config: &config.Config{
				Security: config.Security{
					HumanApproval: config.HumanApprovalConfig{
						Enabled:    true,
						Patterns:   []string{"delete_", "drop_"},
						WebhookURL: srv.URL,
						Timeout:    5 * time.Second,
					},
				},
			},
			logger: testLogger(),
		}

		err := proxy.requestHumanApproval("delete_table", map[string]interface{}{"table": "users"}, proxy.config.Security.HumanApproval)
		if err != nil {
			t.Errorf("expected approval, got error: %v", err)
		}
	})

	t.Run("rejected_by_webhook", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]bool{"approved": false})
		}))
		defer srv.Close()

		proxy := &MCPProxy{
			config: &config.Config{
				Security: config.Security{
					HumanApproval: config.HumanApprovalConfig{
						Enabled:    true,
						Patterns:   []string{"delete_"},
						WebhookURL: srv.URL,
						Timeout:    5 * time.Second,
					},
				},
			},
			logger: testLogger(),
		}

		err := proxy.requestHumanApproval("delete_file", nil, proxy.config.Security.HumanApproval)
		if err == nil {
			t.Error("expected rejection error, got nil")
		}
	})

	t.Run("webhook_timeout_blocks", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			time.Sleep(200 * time.Millisecond) // longer than timeout below
		}))
		defer srv.Close()

		proxy := &MCPProxy{
			config: &config.Config{
				Security: config.Security{
					HumanApproval: config.HumanApprovalConfig{
						Enabled:    true,
						Patterns:   []string{"purge_"},
						WebhookURL: srv.URL,
						Timeout:    50 * time.Millisecond, // very short for test speed
					},
				},
			},
			logger: testLogger(),
		}

		err := proxy.requestHumanApproval("purge_logs", nil, proxy.config.Security.HumanApproval)
		if err == nil {
			t.Error("expected timeout error, got nil")
		}
	})

	t.Run("no_webhook_url_blocks", func(t *testing.T) {
		proxy := &MCPProxy{
			config: &config.Config{
				Security: config.Security{
					HumanApproval: config.HumanApprovalConfig{
						Enabled:    true,
						Patterns:   []string{"drop_"},
						WebhookURL: "",
						Timeout:    5 * time.Second,
					},
				},
			},
			logger: testLogger(),
		}

		err := proxy.requestHumanApproval("drop_table", nil, proxy.config.Security.HumanApproval)
		if err == nil {
			t.Error("expected error for missing webhook_url, got nil")
		}
	})
}

// TestIsDestructiveTool verifies the pattern-matching helper.
func TestIsDestructiveTool(t *testing.T) {
	patterns := []string{"delete_", "drop_", "purge_", "format_", "overwrite_"}
	cases := []struct {
		name string
		want bool
	}{
		{"delete_file", true},
		{"DROP_TABLE", true}, // case-insensitive
		{"purge_logs", true},
		{"format_disk", true},
		{"overwrite_config", true},
		{"list_files", false},
		{"read_data", false},
		{"", false},
	}
	for _, tc := range cases {
		got := isDestructiveTool(tc.name, patterns)
		if got != tc.want {
			t.Errorf("isDestructiveTool(%q) = %v, want %v", tc.name, got, tc.want)
		}
	}
}
