package server

import (
	"fmt"
	"testing"

	"github.com/aegishjalmur/aegir/internal/config"
	"github.com/aegishjalmur/aegir/internal/judge"
)

// TestBuildJudgeConfig is the runtime-reachability probe for M013 (ISC-138,
// ISC-141): the server must construct the judge through the provider factory
// carrying judge.provider and the failover chain, not via NewOllamaJudge with
// those fields dropped. It asserts every field — including each fallback —
// propagates from config.JudgeConfig into judge.Config.
func TestBuildJudgeConfig(t *testing.T) {
	jc := config.JudgeConfig{
		BaseURL:   "https://api.anthropic.com",
		Model:     "claude-haiku-4-5",
		APIKey:    "primary-key",
		TimeoutMs: 1500,
		Provider:  "anthropic",
		Fallbacks: []config.JudgeFallback{
			{BaseURL: "http://localhost:11434", Model: "llama3", Provider: "ollama"},
			{BaseURL: "http://localhost:1234", Model: "gemma", APIKey: "fb-key", Provider: "openai"},
		},
	}

	got := buildJudgeConfig(jc)

	if got.BaseURL != jc.BaseURL || got.Model != jc.Model ||
		got.APIKey != jc.APIKey || got.TimeoutMs != jc.TimeoutMs ||
		got.Provider != jc.Provider {
		t.Fatalf("scalar fields not propagated: got %+v", got)
	}
	if len(got.Fallbacks) != len(jc.Fallbacks) {
		t.Fatalf("fallback count: got %d want %d", len(got.Fallbacks), len(jc.Fallbacks))
	}
	for i, fb := range jc.Fallbacks {
		g := got.Fallbacks[i]
		if g.BaseURL != fb.BaseURL || g.Model != fb.Model ||
			g.APIKey != fb.APIKey || g.Provider != fb.Provider {
			t.Errorf("fallback[%d] mismatch: got %+v want %+v", i, g, fb)
		}
	}
}

// TestBuildJudgeConfig_ProviderReachesFactory proves the translated config,
// fed through judge.NewJudge as the server does, selects the provider-specific
// adapter — i.e. judge.provider: anthropic is genuinely reachable at runtime.
func TestBuildJudgeConfig_ProviderReachesFactory(t *testing.T) {
	cases := map[string]string{
		"anthropic": "*judge.AnthropicJudge",
		"openai":    "*judge.OpenAICompatJudge",
		"ollama":    "*judge.OpenAICompatJudge",
		"":          "*judge.OpenAICompatJudge",
	}
	for provider, wantType := range cases {
		cfg := buildJudgeConfig(config.JudgeConfig{Provider: provider})
		j := judge.NewJudge(cfg, nil, nil)
		if got := fmt.Sprintf("%T", j); got != wantType {
			t.Errorf("provider %q: got %s want %s", provider, got, wantType)
		}
	}
}
