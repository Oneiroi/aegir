package session

import (
	"testing"
	"time"
)

// fragmentTestSession builds a SessionContext whose history carries the
// given per-message scores (newest last — the last entry is the current
// message, which the fragment term excludes by design).
func fragmentTestSession(scores ...float64) *SessionContext {
	hist := make([]MessageContext, 0, len(scores))
	now := time.Now()
	for i, sc := range scores {
		hist = append(hist, MessageContext{
			Timestamp:   now.Add(-time.Duration(i) * time.Second),
			Content:     "m",
			ThreatScore: sc,
		})
	}
	return &SessionContext{History: hist}
}

// TestFragmentAccumulation verifies the F4(e) fragment term (bundle 3):
// sub-threshold fragments from >=2 distinct in-window messages accumulate
// (bounded by fragmentCap), a single fragment does not, and expired
// fragments stop accumulating (self-heal).
func TestFragmentAccumulation(t *testing.T) {
	// Two sub-threshold fragments from earlier turns accumulate below the
	// cap: 0.1+0.1 = 0.2.
	if got := fragmentAccumulation(fragmentTestSession(0.1, 0.1, 0.0)); got != 0.2 {
		t.Errorf("two 0.1 fragments: got %v, want 0.2", got)
	}

	// The accumulated term pushes a 0.4 base score across the 0.5 high
	// band (determineRecommendedAction: >= 0.5 => "high").
	logger := createTestLogger()
	analyzer := NewConversationalThreatAnalyzer(AnalyzerConfig{}, logger)
	assessment := &ThreatAssessment{CurrentThreatScore: 0.4}
	assessment.CurrentThreatScore += fragmentAccumulation(fragmentTestSession(0.1, 0.1, 0.0))
	analyzer.determineRecommendedAction(assessment)
	if assessment.ConversationRisk != "high" {
		t.Errorf("fragments over a 0.4 base should reach the high band, got %q (score %.2f)",
			assessment.ConversationRisk, assessment.CurrentThreatScore)
	}

	// A single fragment (even with a benign current message) never
	// accumulates: the term requires >=2 fragment messages.
	if got := fragmentAccumulation(fragmentTestSession(0.3, 0.0)); got != 0 {
		t.Errorf("single fragment must not accumulate: got %v", got)
	}

	// The contribution is capped at fragmentCap (0.3).
	if got := fragmentAccumulation(fragmentTestSession(0.5, 0.5, 0.5, 0.0)); got != fragmentCap {
		t.Errorf("fragment term must be capped at %v, got %v", fragmentCap, got)
	}

	// Window expiry: fragments older than fragmentWindow stop accumulating,
	// preserving the observed self-heal.
	hist := []MessageContext{
		{Timestamp: time.Now().Add(-10 * time.Minute), ThreatScore: 0.5},
		{Timestamp: time.Now().Add(-10 * time.Minute), ThreatScore: 0.5},
		{Timestamp: time.Now(), ThreatScore: 0.0},
	}
	if got := fragmentAccumulation(&SessionContext{History: hist}); got != 0 {
		t.Errorf("expired fragments must not accumulate: got %v", got)
	}
}
