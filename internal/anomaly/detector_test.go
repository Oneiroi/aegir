package anomaly

import (
	"strings"
	"testing"
)

func TestHeuristicDetector_Benign(t *testing.T) {
	d := NewHeuristicDetector()

	benign := []string{
		"What is the weather in London today?",
		"List all files in the current directory.",
		`{"method": "tools/list", "params": {}, "id": 1}`,
		"Hello, how can I help you?",
	}

	for _, content := range benign {
		score := d.Score(content)
		if score > 0.2 {
			t.Errorf("Benign content %q scored %.3f, want ≤0.2", content, score)
		}
	}
}

func TestHeuristicDetector_Anomalous_HighEntropy(t *testing.T) {
	d := NewHeuristicDetector()

	// All 95 printable ASCII chars repeated — entropy ≈ log2(95) ≈ 6.57 bits,
	// well above the 4.5-bit baseline, so entropyScore should be ≥ 1.0.
	chars := " !\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~"
	highEntropy := strings.Repeat(chars, 20)
	score := d.Score(highEntropy)
	if score < 0.7 {
		t.Errorf("High-entropy content scored %.3f, want ≥0.7", score)
	}
}

func TestHeuristicDetector_Anomalous_NonASCII(t *testing.T) {
	d := NewHeuristicDetector()

	// String with >80% non-ASCII runes
	nonASCII := strings.Repeat("ñöüäßæø", 100) // all non-ASCII
	score := d.Score(nonASCII)
	if score < 0.7 {
		t.Errorf("High non-ASCII content scored %.3f, want ≥0.7", score)
	}
}

func TestHeuristicDetector_Empty(t *testing.T) {
	d := NewHeuristicDetector()
	if score := d.Score(""); score != 0.0 {
		t.Errorf("Empty content scored %.3f, want 0.0", score)
	}
}

func TestHeuristicDetector_ScoreRange(t *testing.T) {
	d := NewHeuristicDetector()
	for _, s := range []string{"hello", strings.Repeat("x", 10000), "\x00\x01\x02\xff"} {
		score := d.Score(s)
		if score < 0 || score > 1 {
			t.Errorf("Score %.3f out of [0,1] range for input len=%d", score, len(s))
		}
	}
}
