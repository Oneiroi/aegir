package anomaly

import (
	"math"
	"unicode/utf8"
)

// Detector scores content for anomalous characteristics.
// Score returns a value in [0.0, 1.0]: 0 = normal, 1 = highly anomalous.
type Detector interface {
	Score(content string) float64
}

// HeuristicDetector uses statistical signals to flag anomalous content.
// It is safe for concurrent use.
//
// Scoring is based on two orthogonal signals:
//   - Shannon entropy anomaly: normal English/JSON sits at 3.5–4.5 bits/char;
//     score rises from 0 at 4.5 bits to 1.0 at 6.5 bits.
//   - Non-ASCII ratio: fraction of runes with codepoint > 127.
//
// Final score uses an "at least one signal fires" combination so that either
// strong signal alone is sufficient to produce a high overall score.
type HeuristicDetector struct{}

// NewHeuristicDetector returns a HeuristicDetector.
func NewHeuristicDetector() *HeuristicDetector {
	return &HeuristicDetector{}
}

// Score returns a normalised anomaly score for content.
func (d *HeuristicDetector) Score(content string) float64 {
	if len(content) == 0 {
		return 0.0
	}

	entropy := shannonEntropy(content) // bits per character
	nonASCII := nonASCIIRatio(content)

	// Entropy anomaly: score is 0 below 4.5 bits, rises linearly to 1.0 at 6.5 bits.
	// English prose and typical JSON cluster at 3.7–4.2 bits; 4.5 leaves headroom.
	const entropyBaseline = 4.5
	const entropyRange = 2.0
	entropyScore := math.Min(1.0, math.Max(0, entropy-entropyBaseline)/entropyRange)

	// "At least one signal" combination: P(A or B) = P(A) + (1-P(A)) * P(B)
	score := entropyScore + (1.0-entropyScore)*nonASCII
	return score
}

// shannonEntropy returns the Shannon entropy of s in bits per character.
func shannonEntropy(s string) float64 {
	freq := make(map[rune]float64)
	total := 0.0
	for _, r := range s {
		freq[r]++
		total++
	}
	var h float64
	for _, count := range freq {
		p := count / total
		h -= p * math.Log2(p)
	}
	return h
}

// nonASCIIRatio returns the fraction of runes with codepoint > 127.
func nonASCIIRatio(s string) float64 {
	total := utf8.RuneCountInString(s)
	if total == 0 {
		return 0
	}
	var count int
	for _, r := range s {
		if r > 127 {
			count++
		}
	}
	return float64(count) / float64(total)
}
