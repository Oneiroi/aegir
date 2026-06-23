package config

import (
	"testing"
)

// TestAnomalyProfiles_ISC20 is the ISC-20 probe: aegir.yaml accepts
// anomaly_detection.profiles map with per-context block/log thresholds.
func TestAnomalyProfiles_ISC20(t *testing.T) {
	blockThresh := 0.80
	logThresh := 0.40

	cfg := AnomalyDetection{
		Enabled:        true,
		BlockThreshold: 0.95,
		LogThreshold:   0.60,
		Profiles: map[string]AnomalyProfile{
			"finance": {
				BlockThreshold: &blockThresh,
				LogThreshold:   &logThresh,
			},
			"assistant": {
				BlockThreshold: nil, // inherits global default
			},
		},
	}

	fp, ok := cfg.Profiles["finance"]
	if !ok {
		t.Fatal("finance profile not found")
	}
	if fp.BlockThreshold == nil || *fp.BlockThreshold != 0.80 {
		t.Errorf("finance block_threshold: got %v, want 0.80", fp.BlockThreshold)
	}
	if fp.LogThreshold == nil || *fp.LogThreshold != 0.40 {
		t.Errorf("finance log_threshold: got %v, want 0.40", fp.LogThreshold)
	}

	ap, ok := cfg.Profiles["assistant"]
	if !ok {
		t.Fatal("assistant profile not found")
	}
	if ap.BlockThreshold != nil {
		t.Errorf("assistant block_threshold should be nil (inherits global), got %v", *ap.BlockThreshold)
	}
}

// TestAnomalyProfiles_ISC21 is the ISC-21 probe: different upstream configs
// accept different entropy thresholds via the profile map.
func TestAnomalyProfiles_ISC21(t *testing.T) {
	highEntropy := 7.5
	lowEntropy := 4.0

	cfg := AnomalyDetection{
		Enabled: true,
		Profiles: map[string]AnomalyProfile{
			"high-entropy-upstream": {
				EntropyThreshold: &highEntropy,
			},
			"low-entropy-upstream": {
				EntropyThreshold: &lowEntropy,
			},
		},
	}

	hp := cfg.Profiles["high-entropy-upstream"]
	if hp.EntropyThreshold == nil || *hp.EntropyThreshold != 7.5 {
		t.Errorf("high-entropy-upstream threshold: got %v, want 7.5", hp.EntropyThreshold)
	}

	lp := cfg.Profiles["low-entropy-upstream"]
	if lp.EntropyThreshold == nil || *lp.EntropyThreshold != 4.0 {
		t.Errorf("low-entropy-upstream threshold: got %v, want 4.0", lp.EntropyThreshold)
	}
}
