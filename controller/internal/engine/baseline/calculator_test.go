package baseline

import (
	"testing"
	"time"
)

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()
	if cfg.WindowDuration != 1*time.Hour {
		t.Errorf("WindowDuration = %v, want 1h", cfg.WindowDuration)
	}
	if cfg.MinDataPoints != 60 {
		t.Errorf("MinDataPoints = %d, want 60", cfg.MinDataPoints)
	}
	if cfg.Multiplier != 3.0 {
		t.Errorf("Multiplier = %f, want 3.0", cfg.Multiplier)
	}
}

func TestCalculatorGet_UnknownKey(t *testing.T) {
	calc := NewCalculator(nil, DefaultConfig())
	bl := calc.Get("unknown-node", "10.0.0.0/24")
	if bl != nil {
		t.Errorf("expected nil for unknown key, got %+v", bl)
	}
}

func TestCalculatorGet_StoredBaseline(t *testing.T) {
	calc := NewCalculator(nil, DefaultConfig())
	// Manually inject a baseline
	key := baselineKey("node-1", "10.0.0.0/24")
	calc.mu.Lock()
	calc.baselines[key] = &Baseline{
		P95PPS:     1000,
		P95BPS:     8000,
		ThreshPPS:  3000,
		ThreshBPS:  24000,
		DataPoints: 100,
		Active:     true,
		ComputedAt: time.Now(),
	}
	calc.mu.Unlock()

	bl := calc.Get("node-1", "10.0.0.0/24")
	if bl == nil {
		t.Fatal("expected stored baseline, got nil")
	}
	if bl.P95PPS != 1000 {
		t.Errorf("P95PPS = %d, want 1000", bl.P95PPS)
	}
	if bl.ThreshPPS != 3000 {
		t.Errorf("ThreshPPS = %d, want 3000", bl.ThreshPPS)
	}
	if !bl.Active {
		t.Error("expected Active=true")
	}
}
