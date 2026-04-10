package config

import (
	"os"
	"path/filepath"
	"testing"
)

// writeConfig writes a YAML config to a temp file and returns its path.
func writeConfig(t *testing.T, yaml string) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(p, []byte(yaml), 0644); err != nil {
		t.Fatal(err)
	}
	return p
}

const baseYAML = `
database:
  driver: postgres
  dsn: "postgres://localhost/xsight_test"
auth:
  api_key: "test-key-123"
`

func TestLoadDefaultConfig(t *testing.T) {
	cfg, err := Load(writeConfig(t, baseYAML))
	if err != nil {
		t.Fatalf("expected valid config, got error: %v", err)
	}
	if cfg.Ring.MaxPointsPerIP != 120 {
		t.Errorf("MaxPointsPerIP = %d, want 120", cfg.Ring.MaxPointsPerIP)
	}
	if cfg.Ring.MaxIPsPerPrefix != 10_000 {
		t.Errorf("MaxIPsPerPrefix = %d, want 10000", cfg.Ring.MaxIPsPerPrefix)
	}
	if cfg.Ring.MaxGlobalKeys != 100_000 {
		t.Errorf("MaxGlobalKeys = %d, want 100000", cfg.Ring.MaxGlobalKeys)
	}
}

func TestRingMaxPointsPerIPTooLow(t *testing.T) {
	yaml := baseYAML + `
ring:
  max_points_per_ip: 5
  max_ips_per_prefix: 1000
  max_global_keys: 10000
`
	_, err := Load(writeConfig(t, yaml))
	if err == nil {
		t.Fatal("expected error for max_points_per_ip < 10")
	}
}

func TestRingMaxPointsPerIPTooHigh(t *testing.T) {
	yaml := baseYAML + `
ring:
  max_points_per_ip: 601
  max_ips_per_prefix: 1000
  max_global_keys: 10000
`
	_, err := Load(writeConfig(t, yaml))
	if err == nil {
		t.Fatal("expected error for max_points_per_ip > 600")
	}
}

func TestRingMaxIPsPerPrefixTooHigh(t *testing.T) {
	yaml := baseYAML + `
ring:
  max_points_per_ip: 120
  max_ips_per_prefix: 50001
  max_global_keys: 10000
`
	_, err := Load(writeConfig(t, yaml))
	if err == nil {
		t.Fatal("expected error for max_ips_per_prefix > 50000")
	}
}

func TestRingMaxGlobalKeysTooHigh(t *testing.T) {
	yaml := baseYAML + `
ring:
  max_points_per_ip: 120
  max_ips_per_prefix: 1000
  max_global_keys: 500001
`
	_, err := Load(writeConfig(t, yaml))
	if err == nil {
		t.Fatal("expected error for max_global_keys > 500000")
	}
}

func TestRingEstimatedMemoryExceeds8GB(t *testing.T) {
	// 500000 * 600 * 80 / 1024 / 1024 = ~22888 MB > 8192 MB
	yaml := baseYAML + `
ring:
  max_points_per_ip: 600
  max_ips_per_prefix: 50000
  max_global_keys: 500000
`
	_, err := Load(writeConfig(t, yaml))
	if err == nil {
		t.Fatal("expected error for estimated memory > 8GB")
	}
}

func TestRingAllPositiveWithinBounds(t *testing.T) {
	yaml := baseYAML + `
ring:
  max_points_per_ip: 60
  max_ips_per_prefix: 5000
  max_global_keys: 50000
`
	_, err := Load(writeConfig(t, yaml))
	if err != nil {
		t.Fatalf("expected valid config, got error: %v", err)
	}
}

func TestRingEdgeCaseExactMinPointsPerIP(t *testing.T) {
	yaml := baseYAML + `
ring:
  max_points_per_ip: 10
  max_ips_per_prefix: 100
  max_global_keys: 1000
`
	_, err := Load(writeConfig(t, yaml))
	if err != nil {
		t.Fatalf("max_points_per_ip=10 should pass, got: %v", err)
	}
}

func TestRingEdgeCaseExactMaxPointsPerIP(t *testing.T) {
	yaml := baseYAML + `
ring:
  max_points_per_ip: 600
  max_ips_per_prefix: 100
  max_global_keys: 1000
`
	// 1000 * 600 * 80 / 1024 / 1024 = ~45 MB — well within 8GB
	_, err := Load(writeConfig(t, yaml))
	if err != nil {
		t.Fatalf("max_points_per_ip=600 with small keys should pass, got: %v", err)
	}
}

func TestRingEdgeCaseExactMaxIPsPerPrefix(t *testing.T) {
	yaml := baseYAML + `
ring:
  max_points_per_ip: 10
  max_ips_per_prefix: 50000
  max_global_keys: 50000
`
	_, err := Load(writeConfig(t, yaml))
	if err != nil {
		t.Fatalf("max_ips_per_prefix=50000 should pass, got: %v", err)
	}
}

func TestRingEdgeCaseExactMaxGlobalKeys(t *testing.T) {
	yaml := baseYAML + `
ring:
  max_points_per_ip: 10
  max_ips_per_prefix: 1000
  max_global_keys: 500000
`
	// 500000 * 10 * 80 / 1024 / 1024 = ~381 MB — under 8GB
	_, err := Load(writeConfig(t, yaml))
	if err != nil {
		t.Fatalf("max_global_keys=500000 with small points should pass, got: %v", err)
	}
}
