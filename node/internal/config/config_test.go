package config

import (
	"os"
	"path/filepath"
	"testing"
)

func writeTestConfig(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestConfigFlowModeNoInterfaces(t *testing.T) {
	path := writeTestConfig(t, `
mode: flow
node_id: "test-flow"
controller:
  address: "localhost:50051"
auth:
  node_api_key: "test-key"
`)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("flow mode should not require interfaces: %v", err)
	}
	if !cfg.IsFlowMode() {
		t.Error("expected IsFlowMode() = true")
	}
}

func TestConfigXDPModeRequiresInterfaces(t *testing.T) {
	path := writeTestConfig(t, `
node_id: "test-xdp"
controller:
  address: "localhost:50051"
auth:
  node_api_key: "test-key"
`)
	_, err := Load(path)
	if err == nil {
		t.Error("xdp mode without interfaces should fail validation")
	}
}

func TestConfigDefaultModeIsXDP(t *testing.T) {
	path := writeTestConfig(t, `
node_id: "test"
interfaces:
  - name: "eth0"
    mode: "mirror"
    sample_bytes: 128
controller:
  address: "localhost:50051"
auth:
  node_api_key: "test-key"
`)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Mode != "xdp" {
		t.Errorf("expected default mode=xdp, got %q", cfg.Mode)
	}
	if cfg.IsFlowMode() {
		t.Error("expected IsFlowMode() = false for default mode")
	}
}

func TestConfigInvalidModeRejected(t *testing.T) {
	path := writeTestConfig(t, `
mode: invalid
node_id: "test"
controller:
  address: "localhost:50051"
auth:
  node_api_key: "test-key"
`)
	_, err := Load(path)
	if err == nil {
		t.Error("invalid mode should fail validation")
	}
}
