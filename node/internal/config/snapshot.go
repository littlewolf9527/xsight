// Package config — snapshot.go manages the local config snapshot
// that persists the last valid Controller-delivered configuration.
//
// Path: /var/lib/xsight/<node_id>/last_config.json
//
package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// SnapshotPrefix is a single watched prefix from the Controller.
type SnapshotPrefix struct {
	Prefix string `json:"prefix"` // CIDR notation, e.g. "10.2.0.0/24"
	Name   string `json:"name"`
}

// SnapshotThresholds stores per-IP hard thresholds.
type SnapshotThresholds struct {
	PPS uint64 `json:"pps"`
	BPS uint64 `json:"bps"`
}

// SnapshotFlowListener is a persisted flow listener config (v3.0).
type SnapshotFlowListener struct {
	ListenAddress string               `json:"listen_address"`
	ProtocolMode  string               `json:"protocol_mode"`
	Sources       []SnapshotFlowSource `json:"sources"`
}

// SnapshotFlowSource is a persisted flow source config (v3.0).
type SnapshotFlowSource struct {
	DeviceIP   string `json:"device_ip"`
	SampleMode string `json:"sample_mode"`
	SampleRate int    `json:"sample_rate"`
	Name       string `json:"name"`
}

// Snapshot is the persisted Controller config.
type Snapshot struct {
	WatchPrefixes          []SnapshotPrefix        `json:"watch_prefixes"`
	HardThresholds         SnapshotThresholds      `json:"hard_thresholds"`
	FlowListeners          []SnapshotFlowListener  `json:"flow_listeners,omitempty"` // v3.0
	DeliveryVersionApplied uint64                  `json:"delivery_version_applied"`
	Timestamp              time.Time               `json:"timestamp"`
}

// SnapshotPath returns the snapshot file path for a given node_id.
func SnapshotPath(nodeID string) string {
	return filepath.Join("/var/lib/xsight", nodeID, "last_config.json")
}

// SaveSnapshot writes the snapshot to disk, creating directories as needed.
func SaveSnapshot(nodeID string, snap *Snapshot) error {
	path := SnapshotPath(nodeID)
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("create snapshot dir: %w", err)
	}

	snap.Timestamp = time.Now()
	data, err := json.MarshalIndent(snap, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal snapshot: %w", err)
	}

	// Write atomically via temp file + rename
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0644); err != nil {
		return fmt.Errorf("write snapshot: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("rename snapshot: %w", err)
	}
	return nil
}

// LoadSnapshot reads the snapshot from disk. Returns nil if not found.
func LoadSnapshot(nodeID string) (*Snapshot, error) {
	path := SnapshotPath(nodeID)
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil // no snapshot yet
		}
		return nil, fmt.Errorf("read snapshot: %w", err)
	}

	var snap Snapshot
	if err := json.Unmarshal(data, &snap); err != nil {
		return nil, fmt.Errorf("unmarshal snapshot: %w", err)
	}
	return &snap, nil
}
