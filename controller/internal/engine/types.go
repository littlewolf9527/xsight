// Package engine implements the detection engine for xSight Controller.
package engine

import (
	"net"
	"time"
)

// DetectionVerdict is the structured output of the detection engine.
// Reference: brainstorm-controller.md "Detection Output Structure"
type DetectionVerdict struct {
	DstIP         net.IP
	Prefix        string   // owning prefix CIDR
	Direction     string   // "receives" | "sends"
	DecoderFamily string   // "tcp_syn" | "udp" | "icmp" | "ip" | "tcp" | "fragment"
	Severity      string   // "critical" | "high" | "medium" | "low"
	Confidence    float32
	AttackType    string   // "syn_flood" | "udp_flood" | "dns_reflection" | ...
	ReasonCodes   []string // ["udp_spike", "src_port_53_dominant"]
	PeakPPS       int64
	PeakBPS       int64
	CurrentPPS    int64
	CurrentBPS    int64
	NodeSources   []string
	StartTime     time.Time
}

// ThresholdExceeded is emitted when a threshold is breached for one tick.
// The AttackTracker accumulates these over confirm_seconds before creating an Attack.
type ThresholdExceeded struct {
	DstIP         net.IP
	Prefix        string
	PrefixID      int
	Direction     string
	Decoder       string // "tcp_syn" | "udp" | "icmp" | "ip" | "tcp" | "fragment"
	Unit          string // "pps" | "bps"
	ThresholdID   int
	ResponseID    *int
	Value         int64  // configured threshold
	Actual        int64  // observed value
	Domain        string // "internal_ip" | "subnet"
	NodeID        string
	Source        string // "hard" | "dynamic" — determines confirm seconds
}

// ResolvedThreshold is a threshold rule after inheritance resolution.
// Stored in the flat map: prefix → []ResolvedThreshold.
type ResolvedThreshold struct {
	ThresholdID int
	PrefixID    int
	Prefix      string
	Domain      string // "internal_ip" | "subnet"
	Direction   string
	Decoder     string
	Unit        string
	Comparison  string // "over" | "under"
	Value       int64
	ResponseID  *int
}

// ClassificationResult is produced by the attack classifier (src_port analysis).
type ClassificationResult struct {
	DstIP      net.IP
	AttackType string   // "dns_reflection" | "ntp_reflection" | "generic_udp_flood" | ...
	Confidence float32
	Reasons    []string
}
