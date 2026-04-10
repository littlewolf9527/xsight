// Package flow implements the Flow Node data pipeline:
// UDP listener → goflow2 decoder → FlowAggregator → *pb.StatsReport → gRPC reporter.
package flow

import (
	"net"
	"time"
)

// FlowRecord is the unified intermediate format extracted from goflow2 decoders.
// All protocol-specific time representations are normalized to UTC absolute time
// by the decoder layer before reaching the aggregator.
type FlowRecord struct {
	SrcIP    net.IP
	DstIP    net.IP
	SrcPort  uint16
	DstPort  uint16
	Protocol uint8  // 6=TCP, 17=UDP, 1=ICMP
	TCPFlags uint8

	Packets    uint64 // raw value (not yet multiplied by sample rate)
	Bytes      uint64
	SampleRate uint32 // from flow record (sFlow always present, NetFlow may be 0)

	// Time semantics (required for NetFlow/IPFIX, zero for sFlow)
	StartTime time.Time
	EndTime   time.Time
	Duration  int // seconds, computed from EndTime-StartTime or record field
}
