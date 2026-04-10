// Package sampler — flowtable.go aggregates PacketSamples by 5-tuple per tick.
//
// Each tick (1 second), the table is drained (top-N returned) and reset.
// The flow table is thread-safe and supports a max entry limit with LRU eviction.
//
package sampler

import (
	"net"
	"sort"
	"sync"
)

const (
	// maxFlowEntries is the maximum number of flow entries in the table.
	// Beyond this, the smallest (least packets) entry is evicted.
	maxFlowEntries = 10_000
)

// FlowKey is the 5-tuple key for flow aggregation.
// IPs are stored as [16]byte to support both IPv4 and IPv6.
type FlowKey struct {
	SrcIP    [16]byte
	DstIP    [16]byte
	SrcPort  uint16
	DstPort  uint16
	Protocol uint8
}

// FlowStats holds per-flow aggregated counters for the current tick.
type FlowStats struct {
	Packets  uint64
	Bytes    uint64
	TCPFlags uint8 // cumulative OR of all TCP flags seen
}

// FlowEntry combines a FlowKey with its aggregated stats (for export).
type FlowEntry struct {
	Key   FlowKey
	Stats FlowStats
}

// FlowTable aggregates PacketSamples by 5-tuple within a single tick.
type FlowTable struct {
	mu    sync.Mutex
	flows map[FlowKey]*FlowStats
}

// NewFlowTable creates an empty FlowTable.
func NewFlowTable() *FlowTable {
	return &FlowTable{
		flows: make(map[FlowKey]*FlowStats),
	}
}

// Add records a packet sample into the flow table.
func (ft *FlowTable) Add(ps PacketSample) {
	if ps.SrcIP == nil && ps.DstIP == nil {
		return
	}

	key := FlowKey{
		SrcPort:  uint16(ps.SrcPort),
		DstPort:  uint16(ps.DstPort),
		Protocol: uint8(ps.Protocol),
	}
	copyIPTo16(ps.SrcIP, &key.SrcIP)
	copyIPTo16(ps.DstIP, &key.DstIP)

	ft.mu.Lock()
	defer ft.mu.Unlock()

	stats, exists := ft.flows[key]
	if !exists {
		// Evict smallest entry if at capacity
		if len(ft.flows) >= maxFlowEntries {
			ft.evictSmallest()
		}
		stats = &FlowStats{}
		ft.flows[key] = stats
	}

	stats.Packets++
	stats.Bytes += uint64(ps.PacketLength)
	stats.TCPFlags |= uint8(ps.TCPFlags)
}

// DrainTopN returns the top-N flows by packet count (descending),
// then resets the table. Thread-safe.
func (ft *FlowTable) DrainTopN(n int) []FlowEntry {
	ft.mu.Lock()
	defer ft.mu.Unlock()

	if len(ft.flows) == 0 {
		return nil
	}

	entries := make([]FlowEntry, 0, len(ft.flows))
	for k, v := range ft.flows {
		entries = append(entries, FlowEntry{Key: k, Stats: *v})
	}

	// Sort by packets descending
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].Stats.Packets > entries[j].Stats.Packets
	})

	// Truncate to top-N
	if len(entries) > n {
		entries = entries[:n]
	}

	// Reset the table
	ft.flows = make(map[FlowKey]*FlowStats)

	return entries
}

// evictSmallest removes the entry with the fewest packets. Caller must hold mu.
func (ft *FlowTable) evictSmallest() {
	var minKey FlowKey
	var minPkts uint64 = ^uint64(0) // max uint64
	for k, v := range ft.flows {
		if v.Packets < minPkts {
			minPkts = v.Packets
			minKey = k
		}
	}
	delete(ft.flows, minKey)
}

// copyIPTo16 copies a net.IP into a [16]byte array.
// IPv4 addresses are stored in the first 4 bytes (NOT mapped to v6).
func copyIPTo16(ip net.IP, dst *[16]byte) {
	if ip == nil {
		return
	}
	if ip4 := ip.To4(); ip4 != nil {
		copy(dst[:4], ip4)
	} else {
		copy(dst[:], ip)
	}
}
