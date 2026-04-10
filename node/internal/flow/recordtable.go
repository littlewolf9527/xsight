package flow

import (
	"net"
	"sort"
	"sync"
)

// FlowKey is the 5-tuple key for flow aggregation.
// Uses [16]byte for IPs to avoid string allocation on the hot path.
type FlowKey struct {
	SrcIP    [16]byte
	DstIP    [16]byte
	SrcPort  uint16
	DstPort  uint16
	Protocol uint8
}

// FlowEntry holds aggregated counters for a single flow.
type FlowEntry struct {
	Key      FlowKey
	Packets  uint64
	Bytes    uint64
	TCPFlags uint8
}

// FlowRecordTable aggregates flow records by 5-tuple.
// Unlike sampler.FlowTable (one-call = one-packet), this table accepts
// pre-aggregated packets/bytes from flow records.
// When full, evicts the entry with the fewest packets (volume-biased eviction,
// keeping high-volume flows for top-N accuracy).
type FlowRecordTable struct {
	mu         sync.Mutex
	entries    map[FlowKey]*FlowEntry
	maxEntries int
}

// NewFlowRecordTable creates a table with the given max capacity.
func NewFlowRecordTable(maxEntries int) *FlowRecordTable {
	if maxEntries <= 0 {
		maxEntries = 10000
	}
	return &FlowRecordTable{
		entries:    make(map[FlowKey]*FlowEntry, maxEntries),
		maxEntries: maxEntries,
	}
}

// Add accumulates packets/bytes for a 5-tuple flow.
// ipTo16 converts net.IP to a fixed [16]byte (zero-alloc key).
func ipTo16(ip net.IP) [16]byte {
	var b [16]byte
	if ip4 := ip.To4(); ip4 != nil {
		copy(b[12:], ip4)
	} else if len(ip) == 16 {
		copy(b[:], ip)
	}
	return b
}

func (t *FlowRecordTable) Add(srcIP, dstIP net.IP, srcPort, dstPort uint16,
	protocol uint8, tcpFlags uint8, packets, bytes uint64) {

	key := FlowKey{
		SrcIP:    ipTo16(srcIP),
		DstIP:    ipTo16(dstIP),
		SrcPort:  srcPort,
		DstPort:  dstPort,
		Protocol: protocol,
	}

	t.mu.Lock()
	defer t.mu.Unlock()

	entry, ok := t.entries[key]
	if !ok {
		if len(t.entries) >= t.maxEntries {
			t.evictSmallest()
		}
		entry = &FlowEntry{Key: key}
		t.entries[key] = entry
	}
	entry.Packets += packets
	entry.Bytes += bytes
	entry.TCPFlags |= tcpFlags
}

// DrainTop returns the top-N entries by packets (descending) and resets the table.
func (t *FlowRecordTable) DrainTop(n int) []FlowEntry {
	t.mu.Lock()
	defer t.mu.Unlock()

	if len(t.entries) == 0 {
		return nil
	}

	all := make([]FlowEntry, 0, len(t.entries))
	for _, e := range t.entries {
		all = append(all, *e)
	}
	sort.Slice(all, func(i, j int) bool {
		return all[i].Packets > all[j].Packets
	})

	if n > len(all) {
		n = len(all)
	}

	// Reset
	t.entries = make(map[FlowKey]*FlowEntry, t.maxEntries)

	return all[:n]
}

// evictSmallest removes the entry with the fewest packets (volume-biased eviction).
func (t *FlowRecordTable) evictSmallest() {
	var minKey FlowKey
	var minPkts uint64 = ^uint64(0)
	for k, e := range t.entries {
		if e.Packets < minPkts {
			minPkts = e.Packets
			minKey = k
		}
	}
	delete(t.entries, minKey)
}

// Len returns current entry count.
func (t *FlowRecordTable) Len() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.entries)
}
