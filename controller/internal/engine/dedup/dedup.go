// Package dedup implements alert deduplication based on decoder containment.
//
// Decoder hierarchy:
//
//	ip ⊃ tcp ⊃ tcp_syn
//	ip ⊃ udp
//	ip ⊃ icmp
//	ip ⊃ fragment
//
// Rule: if a more specific decoder already has an active attack for the same
// (dst_ip, direction), suppress the broader decoder.
package dedup

import (
	"sync"

	"github.com/littlewolf9527/xsight/controller/internal/engine"
)

// suppressedBy maps each decoder to the set of more-specific decoders that suppress it.
// Pre-computed from the hierarchy for O(1) lookup during detection.
var suppressedBy = map[string][]string{
	"ip":       {"tcp", "tcp_syn", "udp", "icmp", "fragment"},
	"tcp":      {"tcp_syn"},
	"tcp_syn":  {},
	"udp":      {},
	"icmp":     {},
	"fragment": {},
}

type attackKey struct {
	DstIP     string
	Direction string
	Decoder   string
}

// Dedup tracks active attacks and suppresses redundant broader alerts.
type Dedup struct {
	mu     sync.RWMutex
	active map[attackKey]bool
}

func New() *Dedup {
	return &Dedup{active: make(map[attackKey]bool)}
}

// MarkActive registers an active attack.
func (d *Dedup) MarkActive(dstIP, direction, decoder string) {
	d.mu.Lock()
	d.active[attackKey{dstIP, direction, decoder}] = true
	d.mu.Unlock()
}

// ClearActive removes an attack from tracking.
func (d *Dedup) ClearActive(dstIP, direction, decoder string) {
	d.mu.Lock()
	delete(d.active, attackKey{dstIP, direction, decoder})
	d.mu.Unlock()
}

// ShouldSuppress returns true if the given threshold exceeded event should be
// suppressed because a more specific decoder is already active.
func (d *Dedup) ShouldSuppress(evt engine.ThresholdExceeded) bool {
	dstIP := ""
	if evt.DstIP != nil {
		dstIP = evt.DstIP.String()
	}
	if dstIP == "" && evt.Domain == "subnet" {
		// Subnet-level events (carpet bombing) use prefix as key, not IP.
		// They are never suppressed by per-IP decoders.
		return false
	}

	d.mu.RLock()
	defer d.mu.RUnlock()

	for _, moreSpecific := range suppressedBy[evt.Decoder] {
		if d.active[attackKey{dstIP, evt.Direction, moreSpecific}] {
			return true
		}
	}
	return false
}
