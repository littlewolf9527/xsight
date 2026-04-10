// Package ring implements in-memory ring buffers for real-time traffic data.
//
// Architecture:
//   - RingStore holds two directionStore instances (inbound + outbound)
//   - Each directionStore has per-prefix and per-IP ring buffers
//   - Each ring is a fixed-capacity circular buffer of DataPoints (1 per second)
//   - LRU eviction when limits are reached
//   - Active-attack IPs are protected from eviction
//
// v2.11 Phase 2: refactored to directionStore to share all logic between
// inbound (dst_ip) and outbound (src_ip) without code duplication.
package ring

import (
	"net"
	"sync"
	"time"

	"github.com/littlewolf9527/xsight/shared/decoder"
)

// DataPoint holds one second of aggregated traffic statistics.
type DataPoint struct {
	Time       time.Time
	PPS        int64
	BPS        int64
	DecoderPPS [decoder.MaxDecoders]int32
	DecoderBPS [decoder.MaxDecoders]int64
	ActiveIPs  uint32
	Overflow   uint32
}

// Limits configures hard upper bounds for the ring store.
type Limits struct {
	MaxIPsPerPrefix int // default 10,000
	MaxPointsPerIP  int // default 120
	MaxGlobalKeys   int // default 100,000
}

func DefaultLimits() Limits {
	return Limits{
		MaxIPsPerPrefix: 10_000,
		MaxPointsPerIP:  120,
		MaxGlobalKeys:   100_000,
	}
}

// ---------------------------------------------------------------------------
// directionStore — the single implementation for one traffic direction.
// Both inbound and outbound use the same struct with identical LRU,
// eviction, MarkActive, and limit enforcement logic.
// ---------------------------------------------------------------------------

type directionStore struct {
	prefixes  map[string]*PrefixRing
	ips       map[string]*IPRing
	ipAccess  map[string]time.Time
	activeIPs map[string]bool
}

func newDirectionStore() *directionStore {
	return &directionStore{
		prefixes:  make(map[string]*PrefixRing),
		ips:       make(map[string]*IPRing),
		ipAccess:  make(map[string]time.Time),
		activeIPs: make(map[string]bool),
	}
}

func (d *directionStore) pushPrefix(key, prefix string, capacity int, dp DataPoint) {
	pr, ok := d.prefixes[key]
	if !ok {
		pr = newPrefixRing(prefix, capacity)
		d.prefixes[key] = pr
	}
	pr.Push(dp)
}

func (d *directionStore) pushIP(pKey, iKey, ipStr, prefix string, limits Limits, dp DataPoint) {
	ir, ok := d.ips[iKey]
	if !ok {
		if len(d.ips) >= limits.MaxGlobalKeys {
			d.evictOne()
		}
		pr := d.prefixes[pKey]
		if pr != nil && len(pr.ipKeys) >= limits.MaxIPsPerPrefix {
			d.evictFromPrefix(pKey)
		}
		ir = newIPRing(ipStr, prefix, limits.MaxPointsPerIP)
		d.ips[iKey] = ir
		if pr == nil {
			pr = newPrefixRing(prefix, limits.MaxPointsPerIP)
			d.prefixes[pKey] = pr
		}
		pr.ipKeys[iKey] = struct{}{}
	}
	ir.Push(dp)
	d.ipAccess[iKey] = dp.Time
}

func (d *directionStore) getPrefixRing(key string) *PrefixRing {
	return d.prefixes[key]
}

func (d *directionStore) getIPRing(key string) *IPRing {
	return d.ips[key]
}

func (d *directionStore) ipKeysForPrefix(pKey string) []string {
	pr := d.prefixes[pKey]
	if pr == nil {
		return nil
	}
	pfx := pKey + ":"
	result := make([]string, 0, len(pr.ipKeys))
	for key := range pr.ipKeys {
		if len(key) > len(pfx) {
			result = append(result, key[len(pfx):])
		}
	}
	return result
}

func (d *directionStore) markActive(key string)  { d.activeIPs[key] = true }
func (d *directionStore) clearActive(key string) { delete(d.activeIPs, key) }

func (d *directionStore) stats() (prefixCount, ipCount, activeCount int) {
	return len(d.prefixes), len(d.ips), len(d.activeIPs)
}

// evictOne removes the LRU non-attack IP ring.
func (d *directionStore) evictOne() {
	var oldest string
	var oldestTime time.Time
	for key, t := range d.ipAccess {
		if d.activeIPs[key] {
			continue
		}
		if oldest == "" || t.Before(oldestTime) {
			oldest = key
			oldestTime = t
		}
	}
	if oldest == "" {
		for key, t := range d.ipAccess {
			if oldest == "" || t.Before(oldestTime) {
				oldest = key
				oldestTime = t
			}
		}
	}
	if oldest != "" {
		d.removeIP(oldest)
	}
}

// evictFromPrefix removes the LRU non-attack IP from a specific prefix.
func (d *directionStore) evictFromPrefix(prefix string) {
	pr := d.prefixes[prefix]
	if pr == nil {
		return
	}
	var oldest string
	var oldestTime time.Time
	for key := range pr.ipKeys {
		if d.activeIPs[key] {
			continue
		}
		t := d.ipAccess[key]
		if oldest == "" || t.Before(oldestTime) {
			oldest = key
			oldestTime = t
		}
	}
	if oldest != "" {
		d.removeIP(oldest)
	}
}

// removeIP deletes an IP ring and all its tracking data.
func (d *directionStore) removeIP(key string) {
	ir, ok := d.ips[key]
	if !ok {
		return
	}
	delete(d.ips, key)
	delete(d.ipAccess, key)
	delete(d.activeIPs, key)
	pKey := key[:len(key)-len(":")-len(ir.DstIP)]
	pr := d.prefixes[pKey]
	if pr != nil {
		delete(pr.ipKeys, key)
	}
}

// ---------------------------------------------------------------------------
// PrefixRing / IPRing — unchanged circular buffer types
// ---------------------------------------------------------------------------

type PrefixRing struct {
	Prefix string
	buf    []DataPoint
	head   int
	count  int
	cap    int
	ipKeys map[string]struct{}
}

func newPrefixRing(prefix string, capacity int) *PrefixRing {
	return &PrefixRing{
		Prefix: prefix,
		buf:    make([]DataPoint, capacity),
		cap:    capacity,
		ipKeys: make(map[string]struct{}),
	}
}

func (r *PrefixRing) Push(dp DataPoint) {
	r.buf[r.head] = dp
	r.head = (r.head + 1) % r.cap
	if r.count < r.cap {
		r.count++
	}
}

func (r *PrefixRing) Latest(n int) []DataPoint {
	if n > r.count {
		n = r.count
	}
	result := make([]DataPoint, n)
	for i := 0; i < n; i++ {
		idx := (r.head - 1 - i + r.cap) % r.cap
		result[i] = r.buf[idx]
	}
	return result
}

func (r *PrefixRing) Count() int { return r.count }

func (r *PrefixRing) LatestOne(maxAge time.Duration) (DataPoint, bool) {
	if r.count == 0 {
		return DataPoint{}, false
	}
	idx := (r.head - 1 + r.cap) % r.cap
	dp := r.buf[idx]
	if maxAge > 0 && time.Since(dp.Time) > maxAge {
		return DataPoint{}, false
	}
	return dp, true
}

type IPRing struct {
	DstIP  string
	Prefix string
	buf    []DataPoint
	head   int
	count  int
	cap    int
}

func newIPRing(dstIP, prefix string, capacity int) *IPRing {
	return &IPRing{
		DstIP:  dstIP,
		Prefix: prefix,
		buf:    make([]DataPoint, capacity),
		cap:    capacity,
	}
}

func (r *IPRing) Push(dp DataPoint) {
	r.buf[r.head] = dp
	r.head = (r.head + 1) % r.cap
	if r.count < r.cap {
		r.count++
	}
}

func (r *IPRing) Latest(n int) []DataPoint {
	if n > r.count {
		n = r.count
	}
	result := make([]DataPoint, n)
	for i := 0; i < n; i++ {
		idx := (r.head - 1 - i + r.cap) % r.cap
		result[i] = r.buf[idx]
	}
	return result
}

func (r *IPRing) Count() int { return r.count }

func (r *IPRing) LatestOne(maxAge time.Duration) (DataPoint, bool) {
	if r.count == 0 {
		return DataPoint{}, false
	}
	idx := (r.head - 1 + r.cap) % r.cap
	dp := r.buf[idx]
	if maxAge > 0 && time.Since(dp.Time) > maxAge {
		return DataPoint{}, false
	}
	return dp, true
}

// ---------------------------------------------------------------------------
// RingStore — top-level container, delegates to directionStore
// ---------------------------------------------------------------------------

type NodePrefix struct {
	NodeID string
	Prefix string
}

func prefixKey(nodeID, prefix string) string { return nodeID + ":" + prefix }
func ipKey(nodeID, prefix, ip string) string { return nodeID + ":" + prefix + ":" + ip }

type RingStore struct {
	mu       sync.RWMutex
	inbound  *directionStore
	outbound *directionStore
	limits   Limits
}

func New(limits Limits) *RingStore {
	return &RingStore{
		inbound:  newDirectionStore(),
		outbound: newDirectionStore(),
		limits:   limits,
	}
}

// --- Inbound (dst_ip) public API ---

func (s *RingStore) PushPrefix(nodeID, prefix string, dp DataPoint) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.inbound.pushPrefix(prefixKey(nodeID, prefix), prefix, s.limits.MaxPointsPerIP, dp)
}

func (s *RingStore) PushIP(nodeID, prefix string, dstIP net.IP, dp DataPoint) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.inbound.pushIP(prefixKey(nodeID, prefix), ipKey(nodeID, prefix, dstIP.String()), dstIP.String(), prefix, s.limits, dp)
}

func (s *RingStore) GetPrefixRing(nodeID, prefix string) *PrefixRing {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.inbound.getPrefixRing(prefixKey(nodeID, prefix))
}

func (s *RingStore) GetIPRing(nodeID, prefix string, dstIP net.IP) *IPRing {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.inbound.getIPRing(ipKey(nodeID, prefix, dstIP.String()))
}

func (s *RingStore) GetIPRingByKey(nodeID, prefix, ipStr string) *IPRing {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.inbound.getIPRing(ipKey(nodeID, prefix, ipStr))
}

func (s *RingStore) MarkActive(nodeID, prefix string, dstIP net.IP) {
	s.mu.Lock()
	s.inbound.markActive(ipKey(nodeID, prefix, dstIP.String()))
	s.mu.Unlock()
}

func (s *RingStore) ClearActive(nodeID, prefix string, dstIP net.IP) {
	s.mu.Lock()
	s.inbound.clearActive(ipKey(nodeID, prefix, dstIP.String()))
	s.mu.Unlock()
}

func (s *RingStore) IPKeysForPrefix(nodeID, prefix string) []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.inbound.ipKeysForPrefix(prefixKey(nodeID, prefix))
}

// --- Outbound (src_ip) public API — same directionStore, different instance ---

func (s *RingStore) PushSrcPrefix(nodeID, prefix string, dp DataPoint) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.outbound.pushPrefix(prefixKey(nodeID, prefix), prefix, s.limits.MaxPointsPerIP, dp)
}

func (s *RingStore) PushSrcIP(nodeID, prefix string, srcIP net.IP, dp DataPoint) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.outbound.pushIP(prefixKey(nodeID, prefix), ipKey(nodeID, prefix, srcIP.String()), srcIP.String(), prefix, s.limits, dp)
}

func (s *RingStore) GetSrcPrefixRing(nodeID, prefix string) *PrefixRing {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.outbound.getPrefixRing(prefixKey(nodeID, prefix))
}

func (s *RingStore) GetSrcIPRingByKey(nodeID, prefix, ipStr string) *IPRing {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.outbound.getIPRing(ipKey(nodeID, prefix, ipStr))
}

func (s *RingStore) SrcIPKeysForPrefix(nodeID, prefix string) []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.outbound.ipKeysForPrefix(prefixKey(nodeID, prefix))
}



func (s *RingStore) MarkSrcActive(nodeID, prefix string, srcIP net.IP) {
	s.mu.Lock()
	s.outbound.markActive(ipKey(nodeID, prefix, srcIP.String()))
	s.mu.Unlock()
}

func (s *RingStore) ClearSrcActive(nodeID, prefix string, srcIP net.IP) {
	s.mu.Lock()
	s.outbound.clearActive(ipKey(nodeID, prefix, srcIP.String()))
	s.mu.Unlock()
}

// --- Shared ---

func (s *RingStore) AllNodePrefixes() []NodePrefix {
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make([]NodePrefix, 0, len(s.inbound.prefixes))
	for key, pr := range s.inbound.prefixes {
		for i := 0; i < len(key); i++ {
			if key[i] == ':' {
				result = append(result, NodePrefix{NodeID: key[:i], Prefix: pr.Prefix})
				break
			}
		}
	}
	return result
}

func (s *RingStore) AllOutboundNodePrefixes() []NodePrefix {
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make([]NodePrefix, 0, len(s.outbound.prefixes))
	for key, pr := range s.outbound.prefixes {
		for i := 0; i < len(key); i++ {
			if key[i] == ':' {
				result = append(result, NodePrefix{NodeID: key[:i], Prefix: pr.Prefix})
				break
			}
		}
	}
	return result
}

func (s *RingStore) Stats() (prefixCount, ipCount, activeCount int) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	ip, iip, ia := s.inbound.stats()
	op, oip, oa := s.outbound.stats()
	return ip + op, iip + oip, ia + oa
}
