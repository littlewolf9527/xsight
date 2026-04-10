// Package collector reads BPF maps every second, computes deltas, adjusts
// the dynamic sample rate, and outputs results for verification (P3) or
// upstream consumption (P5+).
//
package collector

import (
	"context"
	"fmt"
	"log"
	"math"
	"net"
	"sort"
	"strings"
	"sync/atomic"
	"time"

	"github.com/littlewolf9527/xsight/node/internal/bpf"
	"github.com/littlewolf9527/xsight/node/internal/sampler"
	"github.com/littlewolf9527/xsight/shared/decoder"
)

// ----- configuration constants -----

const (
	// DefaultTargetSPS is the default target samples per second fed to gopacket.
	DefaultTargetSPS = 100_000

	// maxIPDelta is the ip_stats truncation threshold (brainstorm: 10 000).
	maxIPDelta = 10_000

	// topKTerminal is how many IPs to print in the terminal output.
	topKTerminal = 10

	// ewmaAlpha is the EWMA smoothing factor for sample rate (brainstorm: α=0.3).
	ewmaAlpha = 0.3

	// hysteresis prevents rate micro-adjustments (absolute delta threshold).
	hysteresis = 2.0

	// minHoldTime prevents sample rate oscillation (brainstorm: 3 s).
	minHoldTime = 3 * time.Second

	// maxSampleRate clamps the upper bound (brainstorm: 1000).
	maxSampleRate = 1000
)

// ----- public types -----

// IPDelta is a single IP's per-second delta.
type IPDelta struct {
	Key   bpf.LPMKey
	Stats bpf.DstIPStats
}

// PrefixDelta is a single prefix's per-second delta plus active-IP count.
type PrefixDelta struct {
	Key       bpf.PrefixKeyGo
	Stats     bpf.PrefixStats
	ActiveIPs uint32
}

// GlobalDelta is the per-second delta for global counters.
// v2.11: added MatchedBytes + per-decoder breakdown for 0.0.0.0/0 global threshold.
// v2.11 Phase 2: added outbound (src_ip matched) counters.
type GlobalDelta struct {
	TotalPkts         uint64
	TotalBytes        uint64
	MatchedPkts       uint64
	MatchedBytes      uint64                     // bytes within watch scope
	SampleDrops       uint64                     // ring buffer reserve failures this tick
	DecoderCounts     [decoder.MaxDecoders]uint32 // per-decoder PPS (inbound matched only)
	DecoderByteCounts [decoder.MaxDecoders]uint64 // per-decoder BPS (inbound matched only)
	// Outbound (src_ip matched) global counters
	SrcMatchedPkts       uint64
	SrcMatchedBytes      uint64
	SrcDecoderCounts     [decoder.MaxDecoders]uint32
	SrcDecoderByteCounts [decoder.MaxDecoders]uint64
}

// HealthStatus represents Node health per brainstorm spec.
type HealthStatus struct {
	Status  string // "healthy" | "degraded" | "unhealthy"
	Message string
}

// Report is the output of a single collection tick.
type Report struct {
	Timestamp      time.Time
	Global         GlobalDelta
	IPDeltas       []IPDelta
	PrefixDeltas   []PrefixDelta
	// v2.11 Phase 2: outbound (src_ip matched) deltas
	SrcIPDeltas       []IPDelta
	SrcPrefixDeltas   []PrefixDelta
	SrcTruncated      bool
	TotalActiveSrcIPs int
	Truncated      bool
	TotalActiveIPs int
	SampleRate     uint32
	Health         HealthStatus
	TopFlows       []sampler.FlowEntry // top-N flows from flow table this tick
}

// ----- collector -----

// Collector reads BPF maps every second and computes deltas.
type Collector struct {
	mgr *bpf.Manager

	// Reports channel delivers each tick's report to the reporter (P5).
	// Buffered so collection is not blocked by slow consumers.
	Reports chan *Report

	// snapshots from last tick (inbound)
	lastGlobal  bpf.GlobalStats
	lastIP      map[bpf.LPMKey]bpf.DstIPStats
	lastPrefix  map[bpf.PrefixKeyGo]bpf.PrefixStats
	// snapshots from last tick (outbound)
	lastSrcIP     map[bpf.LPMKey]bpf.DstIPStats
	lastSrcPrefix map[bpf.PrefixKeyGo]bpf.PrefixStats

	// report channel drop counter (rate-limited log)
	reportDrops uint64

	// dynamic sample rate state
	smoothedRate   float64
	lastRateChange time.Time

	// backpressure: consecutive ticks with increasing sample_drops
	dropTicks int

	// health: count consecutive ticks with zero global_stats growth
	zeroTicks int

	// HotSwap: skip next tick's deltas to avoid cumulative-as-delta spike
	skipNextTick atomic.Bool

	// config
	targetSPS float64

	// Flow table (optional, set via SetFlowTable)
	flowTable *sampler.FlowTable
}

// New creates a Collector that reads maps from mgr.
// targetSPS is the target samples-per-second (0 = DefaultTargetSPS).
func New(mgr *bpf.Manager, targetSPS float64) *Collector {
	if targetSPS <= 0 {
		targetSPS = DefaultTargetSPS
	}
	c := &Collector{
		mgr:          mgr,
		Reports:      make(chan *Report, 4),
		lastIP:        make(map[bpf.LPMKey]bpf.DstIPStats),
		lastPrefix:    make(map[bpf.PrefixKeyGo]bpf.PrefixStats),
		lastSrcIP:     make(map[bpf.LPMKey]bpf.DstIPStats),
		lastSrcPrefix: make(map[bpf.PrefixKeyGo]bpf.PrefixStats),
		smoothedRate: 1,
		targetSPS:    targetSPS,
	}
	c.skipNextTick.Store(true) // skip first tick to establish baseline
	return c
}

// SetFlowTable sets the flow table used to drain top-N flows each tick.
// Must be called before Run().
func (c *Collector) SetFlowTable(ft *sampler.FlowTable) {
	c.flowTable = ft
}

// NotifyHotSwap tells the collector that a BPF map slot swap happened.
// The next tick will update baselines but skip delta reporting to avoid
// cumulative-as-delta spikes (BPF counters reset to new slot baseline).
func (c *Collector) NotifyHotSwap() {
	c.skipNextTick.Store(true)
}

// Run starts the 1-second collection loop.  Blocks until ctx is cancelled.
func (c *Collector) Run(ctx context.Context) {
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			report, err := c.collect()
			if err != nil {
				log.Printf("collector: %v", err)
				continue
			}
			c.logReport(report)
			// Non-blocking send to Reports channel for P5 reporter
			select {
			case c.Reports <- report:
			default:
				c.reportDrops++
				if c.reportDrops == 1 || c.reportDrops%60 == 0 {
					log.Printf("collector: report channel full, dropping tick (total_drops=%d)", c.reportDrops)
				}
			}
		}
	}
}

// ----- internal -----

func (c *Collector) collect() (*Report, error) {
	now := time.Now()

	// 1. Read global_stats
	gs, err := c.mgr.GlobalStats()
	if err != nil {
		return nil, fmt.Errorf("global_stats: %w", err)
	}
	gd := GlobalDelta{
		TotalPkts:   gs.TotalPkts - c.lastGlobal.TotalPkts,
		TotalBytes:  gs.TotalBytes - c.lastGlobal.TotalBytes,
		MatchedPkts: gs.MatchedPkts - c.lastGlobal.MatchedPkts,
		MatchedBytes: gs.MatchedBytes - c.lastGlobal.MatchedBytes,
		SampleDrops: gs.SampleDrops - c.lastGlobal.SampleDrops,
	}
	// Per-decoder global deltas (inbound)
	for i := 0; i < decoder.MaxDecoders; i++ {
		gd.DecoderCounts[i] = gs.DecoderCounts[i] - c.lastGlobal.DecoderCounts[i]
		gd.DecoderByteCounts[i] = gs.DecoderByteCounts[i] - c.lastGlobal.DecoderByteCounts[i]
	}
	// Outbound global deltas
	gd.SrcMatchedPkts = gs.SrcMatchedPkts - c.lastGlobal.SrcMatchedPkts
	gd.SrcMatchedBytes = gs.SrcMatchedBytes - c.lastGlobal.SrcMatchedBytes
	for i := 0; i < decoder.MaxDecoders; i++ {
		gd.SrcDecoderCounts[i] = gs.SrcDecoderCounts[i] - c.lastGlobal.SrcDecoderCounts[i]
		gd.SrcDecoderByteCounts[i] = gs.SrcDecoderByteCounts[i] - c.lastGlobal.SrcDecoderByteCounts[i]
	}
	c.lastGlobal = *gs

	// 2. Read prefix_stats
	prefixNow := make(map[bpf.PrefixKeyGo]bpf.PrefixStats)
	{
		iter := c.mgr.IterPrefixStats()
		var k bpf.PrefixKeyGo
		var v bpf.PrefixStats
		for iter.Next(&k, &v) {
			prefixNow[k] = v
		}
		if err := iter.Err(); err != nil {
			return nil, fmt.Errorf("prefix_stats iter: %w", err)
		}
	}

	// 3. Read ip_stats (active slot) — batch syscalls for performance
	ipNow, err := c.mgr.BatchReadIPStats()
	if err != nil {
		return nil, fmt.Errorf("ip_stats: %w", err)
	}

	// 4. Compute IP deltas (only entries with pkt_count delta > 0)
	var ipDeltas []IPDelta
	for k, cur := range ipNow {
		prev := c.lastIP[k]
		d := subtractIPStats(cur, prev)
		if d.PktCount > 0 {
			ipDeltas = append(ipDeltas, IPDelta{Key: k, Stats: d})
		}
	}
	totalActiveIPs := len(ipDeltas)

	// Truncation: if > maxIPDelta, keep top-K by pkt_count
	truncated := false
	if len(ipDeltas) > maxIPDelta {
		truncated = true
		sort.Slice(ipDeltas, func(i, j int) bool {
			return ipDeltas[i].Stats.PktCount > ipDeltas[j].Stats.PktCount
		})
		ipDeltas = ipDeltas[:maxIPDelta]
	}

	// 5. Compute prefix deltas + active_ips per prefix
	prefixIPCount := c.countActiveIPsPerPrefix(ipDeltas, prefixNow)
	var prefixDeltas []PrefixDelta
	for k, cur := range prefixNow {
		prev := c.lastPrefix[k]
		d := subtractPrefixStats(cur, prev)
		if d.PktCount > 0 || d.OverflowCount > 0 {
			prefixDeltas = append(prefixDeltas, PrefixDelta{
				Key:       k,
				Stats:     d,
				ActiveIPs: prefixIPCount[k],
			})
		}
	}

	// 5b. Read outbound (src) maps — fail-closed, same as inbound
	srcPrefixNow := make(map[bpf.PrefixKeyGo]bpf.PrefixStats)
	{
		iter := c.mgr.IterSrcPrefixStats()
		var k bpf.PrefixKeyGo
		var v bpf.PrefixStats
		for iter.Next(&k, &v) {
			srcPrefixNow[k] = v
		}
		if err := iter.Err(); err != nil {
			return nil, fmt.Errorf("src_prefix_stats iter: %w", err)
		}
	}

	srcIPNow, err := c.mgr.BatchReadSrcIPStats()
	if err != nil {
		return nil, fmt.Errorf("src_ip_stats: %w", err)
	}

	var srcIPDeltas []IPDelta
	for k, cur := range srcIPNow {
		prev := c.lastSrcIP[k]
		d := subtractIPStats(cur, prev)
		if d.PktCount > 0 {
			srcIPDeltas = append(srcIPDeltas, IPDelta{Key: k, Stats: d})
		}
	}
	totalActiveSrcIPs := len(srcIPDeltas)
	srcTruncated := false
	if len(srcIPDeltas) > maxIPDelta {
		srcTruncated = true
		sort.Slice(srcIPDeltas, func(i, j int) bool {
			return srcIPDeltas[i].Stats.PktCount > srcIPDeltas[j].Stats.PktCount
		})
		srcIPDeltas = srcIPDeltas[:maxIPDelta]
	}

	srcPrefixIPCount := c.countActiveIPsPerPrefix(srcIPDeltas, srcPrefixNow)
	var srcPrefixDeltas []PrefixDelta
	for k, cur := range srcPrefixNow {
		prev := c.lastSrcPrefix[k]
		d := subtractPrefixStats(cur, prev)
		if d.PktCount > 0 || d.OverflowCount > 0 {
			srcPrefixDeltas = append(srcPrefixDeltas, PrefixDelta{
				Key:       k,
				Stats:     d,
				ActiveIPs: srcPrefixIPCount[k],
			})
		}
	}

	// 6. Backpressure tracking: consecutive ticks with ring buffer drops
	if gd.SampleDrops > 0 {
		c.dropTicks++
	} else {
		c.dropTicks = 0
	}

	// Health: detect stale global_stats (mirror port may be down)
	if gd.TotalPkts == 0 {
		c.zeroTicks++
	} else {
		c.zeroTicks = 0
	}
	health := HealthStatus{Status: "healthy"}
	if c.zeroTicks >= 10 {
		health = HealthStatus{Status: "degraded", Message: "global_stats not growing for 10+ seconds"}
	}

	// Store snapshots for next tick
	c.lastIP = ipNow
	c.lastPrefix = prefixNow
	c.lastSrcIP = srcIPNow
	c.lastSrcPrefix = srcPrefixNow

	// HotSwap guard: skip deltas AND sample rate adjustment for one tick
	// after startup or slot swap. The matched count on this tick is cumulative
	// (not a 1-second delta), so feeding it into EWMA would produce a wildly
	// inflated local_sample_rate that persists for many subsequent ticks and
	// causes the upstream restoration (observed × upstream × local) to overshoot.
	if c.skipNextTick.Load() {
		c.skipNextTick.Store(false)
		log.Println("collector: skipping delta report + sample rate (post-HotSwap baseline reset)")
		ipDeltas = nil
		prefixDeltas = nil
		// Keep current smoothedRate unchanged; use it as-is for this tick's report
		sampleRate := uint32(math.Round(c.smoothedRate))
		if sampleRate < 1 {
			sampleRate = 1
		}
		return &Report{
			Timestamp:      now,
			Global:         gd,
			IPDeltas:       nil,
			PrefixDeltas:   nil,
			Truncated:      false,
			TotalActiveIPs: 0,
			SampleRate:     sampleRate,
			Health:         health,
		}, nil
	}

	// 7. Dynamic sample rate adjustment (includes backpressure)
	// Dynamic sample rate uses total matched PPS (inbound + outbound)
	sampleRate := c.adjustSampleRate(gd.MatchedPkts+gd.SrcMatchedPkts, now)

	// 8. Drain flow table top-N for this tick
	var topFlows []sampler.FlowEntry
	if c.flowTable != nil {
		topFlows = c.flowTable.DrainTopN(100)
	}

	return &Report{
		Timestamp:         now,
		Global:            gd,
		IPDeltas:          ipDeltas,
		PrefixDeltas:      prefixDeltas,
		Truncated:         truncated,
		TotalActiveIPs:    totalActiveIPs,
		SrcIPDeltas:       srcIPDeltas,
		SrcPrefixDeltas:   srcPrefixDeltas,
		SrcTruncated:      srcTruncated,
		TotalActiveSrcIPs: totalActiveSrcIPs,
		SampleRate:        sampleRate,
		Health:            health,
		TopFlows:          topFlows,
	}, nil
}

// adjustSampleRate implements the EWMA + hysteresis + min-hold algorithm.
// Reference: brainstorm-node.md "Dynamic Sample Rate Mechanism"
func (c *Collector) adjustSampleRate(matchedPPS uint64, now time.Time) uint32 {
	// raw_rate = observed_pps / target
	rawRate := float64(matchedPPS) / c.targetSPS

	// rate < 2 → 1 (prefer no secondary sampling)
	if rawRate < 2 {
		rawRate = 1
	}

	// Backpressure: ring buffer drops for 3+ consecutive ticks → double rate
	// Reference: brainstorm-node.md "Backpressure Handling"
	if c.dropTicks >= 3 && rawRate < maxSampleRate {
		rawRate = math.Max(rawRate*2, float64(c.smoothedRate)*2)
		log.Printf("collector: backpressure engaged (drops for %d ticks), rate → %.0f", c.dropTicks, rawRate)
	}

	// clamp [1, maxSampleRate]
	if rawRate < 1 {
		rawRate = 1
	}
	if rawRate > maxSampleRate {
		rawRate = maxSampleRate
	}

	// EWMA smoothing
	smoothed := ewmaAlpha*rawRate + (1-ewmaAlpha)*c.smoothedRate

	// Hysteresis: skip small changes
	if math.Abs(smoothed-c.smoothedRate) < hysteresis {
		smoothed = c.smoothedRate
	}

	// Min hold time: don't change rate within 3s of last change
	rateChanged := uint32(math.Round(smoothed)) != uint32(math.Round(c.smoothedRate))
	if rateChanged && now.Sub(c.lastRateChange) < minHoldTime {
		smoothed = c.smoothedRate
	}

	finalRate := uint32(math.Round(smoothed))
	if finalRate < 1 {
		finalRate = 1
	}

	// Write to BPF if changed
	if finalRate != uint32(math.Round(c.smoothedRate)) {
		if err := c.mgr.SetSampleRate(finalRate); err != nil {
			log.Printf("collector: set sample_rate: %v", err)
		} else {
			c.lastRateChange = now
		}
	}
	c.smoothedRate = smoothed

	return finalRate
}

// countActiveIPsPerPrefix counts how many active IPs fall under each prefix.
func (c *Collector) countActiveIPsPerPrefix(
	ipDeltas []IPDelta,
	prefixNow map[bpf.PrefixKeyGo]bpf.PrefixStats,
) map[bpf.PrefixKeyGo]uint32 {
	// Build list of net.IPNet from known prefix keys
	type prefixNet struct {
		key bpf.PrefixKeyGo
		net net.IPNet
	}
	var prefixes []prefixNet
	for k := range prefixNow {
		ipNet := PrefixKeyToIPNet(k)
		prefixes = append(prefixes, prefixNet{key: k, net: ipNet})
	}

	counts := make(map[bpf.PrefixKeyGo]uint32)
	for _, d := range ipDeltas {
		ip := LPMKeyToIP(d.Key)
		for _, p := range prefixes {
			if p.net.Contains(ip) {
				counts[p.key]++
				break
			}
		}
	}
	return counts
}

// ----- helpers -----

func subtractIPStats(cur, prev bpf.DstIPStats) bpf.DstIPStats {
	d := bpf.DstIPStats{
		PktCount:  cur.PktCount - prev.PktCount,
		ByteCount: cur.ByteCount - prev.ByteCount,
		SmallPkt:  cur.SmallPkt - prev.SmallPkt,
		MediumPkt: cur.MediumPkt - prev.MediumPkt,
		LargePkt:  cur.LargePkt - prev.LargePkt,
	}
	for i := 0; i < len(d.DecoderCounts); i++ {
		d.DecoderCounts[i] = cur.DecoderCounts[i] - prev.DecoderCounts[i]
	}
	for i := 0; i < len(d.DecoderByteCounts); i++ {
		d.DecoderByteCounts[i] = cur.DecoderByteCounts[i] - prev.DecoderByteCounts[i]
	}
	return d
}

func subtractPrefixStats(cur, prev bpf.PrefixStats) bpf.PrefixStats {
	d := bpf.PrefixStats{
		PktCount:      cur.PktCount - prev.PktCount,
		ByteCount:     cur.ByteCount - prev.ByteCount,
		OverflowCount: cur.OverflowCount - prev.OverflowCount,
	}
	for i := 0; i < len(d.DecoderCounts); i++ {
		d.DecoderCounts[i] = cur.DecoderCounts[i] - prev.DecoderCounts[i]
	}
	for i := 0; i < len(d.DecoderByteCounts); i++ {
		d.DecoderByteCounts[i] = cur.DecoderByteCounts[i] - prev.DecoderByteCounts[i]
	}
	return d
}

// LPMKeyToIP extracts a net.IP from an LPMKey (/32 → IPv4, /128 → IPv6).
func LPMKeyToIP(k bpf.LPMKey) net.IP {
	if k.Prefixlen == 32 {
		return net.IP(k.Addr[:4])
	}
	return net.IP(k.Addr[:16])
}

// PrefixKeyToIPNet builds a net.IPNet from a PrefixKeyGo.
func PrefixKeyToIPNet(k bpf.PrefixKeyGo) net.IPNet {
	ones := int(k.Prefixlen)
	// Detect IPv4 vs IPv6: if bytes 4-15 are all zero and prefixlen <= 32 → IPv4
	isV4 := ones <= 32
	if isV4 {
		for i := 4; i < 16; i++ {
			if k.Addr[i] != 0 {
				isV4 = false
				break
			}
		}
	}
	if isV4 {
		return net.IPNet{
			IP:   net.IP(k.Addr[:4]),
			Mask: net.CIDRMask(ones, 32),
		}
	}
	return net.IPNet{
		IP:   net.IP(k.Addr[:16]),
		Mask: net.CIDRMask(ones, 128),
	}
}

// formatIP returns a human-readable IP string from an LPMKey.
func formatIP(k bpf.LPMKey) string {
	return LPMKeyToIP(k).String()
}

// formatPrefix returns a CIDR string from a PrefixKeyGo.
func formatPrefix(k bpf.PrefixKeyGo) string {
	n := PrefixKeyToIPNet(k)
	return n.String()
}

// logReport prints the per-second delta to stdout for P3 verification.
// Will be replaced by gRPC reporting in P5.
func (c *Collector) logReport(r *Report) {
	var sb strings.Builder

	// Global line
	fmt.Fprintf(&sb, "--- %s | global: pps=%d bps=%d matched=%d | sample_rate=%d",
		r.Timestamp.Format("15:04:05"),
		r.Global.TotalPkts, r.Global.TotalBytes*8, r.Global.MatchedPkts,
		r.SampleRate)
	if r.Truncated {
		fmt.Fprintf(&sb, " | TRUNCATED active_ips=%d (showing top %d)", r.TotalActiveIPs, maxIPDelta)
	}
	sb.WriteString("\n")

	// Prefix summary
	if len(r.PrefixDeltas) > 0 {
		sb.WriteString("  prefixes:\n")
		for _, pd := range r.PrefixDeltas {
			fmt.Fprintf(&sb, "    %s  pps=%-8d bps=%-12d active_ips=%-5d overflow=%d\n",
				formatPrefix(pd.Key), pd.Stats.PktCount, pd.Stats.ByteCount*8,
				pd.ActiveIPs, pd.Stats.OverflowCount)
		}
	}

	// Top-N IP deltas
	if len(r.IPDeltas) > 0 {
		// Sort by pkt_count descending for display
		sorted := make([]IPDelta, len(r.IPDeltas))
		copy(sorted, r.IPDeltas)
		sort.Slice(sorted, func(i, j int) bool {
			return sorted[i].Stats.PktCount > sorted[j].Stats.PktCount
		})
		n := topKTerminal
		if n > len(sorted) {
			n = len(sorted)
		}
		fmt.Fprintf(&sb, "  top-%d IPs:\n", n)
		for _, d := range sorted[:n] {
			s := d.Stats
			fmt.Fprintf(&sb, "    %-40s pps=%-8d bps=%-12d tcp=%-5d syn=%-5d udp=%-5d icmp=%-5d frag=%-5d sm=%-5d md=%-5d lg=%-5d\n",
				formatIP(d.Key), s.PktCount, s.ByteCount*8,
				s.DecoderCounts[decoder.TCP], s.DecoderCounts[decoder.TCPSyn], s.DecoderCounts[decoder.UDP], s.DecoderCounts[decoder.ICMP], s.DecoderCounts[decoder.Frag],
				s.SmallPkt, s.MediumPkt, s.LargePkt)
		}
	}

	log.Print(sb.String())
}
