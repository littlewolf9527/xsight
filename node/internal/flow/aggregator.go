package flow

import (
	"encoding/json"
	"log"
	"net"
	"sync"
	"time"

	"github.com/littlewolf9527/xsight/node/internal/pb"
	"github.com/littlewolf9527/xsight/shared/decoder"
)

const sourceOfflineTimeout = 60 // seconds — source considered offline if no packets for this long

const (
	// maxSpreadDuration clamps excessively long flow durations (e.g. broken exporter).
	maxSpreadDuration = 300
	// staleBucketAge — buckets older than this are garbage-collected in Flush.
	staleBucketAge = int64(600) // seconds
)

// FlowAggregator accumulates FlowRecords into per-second buckets,
// producing *pb.StatsReport directly (bypasses BPF-coupled collector.Report).
//
// Time spreading: NetFlow/IPFIX records with Duration > 1s are evenly distributed
// across their actual time range. sFlow records (Duration=0) go into the current second.
// Flush pops the bucket for (now-1) each tick.
type FlowAggregator struct {
	mu              sync.Mutex
	prefixTrie      *PrefixTrie
	flowRecordTable *FlowRecordTable
	buckets         map[int64]*secondBucket // unix timestamp → bucket

	listeners []*Listener // for metrics collection
}

// secondBucket holds all stats accumulated for a single second.
type secondBucket struct {
	// Inbound global
	globalPkts         uint64
	globalBytes        uint64
	globalDecoderPkts  [decoder.MaxDecoders]uint32
	globalDecoderBytes [decoder.MaxDecoders]uint64
	// Outbound global
	srcGlobalPkts         uint64
	srcGlobalBytes        uint64
	srcGlobalDecoderPkts  [decoder.MaxDecoders]uint32
	srcGlobalDecoderBytes [decoder.MaxDecoders]uint64

	ipStats        map[string]*ipDelta    // dst_ip string → inbound
	prefixStats    map[string]*prefixDelta
	srcIPStats     map[string]*ipDelta    // src_ip string → outbound
	srcPrefixStats map[string]*prefixDelta
}

func newSecondBucket() *secondBucket {
	return &secondBucket{
		ipStats:        make(map[string]*ipDelta),
		prefixStats:    make(map[string]*prefixDelta),
		srcIPStats:     make(map[string]*ipDelta),
		srcPrefixStats: make(map[string]*prefixDelta),
	}
}

type ipDelta struct {
	IP           net.IP
	Pkts         uint64
	Bytes        uint64
	DecoderPkts  [decoder.MaxDecoders]uint32
	DecoderBytes [decoder.MaxDecoders]uint64
}

type prefixDelta struct {
	Prefix       string
	PrefixLen    uint32
	PrefixIP     net.IP
	Pkts         uint64
	Bytes        uint64
	ActiveIPs    map[string]bool
	DecoderPkts  [decoder.MaxDecoders]uint32
	DecoderBytes [decoder.MaxDecoders]uint64
}

// SetListeners sets the listener references for metrics collection in Flush().
func (a *FlowAggregator) SetListeners(listeners []*Listener) {
	a.mu.Lock()
	a.listeners = listeners
	a.mu.Unlock()
}

// NewFlowAggregator creates an aggregator with the given prefix trie.
func NewFlowAggregator(trie *PrefixTrie) *FlowAggregator {
	return &FlowAggregator{
		prefixTrie:      trie,
		flowRecordTable: NewFlowRecordTable(10000),
		buckets:         make(map[int64]*secondBucket),
	}
}

// getBucket returns (or creates) the bucket for the given unix second.
func (a *FlowAggregator) getBucket(ts int64) *secondBucket {
	b, ok := a.buckets[ts]
	if !ok {
		b = newSecondBucket()
		a.buckets[ts] = b
	}
	return b
}

// Add processes a single FlowRecord from a listener.
// If Duration > 1, the record's packets/bytes are evenly spread across
// [StartTime, StartTime+Duration) second buckets. Otherwise, everything
// goes into the current-second bucket (arrival-time semantics).
func (a *FlowAggregator) Add(rec FlowRecord, source *Source) {
	rate := source.ResolveSampleRate(rec.SampleRate)
	realPkts := rec.Packets * uint64(rate)
	realBytes := rec.Bytes * uint64(rate)
	decoderIdx := ProtocolToDecoder(rec.Protocol, rec.TCPFlags)

	a.mu.Lock()
	defer a.mu.Unlock()

	// Determine time spread
	now := time.Now().Unix()
	duration := rec.Duration

	// Validate duration (ignore exporter absolute clock — only use duration)
	if duration > maxSpreadDuration {
		duration = maxSpreadDuration
	}
	// Spread into the future from arrival time: [now, now+duration-1].
	// This avoids depending on exporter clock accuracy (which can be off by minutes).
	// Natural Flush(now-1) drains each bucket as time advances.
	// Detection sees smooth data with up to `duration` seconds of additional latency
	// (acceptable since the flow was already `duration` seconds old when exported).
	startTS := now
	if duration <= 1 {
		duration = 0
	}

	// Prefix matching
	dstPrefix := a.prefixTrie.Match(rec.DstIP)
	srcPrefix := a.prefixTrie.Match(rec.SrcIP)

	if dstPrefix == "" && srcPrefix == "" {
		return // no match at all
	}

	// Spread across buckets
	if duration <= 1 {
		// sFlow or short flow — single bucket at arrival time
		b := a.getBucket(now)
		if dstPrefix != "" {
			a.addInbound(b, dstPrefix, rec.DstIP, decoderIdx, realPkts, realBytes)
		}
		if srcPrefix != "" {
			a.addOutbound(b, srcPrefix, rec.SrcIP, decoderIdx, realPkts, realBytes)
		}
	} else {
		// NetFlow/IPFIX — spread across [startTS, startTS+duration)
		dur := uint64(duration)
		basePkts := realPkts / dur
		baseBytes := realBytes / dur
		remPkts := realPkts % dur
		remBytes := realBytes % dur

		for i := uint64(0); i < dur; i++ {
			p := basePkts
			by := baseBytes
			if i < remPkts {
				p++
			}
			if i < remBytes {
				by++
			}
			if p == 0 && by == 0 {
				continue
			}
			b := a.getBucket(startTS + int64(i))
			if dstPrefix != "" {
				a.addInbound(b, dstPrefix, rec.DstIP, decoderIdx, p, by)
			}
			if srcPrefix != "" {
				a.addOutbound(b, srcPrefix, rec.SrcIP, decoderIdx, p, by)
			}
		}
	}

	// Flow record table — arrival-time semantics (not spread), for top_flows / flow_logs
	if dstPrefix != "" || srcPrefix != "" {
		a.flowRecordTable.Add(rec.SrcIP, rec.DstIP, rec.SrcPort, rec.DstPort,
			rec.Protocol, rec.TCPFlags, realPkts, realBytes)
	}
}

func (a *FlowAggregator) addInbound(b *secondBucket, prefix string, ip net.IP, decoderIdx int, pkts, bytes uint64) {
	ipStr := ip.String()
	d, ok := b.ipStats[ipStr]
	if !ok {
		d = &ipDelta{IP: copyIP(ip)}
		b.ipStats[ipStr] = d
	}
	d.Pkts += pkts
	d.Bytes += bytes
	if decoderIdx >= 0 && decoderIdx < decoder.MaxDecoders {
		d.DecoderPkts[decoderIdx] += uint32(pkts)
		d.DecoderBytes[decoderIdx] += bytes
	}

	pf, ok := b.prefixStats[prefix]
	if !ok {
		pfxIP, pfxLen := parseCIDR(prefix)
		pf = &prefixDelta{Prefix: prefix, PrefixLen: pfxLen, PrefixIP: pfxIP, ActiveIPs: make(map[string]bool)}
		b.prefixStats[prefix] = pf
	}
	pf.Pkts += pkts
	pf.Bytes += bytes
	pf.ActiveIPs[ipStr] = true
	if decoderIdx >= 0 && decoderIdx < decoder.MaxDecoders {
		pf.DecoderPkts[decoderIdx] += uint32(pkts)
		pf.DecoderBytes[decoderIdx] += bytes
	}

	b.globalPkts += pkts
	b.globalBytes += bytes
	if decoderIdx >= 0 && decoderIdx < decoder.MaxDecoders {
		b.globalDecoderPkts[decoderIdx] += uint32(pkts)
		b.globalDecoderBytes[decoderIdx] += bytes
	}
}

func (a *FlowAggregator) addOutbound(b *secondBucket, prefix string, ip net.IP, decoderIdx int, pkts, bytes uint64) {
	ipStr := ip.String()
	d, ok := b.srcIPStats[ipStr]
	if !ok {
		d = &ipDelta{IP: copyIP(ip)}
		b.srcIPStats[ipStr] = d
	}
	d.Pkts += pkts
	d.Bytes += bytes
	if decoderIdx >= 0 && decoderIdx < decoder.MaxDecoders {
		d.DecoderPkts[decoderIdx] += uint32(pkts)
		d.DecoderBytes[decoderIdx] += bytes
	}

	pf, ok := b.srcPrefixStats[prefix]
	if !ok {
		pfxIP, pfxLen := parseCIDR(prefix)
		pf = &prefixDelta{Prefix: prefix, PrefixLen: pfxLen, PrefixIP: pfxIP, ActiveIPs: make(map[string]bool)}
		b.srcPrefixStats[prefix] = pf
	}
	pf.Pkts += pkts
	pf.Bytes += bytes
	pf.ActiveIPs[ipStr] = true
	if decoderIdx >= 0 && decoderIdx < decoder.MaxDecoders {
		pf.DecoderPkts[decoderIdx] += uint32(pkts)
		pf.DecoderBytes[decoderIdx] += bytes
	}

	b.srcGlobalPkts += pkts
	b.srcGlobalBytes += bytes
	if decoderIdx >= 0 && decoderIdx < decoder.MaxDecoders {
		b.srcGlobalDecoderPkts[decoderIdx] += uint32(pkts)
		b.srcGlobalDecoderBytes[decoderIdx] += bytes
	}
}

// Flush pops the bucket for (now - 1) and builds a StatsReport.
// Called every 1 second by the flow mode main loop.
func (a *FlowAggregator) Flush(nodeID, ifaceName string, upstreamRate uint32) *pb.StatsReport {
	return a.FlushAt(time.Now().Unix()-1, nodeID, ifaceName, upstreamRate)
}

// FlushAt pops the bucket at the given unix second and builds a StatsReport.
// Also garbage-collects stale buckets (> staleBucketAge).
func (a *FlowAggregator) FlushAt(ts int64, nodeID, ifaceName string, upstreamRate uint32) *pb.StatsReport {
	a.mu.Lock()
	defer a.mu.Unlock()

	b, ok := a.buckets[ts]
	if ok {
		delete(a.buckets, ts)
	}

	// GC stale buckets
	cutoff := ts - staleBucketAge
	for k := range a.buckets {
		if k < cutoff {
			delete(a.buckets, k)
		}
	}

	if !ok || (len(b.ipStats) == 0 && len(b.srcIPStats) == 0 && b.globalPkts == 0 && b.srcGlobalPkts == 0) {
		return nil
	}

	msg := &pb.StatsReport{
		NodeId:             nodeID,
		InterfaceName:      ifaceName,
		UpstreamSampleRate: upstreamRate,
		LocalSampleRate:    1, // flow mode: no dynamic sampling
		Timestamp:          ts,
		GlobalStats: &pb.GlobalStatsMsg{
			TotalPkts:            b.globalPkts + b.srcGlobalPkts,
			TotalBytes:           b.globalBytes + b.srcGlobalBytes,
			MatchedPkts:          b.globalPkts,
			MatchedBytes:         b.globalBytes,
			DecoderCounts:        trimZeroes32(b.globalDecoderPkts[:]),
			DecoderByteCounts:    trimZeroes64(b.globalDecoderBytes[:]),
			SrcMatchedPkts:       b.srcGlobalPkts,
			SrcMatchedBytes:      b.srcGlobalBytes,
			SrcDecoderCounts:     trimZeroes32(b.srcGlobalDecoderPkts[:]),
			SrcDecoderByteCounts: trimZeroes64(b.srcGlobalDecoderBytes[:]),
		},
		Health: a.collectHealth(),
		SamplingMetrics: a.collectMetrics(),
	}

	// IP stats (inbound)
	for _, d := range b.ipStats {
		msg.IpStats = append(msg.IpStats, &pb.IPStats{
			DstIp:             ipToBytes(d.IP),
			PktCount:          d.Pkts,
			ByteCount:         d.Bytes,
			DecoderCounts:     trimZeroes32(d.DecoderPkts[:]),
			DecoderByteCounts: trimZeroes64(d.DecoderBytes[:]),
		})
	}
	msg.TotalActiveIps = uint32(len(b.ipStats))

	// Prefix stats (inbound)
	for _, d := range b.prefixStats {
		msg.PrefixStats = append(msg.PrefixStats, &pb.PrefixStatsMsg{
			Prefix:            ipToBytes(d.PrefixIP),
			PrefixLen:         d.PrefixLen,
			PktCount:          d.Pkts,
			ByteCount:         d.Bytes,
			ActiveIps:         uint32(len(d.ActiveIPs)),
			DecoderCounts:     trimZeroes32(d.DecoderPkts[:]),
			DecoderByteCounts: trimZeroes64(d.DecoderBytes[:]),
		})
	}

	// Outbound IP stats
	for _, d := range b.srcIPStats {
		msg.SrcIpStats = append(msg.SrcIpStats, &pb.IPStats{
			DstIp:             ipToBytes(d.IP),
			PktCount:          d.Pkts,
			ByteCount:         d.Bytes,
			DecoderCounts:     trimZeroes32(d.DecoderPkts[:]),
			DecoderByteCounts: trimZeroes64(d.DecoderBytes[:]),
		})
	}
	msg.TotalActiveSrcIps = uint32(len(b.srcIPStats))

	// Outbound prefix stats
	for _, d := range b.srcPrefixStats {
		msg.SrcPrefixStats = append(msg.SrcPrefixStats, &pb.PrefixStatsMsg{
			Prefix:            ipToBytes(d.PrefixIP),
			PrefixLen:         d.PrefixLen,
			PktCount:          d.Pkts,
			ByteCount:         d.Bytes,
			ActiveIps:         uint32(len(d.ActiveIPs)),
			DecoderCounts:     trimZeroes32(d.DecoderPkts[:]),
			DecoderByteCounts: trimZeroes64(d.DecoderBytes[:]),
		})
	}

	// Top flows — arrival-time semantics (not spread), for forensic use
	topFlows := a.flowRecordTable.DrainTop(100)
	for _, f := range topFlows {
		msg.TopFlows = append(msg.TopFlows, &pb.FlowSample{
			SrcIp:      ipToBytes(bytesToIP(f.Key.SrcIP)),
			DstIp:      ipToBytes(bytesToIP(f.Key.DstIP)),
			SrcPort:    uint32(f.Key.SrcPort),
			DstPort:    uint32(f.Key.DstPort),
			Protocol:   uint32(f.Key.Protocol),
			TcpFlags:   uint32(f.TCPFlags),
			Packets:    f.Packets,
			BytesTotal: f.Bytes,
		})
	}

	log.Printf("flow-aggregator: flushed ts=%d ips=%d prefixes=%d src_ips=%d global_pps=%d buckets_remaining=%d",
		ts, len(msg.IpStats), len(msg.PrefixStats), len(msg.SrcIpStats), msg.GlobalStats.MatchedPkts, len(a.buckets))

	return msg
}

// --- helpers ---

func copyIP(ip net.IP) net.IP {
	c := make(net.IP, len(ip))
	copy(c, ip)
	return c
}

// bytesToIP converts a [16]byte (from FlowKey) back to net.IP.
// Detects IPv4 (mapped in last 4 bytes, first 12 zero) vs IPv6.
func bytesToIP(b [16]byte) net.IP {
	// Check if it's IPv4-mapped: first 12 bytes are zero (our ipTo16 layout)
	isV4 := true
	for i := 0; i < 12; i++ {
		if b[i] != 0 {
			isV4 = false
			break
		}
	}
	if isV4 {
		return net.IPv4(b[12], b[13], b[14], b[15])
	}
	ip := make(net.IP, 16)
	copy(ip, b[:])
	return ip
}

func ipToBytes(ip net.IP) []byte {
	if ip4 := ip.To4(); ip4 != nil {
		return ip4
	}
	return ip
}

func parseCIDR(cidr string) (net.IP, uint32) {
	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, 0
	}
	ones, _ := ipnet.Mask.Size()
	return ipnet.IP, uint32(ones)
}

// sourceStatusJSON is the per-source status included in NodeHealth.Message.
type sourceStatusJSON struct {
	DeviceIP        string `json:"device_ip"`
	Active          bool   `json:"active"`
	LastSeenAt      int64  `json:"last_seen_at"`
	RecordsReceived int64  `json:"records_received"`
}

// listenerStatusJSON is per-listener metrics included in NodeHealth.Message.
type listenerStatusJSON struct {
	ListenAddr     string `json:"listen_addr"`
	ProtocolMode   string `json:"protocol_mode"`
	RecordsDecoded    int64  `json:"records_decoded"`
	DecodeErrors   int64  `json:"decode_errors"`
	UnknownExporter int64 `json:"unknown_exporter"`
	TemplateMisses int64  `json:"template_misses"`
	SourceCount    int    `json:"source_count"`
}

// collectHealth builds NodeHealth with per-source and per-listener status in Message as JSON.
func (a *FlowAggregator) collectHealth() *pb.NodeHealth {
	now := time.Now().Unix()
	var sources []sourceStatusJSON
	var listeners []listenerStatusJSON
	for _, l := range a.listeners {
		l.mu.RLock()
		for _, s := range l.sources {
			lastSeen := s.LastSeenAt.Load()
			sources = append(sources, sourceStatusJSON{
				DeviceIP:        s.DeviceIP.String(),
				Active:          lastSeen > 0 && (now-lastSeen) < sourceOfflineTimeout,
				LastSeenAt:      lastSeen,
				RecordsReceived: s.RecordsReceived.Load(),
			})
		}
		srcCount := len(l.sources)
		l.mu.RUnlock()

		listeners = append(listeners, listenerStatusJSON{
			ListenAddr:      l.ListenAddr,
			ProtocolMode:    l.ProtocolMode,
			RecordsDecoded:     l.RecordsDecoded.Load(),
			DecodeErrors:    l.DecodeErrors.Load(),
			UnknownExporter: l.UnknownExporter.Load(),
			TemplateMisses:  l.TemplateMisses.Load(),
			SourceCount:     srcCount,
		})
	}

	// Always emit JSON so controller can clear stale state when sources=[]
	payload := map[string]interface{}{"sources": sources, "listeners": listeners}
	msg := `{"sources":[],"listeners":[]}`
	if b, err := json.Marshal(payload); err == nil {
		msg = string(b)
	}
	return &pb.NodeHealth{
		Status:  "healthy",
		Message: msg,
	}
}

// collectMetrics aggregates listener runtime metrics into SamplingMetrics.
//
// Flow mode field mapping (proto reuse):
//   decode_error    → goflow2 decode errors (unmarshal failures)
//   dropped_user    → unknown exporter (unregistered source IP)
//   dropped_kernel  → template misses (NFv9/IPFIX template not yet received)
func (a *FlowAggregator) collectMetrics() *pb.SamplingMetrics {
	m := &pb.SamplingMetrics{}
	for _, l := range a.listeners {
		m.DecodeError += uint64(l.DecodeErrors.Load())
		m.DroppedUser += uint64(l.UnknownExporter.Load())
		m.DroppedKernel += uint64(l.TemplateMisses.Load())
	}
	return m
}

func trimZeroes32(s []uint32) []uint32 {
	n := len(s)
	for n > 0 && s[n-1] == 0 {
		n--
	}
	if n == 0 {
		return nil
	}
	out := make([]uint32, n)
	copy(out, s[:n])
	return out
}

func trimZeroes64(s []uint64) []uint64 {
	n := len(s)
	for n > 0 && s[n-1] == 0 {
		n--
	}
	if n == 0 {
		return nil
	}
	out := make([]uint64, n)
	copy(out, s[:n])
	return out
}
