// Package reporter — convert.go maps internal types to protobuf messages.
package reporter

import (
	"time"

	"github.com/littlewolf9527/xsight/node/internal/collector"
	"github.com/littlewolf9527/xsight/node/internal/pb"
	"github.com/littlewolf9527/xsight/node/internal/sampler"
)

func reportToProto(
	r *collector.Report,
	nodeID, ifaceName string,
	upstreamRate, gapSeconds uint32,
	bt *sampler.Batcher,
	batchSendLatencyMs float32,
) *pb.StatsReport {
	msg := &pb.StatsReport{
		NodeId:             nodeID,
		InterfaceName:      ifaceName,
		UpstreamSampleRate: upstreamRate,
		LocalSampleRate:    r.SampleRate,
		Timestamp:          r.Timestamp.Unix(),
		IpStatsTruncated:   r.Truncated,
		TotalActiveIps:     uint32(r.TotalActiveIPs),
		GapSeconds:         gapSeconds,
		GlobalStats: &pb.GlobalStatsMsg{
			TotalPkts:            r.Global.TotalPkts,
			TotalBytes:           r.Global.TotalBytes,
			MatchedPkts:          r.Global.MatchedPkts,
			MatchedBytes:         r.Global.MatchedBytes,
			DecoderCounts:        trimZeroes(r.Global.DecoderCounts[:]),
			DecoderByteCounts:    trimZeroes64(r.Global.DecoderByteCounts[:]),
			SrcMatchedPkts:       r.Global.SrcMatchedPkts,
			SrcMatchedBytes:      r.Global.SrcMatchedBytes,
			SrcDecoderCounts:     trimZeroes(r.Global.SrcDecoderCounts[:]),
			SrcDecoderByteCounts: trimZeroes64(r.Global.SrcDecoderByteCounts[:]),
		},
		Health: &pb.NodeHealth{
			Status:  r.Health.Status,
			Message: r.Health.Message,
		},
	}

	// SamplingMetrics from global_stats (BPF) + batcher (userspace) + reporter (latency)
	metrics := &pb.SamplingMetrics{
		EffectiveSampleRate: float32(r.SampleRate),
		DroppedKernel:       r.Global.SampleDrops, // from BPF global_stats.sample_drops
		BatchSendLatencyMs:  batchSendLatencyMs,
		// ring_fill_ratio: reserved — kernel ringbuf doesn't expose fill level to userspace;
		// sample_drops serves as the practical backpressure signal instead.
	}
	if bt != nil {
		metrics.DroppedUser = bt.Metrics.DroppedUser.Load()
		metrics.DecodeError = bt.Metrics.DecodeErrors.Load()
	}
	msg.SamplingMetrics = metrics

	// IP deltas
	for _, d := range r.IPDeltas {
		ip := collector.LPMKeyToIP(d.Key)
		msg.IpStats = append(msg.IpStats, &pb.IPStats{
			DstIp:             ip,
			PktCount:          d.Stats.PktCount,
			ByteCount:         d.Stats.ByteCount,
			DecoderCounts:     trimZeroes(d.Stats.DecoderCounts[:]),
			DecoderByteCounts: trimZeroes64(d.Stats.DecoderByteCounts[:]),
			SmallPkt:          d.Stats.SmallPkt,
			MediumPkt:         d.Stats.MediumPkt,
			LargePkt:          d.Stats.LargePkt,
		})
	}

	// Prefix deltas
	for _, d := range r.PrefixDeltas {
		n := collector.PrefixKeyToIPNet(d.Key)
		msg.PrefixStats = append(msg.PrefixStats, &pb.PrefixStatsMsg{
			Prefix:            n.IP,
			PrefixLen:         d.Key.Prefixlen,
			PktCount:          d.Stats.PktCount,
			ByteCount:         d.Stats.ByteCount,
			ActiveIps:         d.ActiveIPs,
			OverflowCount:     d.Stats.OverflowCount,
			DecoderCounts:     trimZeroes(d.Stats.DecoderCounts[:]),
			DecoderByteCounts: trimZeroes64(d.Stats.DecoderByteCounts[:]),
		})
	}

	// v2.11 Phase 2: outbound (src_ip matched) deltas
	for _, d := range r.SrcIPDeltas {
		ip := collector.LPMKeyToIP(d.Key)
		msg.SrcIpStats = append(msg.SrcIpStats, &pb.IPStats{
			DstIp:             ip, // reuse dst_ip bytes field for src_ip
			PktCount:          d.Stats.PktCount,
			ByteCount:         d.Stats.ByteCount,
			DecoderCounts:     trimZeroes(d.Stats.DecoderCounts[:]),
			DecoderByteCounts: trimZeroes64(d.Stats.DecoderByteCounts[:]),
			SmallPkt:          d.Stats.SmallPkt,
			MediumPkt:         d.Stats.MediumPkt,
			LargePkt:          d.Stats.LargePkt,
		})
	}
	for _, d := range r.SrcPrefixDeltas {
		n := collector.PrefixKeyToIPNet(d.Key)
		msg.SrcPrefixStats = append(msg.SrcPrefixStats, &pb.PrefixStatsMsg{
			Prefix:            n.IP,
			PrefixLen:         d.Key.Prefixlen,
			PktCount:          d.Stats.PktCount,
			ByteCount:         d.Stats.ByteCount,
			ActiveIps:         d.ActiveIPs,
			OverflowCount:     d.Stats.OverflowCount,
			DecoderCounts:     trimZeroes(d.Stats.DecoderCounts[:]),
			DecoderByteCounts: trimZeroes64(d.Stats.DecoderByteCounts[:]),
		})
	}
	msg.SrcIpStatsTruncated = r.SrcTruncated
	msg.TotalActiveSrcIps = uint32(r.TotalActiveSrcIPs)

	// Top flows from flow table
	for _, f := range r.TopFlows {
		srcIP := flowKeyIP(f.Key.SrcIP)
		dstIP := flowKeyIP(f.Key.DstIP)
		msg.TopFlows = append(msg.TopFlows, &pb.FlowSample{
			SrcIp:      srcIP,
			DstIp:      dstIP,
			SrcPort:    uint32(f.Key.SrcPort),
			DstPort:    uint32(f.Key.DstPort),
			Protocol:   uint32(f.Key.Protocol),
			TcpFlags:   uint32(f.Stats.TCPFlags),
			Packets:    f.Stats.Packets,
			BytesTotal: f.Stats.Bytes,
		})
	}

	return msg
}

// flowKeyIP extracts a net.IP (4 or 16 bytes) from a [16]byte flow key address.
// IPv4 addresses are stored in the first 4 bytes with bytes 4-15 all zero.
// Returns a new slice (safe for protobuf assignment).
func flowKeyIP(addr [16]byte) []byte {
	// Check if it's IPv4 (bytes 4-15 all zero)
	isV4 := true
	for i := 4; i < 16; i++ {
		if addr[i] != 0 {
			isV4 = false
			break
		}
	}
	if isV4 {
		ip := make([]byte, 4)
		copy(ip, addr[:4])
		return ip
	}
	ip := make([]byte, 16)
	copy(ip, addr[:])
	return ip
}

// trimZeroes returns a slice trimmed of trailing zero values.
// Reduces protobuf wire size when only the first N decoders are active.
func trimZeroes(s []uint32) []uint32 {
	n := len(s)
	for n > 0 && s[n-1] == 0 {
		n--
	}
	return s[:n]
}

func trimZeroes64(s []uint64) []uint64 {
	n := len(s)
	for n > 0 && s[n-1] == 0 {
		n--
	}
	return s[:n]
}

func batchToProto(batch []sampler.PacketSample, nodeID, ifaceName string, upstreamRate, localRate uint32) *pb.SampleBatch {
	msg := &pb.SampleBatch{
		NodeId:             nodeID,
		InterfaceName:      ifaceName,
		UpstreamSampleRate: upstreamRate,
		LocalSampleRate:    localRate,
		Timestamp:          time.Now().Unix(),
	}

	for _, ps := range batch {
		msg.Samples = append(msg.Samples, &pb.PacketSample{
			RawHeader:      ps.RawHeader,
			SrcIp:          ps.SrcIP,
			DstIp:          ps.DstIP,
			IpProtocol:     ps.Protocol,
			SrcPort:        ps.SrcPort,
			DstPort:        ps.DstPort,
			PacketLength:   ps.PacketLength,
			TcpFlags:       ps.TCPFlags,
			IpTtl:          ps.TTL,
			FragmentOffset: ps.FragmentOffset,
			IcmpType:       ps.ICMPType,
			IcmpCode:       ps.ICMPCode,
		})
	}

	return msg
}
