// Package ingestion — flow_writer.go converts FlowSample from StatsReport
// into flow_logs DB rows and bulk-inserts them asynchronously.
//
package ingestion

import (
	"context"
	"log"
	"net"
	"time"

	"github.com/littlewolf9527/xsight/controller/internal/netutil"
	pb "github.com/littlewolf9527/xsight/controller/internal/pb"
	"github.com/littlewolf9527/xsight/controller/internal/store"
)

// FlowWriter receives StatsReports and bulk-inserts top_flows into flow_logs.
type FlowWriter struct {
	repo store.FlowLogRepo
	ch   chan flowBatch
}

type flowBatch struct {
	flows []store.FlowLog
}

// NewFlowWriter creates a FlowWriter that writes to the given repo.
// Starts a background goroutine for async inserts.
func NewFlowWriter(repo store.FlowLogRepo) *FlowWriter {
	w := &FlowWriter{
		repo: repo,
		ch:   make(chan flowBatch, 16),
	}
	go w.run()
	return w
}

// HandleFlows extracts top_flows from a StatsReport, matches dst_ip to prefix,
// and enqueues for bulk insert.
func (w *FlowWriter) HandleFlows(nodeID string, report *pb.StatsReport) {
	flows := report.GetTopFlows()
	if len(flows) == 0 {
		return
	}
	// Debug log removed — high volume

	ts := time.Unix(report.Timestamp, 0)

	// Build prefix nets from the same report for dst_ip→prefix matching
	var prefixNets []parsedPrefix
	for _, ps := range report.PrefixStats {
		cidr := netutil.FormatPrefix(ps.Prefix, ps.PrefixLen)
		_, ipnet, err := net.ParseCIDR(cidr)
		if err != nil {
			continue
		}
		prefixNets = append(prefixNets, parsedPrefix{cidr, ipnet})
	}

	logs := make([]store.FlowLog, 0, len(flows))
	for _, f := range flows {
		srcIP := net.IP(f.SrcIp)
		dstIP := net.IP(f.DstIp)

		var prefix *string
		if p := matchPrefix(prefixNets, dstIP); p != "" {
			prefix = &p
		}

		logs = append(logs, store.FlowLog{
			Time:     ts,
			NodeID:   nodeID,
			Prefix:   prefix,
			SrcIP:    srcIP.String(),
			DstIP:    dstIP.String(),
			SrcPort:  int(f.SrcPort),
			DstPort:  int(f.DstPort),
			Protocol: int(f.Protocol),
			TCPFlags: int(f.TcpFlags),
			Packets:  int64(f.Packets),
			Bytes:    int64(f.BytesTotal),
		})
	}

	// Non-blocking enqueue
	select {
	case w.ch <- flowBatch{flows: logs}:
	default:
		log.Printf("flow_writer: queue full, dropping %d flow logs", len(logs))
	}
}

func (w *FlowWriter) run() {
	for batch := range w.ch {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		if err := w.repo.BulkInsert(ctx, batch.flows); err != nil {
			log.Printf("flow_writer: bulk insert error (%d flows): %v", len(batch.flows), err)
		}
		cancel()
	}
}
