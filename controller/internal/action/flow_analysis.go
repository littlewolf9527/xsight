// Package action — flow_analysis.go aggregates flow_logs data for dynamic
// response parameters ({top_src_ips}, {dominant_src_port}, etc.)
//
package action

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/littlewolf9527/xsight/controller/internal/store"
)

// FlowAnalysis holds aggregated flow data for response dynamic parameters.
type FlowAnalysis struct {
	TopSrcIPs          []string // top-5 source IPs by packets
	TopSrcPorts        []int    // top-5 source ports
	TopDstPorts        []int    // top-5 destination ports
	DominantSrcPort    int      // highest-packet source port
	DominantSrcPortPct int      // percentage (0-100)
	DominantDstPort    int      // highest-packet destination port
	DominantDstPortPct int      // percentage (0-100)
	UniqueSrcIPs       int      // count of distinct source IPs
	FlowSummaryJSON    string   // JSON array of top flows
}

type kv struct {
	Key   string
	Count int64
}

// analyzeFlows queries flow_logs for the attack's time window and aggregates top-N stats.
func analyzeFlows(ctx context.Context, s store.Store, attack *store.Attack) *FlowAnalysis {
	to := time.Now()
	if attack.EndedAt != nil {
		to = *attack.EndedAt
	}

	filter := store.FlowLogFilter{
		DstIP: attack.DstIP,
		From:  attack.StartedAt,
		To:    to,
		Limit: 10000,
	}
	// Outbound attacks: DstIP is the internal source IP — query by src_ip instead
	var flows []store.FlowLog
	var err error
	if attack.Direction == "sends" {
		flows, err = s.FlowLogs().QueryBySrcIP(ctx, filter)
	} else {
		flows, err = s.FlowLogs().QueryByDstIP(ctx, filter)
	}
	if err != nil || len(flows) == 0 {
		return nil
	}

	// Aggregate by src_ip, src_port, dst_port — weighted by packets
	srcIPMap := map[string]int64{}
	srcPortMap := map[string]int64{}
	dstPortMap := map[string]int64{}
	var totalPackets int64

	for _, f := range flows {
		srcIPMap[f.SrcIP] += f.Packets
		srcPortMap[strconv.Itoa(f.SrcPort)] += f.Packets
		dstPortMap[strconv.Itoa(f.DstPort)] += f.Packets
		totalPackets += f.Packets
	}

	topSrcIPs := topN(srcIPMap, 5)
	topSrcPorts := topN(srcPortMap, 5)
	topDstPorts := topN(dstPortMap, 5)

	a := &FlowAnalysis{
		UniqueSrcIPs: len(srcIPMap),
	}

	for _, v := range topSrcIPs {
		a.TopSrcIPs = append(a.TopSrcIPs, v.Key)
	}
	for _, v := range topSrcPorts {
		p, err := strconv.Atoi(v.Key)
		if err != nil {
			log.Printf("flow_analysis: skip non-numeric src_port %q: %v", v.Key, err)
			continue
		}
		a.TopSrcPorts = append(a.TopSrcPorts, p)
	}
	for _, v := range topDstPorts {
		p, err := strconv.Atoi(v.Key)
		if err != nil {
			log.Printf("flow_analysis: skip non-numeric dst_port %q: %v", v.Key, err)
			continue
		}
		a.TopDstPorts = append(a.TopDstPorts, p)
	}

	if len(a.TopSrcPorts) > 0 && totalPackets > 0 {
		a.DominantSrcPort = a.TopSrcPorts[0]
		a.DominantSrcPortPct = int(topSrcPorts[0].Count * 100 / totalPackets)
	}
	if len(a.TopDstPorts) > 0 && totalPackets > 0 {
		a.DominantDstPort = a.TopDstPorts[0]
		a.DominantDstPortPct = int(topDstPorts[0].Count * 100 / totalPackets)
	}

	// Build flow summary JSON (top 20 flows from query result, already sorted by packets desc)
	limit := 20
	if len(flows) < limit {
		limit = len(flows)
	}
	type flowEntry struct {
		SrcIP    string `json:"src"`
		DstIP    string `json:"dst"`
		SrcPort  int    `json:"sport"`
		DstPort  int    `json:"dport"`
		Protocol int    `json:"proto"`
		Packets  int64  `json:"packets"`
		Bytes    int64  `json:"bytes"`
	}
	summary := make([]flowEntry, limit)
	for i := 0; i < limit; i++ {
		summary[i] = flowEntry{
			SrcIP:    flows[i].SrcIP,
			DstIP:    flows[i].DstIP,
			SrcPort:  flows[i].SrcPort,
			DstPort:  flows[i].DstPort,
			Protocol: flows[i].Protocol,
			Packets:  flows[i].Packets,
			Bytes:    flows[i].Bytes,
		}
	}
	if b, err := json.Marshal(summary); err == nil {
		a.FlowSummaryJSON = string(b)
	}

	return a
}

func topN(m map[string]int64, n int) []kv {
	items := make([]kv, 0, len(m))
	for k, v := range m {
		items = append(items, kv{k, v})
	}
	sort.Slice(items, func(i, j int) bool { return items[i].Count > items[j].Count })
	if len(items) > n {
		items = items[:n]
	}
	return items
}

// flowVarPrefixes lists substrings that indicate flow-derived variable usage.
var flowVarPrefixes = []string{
	"{top_src_ips}", "{top_src_ports}", "{top_dst_ports}",
	"{dominant_src_port}", "{dominant_src_port_pct}",
	"{dominant_dst_port}", "{dominant_dst_port_pct}",
	"{src_ip}", "{unique_src_ips}", "{flow_summary_json}",
}

// flowPreconditionAttrs lists precondition attributes that require flow data.
var flowPreconditionAttrs = map[string]bool{
	"dominant_src_port":     true,
	"dominant_src_port_pct": true,
	"dominant_dst_port":     true,
	"dominant_dst_port_pct": true,
	"unique_src_ips":        true,
}

// actionNeedsFlowData checks if an action needs FlowAnalysis for execution.
// This covers: webhook connector auto-payload enrichment, and flow variable
// references ({top_src_ips} etc.) in action config / xDrop custom payload / shell args.
// Note: flow-dependent preconditions are handled separately via lazy getFA() in
// checkAllPreconditions, not by this function.
func actionNeedsFlowData(act store.ResponseAction) bool {
	// Connector-based webhooks always get flow fields in auto-payload
	if act.ActionType == "webhook" && act.WebhookConnectorID != nil {
		return true
	}

	// Check action config / custom payload / shell args for flow variable references
	searchable := string(act.Config) + string(act.XDropCustomPayload) + act.ShellExtraArgs
	for _, v := range flowVarPrefixes {
		if strings.Contains(searchable, v) {
			return true
		}
	}

	return false
}

// flowAnalysisReplacements returns key-value pairs for strings.NewReplacer.
func flowAnalysisReplacements(fa *FlowAnalysis) []string {
	if fa == nil {
		return []string{
			"{top_src_ips}", "",
			"{top_src_ports}", "",
			"{top_dst_ports}", "",
			"{dominant_src_port}", "",
			"{dominant_src_port_pct}", "",
			"{dominant_dst_port}", "",
			"{dominant_dst_port_pct}", "",
			"{src_ip}", "",
			"{unique_src_ips}", "0",
			"{flow_summary_json}", "[]",
		}
	}

	srcPorts := make([]string, len(fa.TopSrcPorts))
	for i, p := range fa.TopSrcPorts {
		srcPorts[i] = strconv.Itoa(p)
	}
	dstPorts := make([]string, len(fa.TopDstPorts))
	for i, p := range fa.TopDstPorts {
		dstPorts[i] = strconv.Itoa(p)
	}

	srcIP := ""
	if len(fa.TopSrcIPs) > 0 {
		srcIP = fa.TopSrcIPs[0]
	}

	return []string{
		"{top_src_ips}", strings.Join(fa.TopSrcIPs, ","),
		"{top_src_ports}", strings.Join(srcPorts, ","),
		"{top_dst_ports}", strings.Join(dstPorts, ","),
		"{dominant_src_port}", strconv.Itoa(fa.DominantSrcPort),
		"{dominant_src_port_pct}", fmt.Sprintf("%d", fa.DominantSrcPortPct),
		"{dominant_dst_port}", strconv.Itoa(fa.DominantDstPort),
		"{dominant_dst_port_pct}", fmt.Sprintf("%d", fa.DominantDstPortPct),
		"{src_ip}", srcIP,
		"{unique_src_ips}", strconv.Itoa(fa.UniqueSrcIPs),
		"{flow_summary_json}", fa.FlowSummaryJSON,
	}
}
