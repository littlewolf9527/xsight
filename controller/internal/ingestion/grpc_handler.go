package ingestion

import (
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"sync"
	"sync/atomic"

	"google.golang.org/grpc"
	"google.golang.org/grpc/peer"
	"google.golang.org/protobuf/types/known/emptypb"

	pb "github.com/littlewolf9527/xsight/controller/internal/pb"
	"github.com/littlewolf9527/xsight/controller/internal/store"
)

// StatsCallback is invoked for each received StatsReport.
type StatsCallback func(nodeID string, report *pb.StatsReport)

// CriticalEventCallback is invoked for each CriticalEvent.
type CriticalEventCallback func(nodeID string, event *pb.CriticalEvent)

// GRPCHandler implements pb.XSightServiceServer.
type GRPCHandler struct {
	pb.UnimplementedXSightServiceServer

	store      store.Store
	nodeState  *NodeState
	samplePool *SampleWorkerPool
	onStats    StatsCallback
	onCritical CriticalEventCallback

	// Peer → nodeID mapping (set during Handshake, used by ControlStream)
	peerNodes   map[string]string // peer address → nodeID
	peerNodesMu sync.RWMutex

	// Metrics
	StatsReceived   atomic.Uint64
	StatsDropped    atomic.Uint64 // reports dropped due to processing queue full
	SamplesReceived atomic.Uint64
	EventsReceived  atomic.Uint64
}

type GRPCHandlerConfig struct {
	Store      store.Store
	NodeState  *NodeState
	SamplePool *SampleWorkerPool
	OnStats    StatsCallback
	OnCritical CriticalEventCallback
}

func NewGRPCHandler(cfg GRPCHandlerConfig) *GRPCHandler {
	return &GRPCHandler{
		store:      cfg.Store,
		nodeState:  cfg.NodeState,
		samplePool: cfg.SamplePool,
		onStats:    cfg.OnStats,
		onCritical: cfg.OnCritical,
		peerNodes:  make(map[string]string),
	}
}

// peerAddr extracts the remote address from the gRPC context.
func peerAddr(ctx context.Context) string {
	if p, ok := peer.FromContext(ctx); ok {
		return p.Addr.String()
	}
	return ""
}

// --- 1.2 Handshake ---

func (h *GRPCHandler) Handshake(ctx context.Context, req *pb.NodeHandshake) (*pb.HandshakeResponse, error) {
	log.Printf("grpc: handshake from node_id=%s interfaces=%v", req.NodeId, req.Interfaces)

	node, err := h.store.Nodes().Get(ctx, req.NodeId)
	if err != nil {
		log.Printf("grpc: handshake reject: node %q not found: %v", req.NodeId, err)
		return &pb.HandshakeResponse{Accepted: false, RejectReason: "node not found"}, nil
	}
	if node.APIKey != req.ApiKey {
		log.Printf("grpc: handshake reject: node %q bad api_key", req.NodeId)
		return &pb.HandshakeResponse{Accepted: false, RejectReason: "invalid api_key"}, nil
	}
	if !node.Enabled {
		return &pb.HandshakeResponse{Accepted: false, RejectReason: "node disabled"}, nil
	}

	// Register peer → nodeID mapping for ControlStream identification
	if addr := peerAddr(ctx); addr != "" {
		h.peerNodesMu.Lock()
		h.peerNodes[addr] = req.NodeId
		h.peerNodesMu.Unlock()
	}

	watchConfig, err := h.buildWatchConfig(ctx)
	if err != nil {
		log.Printf("grpc: handshake build watch config: %v", err)
		return &pb.HandshakeResponse{Accepted: false, RejectReason: fmt.Sprintf("internal error: %v", err)}, nil
	}
	// Update node mode from handshake (xdp nodes send "" or "xdp", flow nodes send "flow")
	mode := req.Mode
	if mode == "" {
		mode = "xdp"
	}
	if mode != "xdp" && mode != "flow" {
		return &pb.HandshakeResponse{Accepted: false, RejectReason: fmt.Sprintf("invalid mode: %q (must be xdp or flow)", mode)}, nil
	}
	_ = h.store.Nodes().UpdateMode(ctx, req.NodeId, mode)

	// Append per-node flow config (only for flow-mode nodes)
	if mode == "flow" {
		if err := h.appendFlowConfig(ctx, watchConfig, req.NodeId); err != nil {
			log.Printf("grpc: handshake flow config for %s failed: %v", req.NodeId, err)
			// Continue with handshake but without flow config — node will retry on next connect
		}
	}

	// If this node has never received a config publish (version=0),
	// catch it up to the current max version so it can ACK and become synced.
	version := node.DeliveryVersionCurrent
	if version == 0 {
		allNodes, _ := h.store.Nodes().List(ctx)
		var maxVer int64
		for _, n := range allNodes {
			if n.DeliveryVersionCurrent > maxVer {
				maxVer = n.DeliveryVersionCurrent
			}
		}
		if maxVer > 0 {
			version = maxVer
			_ = h.store.Nodes().UpdateDeliveryVersionCurrent(ctx, req.NodeId, version)
			log.Printf("grpc: handshake: caught up node %s to version=%d", req.NodeId, version)
		}
	}

	log.Printf("grpc: handshake accepted: node=%s prefixes=%d delivery_version=%d",
		req.NodeId, len(watchConfig.Prefixes), version)

	return &pb.HandshakeResponse{
		Accepted:               true,
		WatchConfig:            watchConfig,
		DeliveryVersionCurrent: uint64(version),
	}, nil
}

func (h *GRPCHandler) buildWatchConfig(ctx context.Context) (*pb.WatchConfig, error) {
	prefixes, err := h.store.Prefixes().List(ctx)
	if err != nil {
		return nil, err
	}

	var wp []*pb.WatchPrefix
	for _, p := range prefixes {
		if !p.Enabled {
			continue
		}
		// 0.0.0.0/0 is a virtual global prefix — do NOT push to BPF trie.
		if p.Prefix == "0.0.0.0/0" {
			continue
		}
		_, ipnet, err := net.ParseCIDR(p.Prefix)
		if err != nil {
			log.Printf("grpc: skip bad prefix %q: %v", p.Prefix, err)
			continue
		}
		ones, _ := ipnet.Mask.Size()
		wp = append(wp, &pb.WatchPrefix{
			Prefix:    ipnet.IP,
			PrefixLen: uint32(ones),
			Name:      p.Name,
		})
	}

	// Load aggregated hard thresholds from DB: lowest per-IP pps/bps
	allThresholds, _ := h.store.Thresholds().List(ctx)
	var minPPS, minBPS int64
	for _, th := range allThresholds {
		if !th.Enabled || th.Comparison != "over" || th.Domain != "internal_ip" {
			continue
		}
		if th.Unit == "pps" && th.Value > 0 && (minPPS == 0 || th.Value < minPPS) {
			minPPS = th.Value
		}
		if th.Unit == "bps" && th.Value > 0 && (minBPS == 0 || th.Value < minBPS) {
			minBPS = th.Value
		}
	}
	if minPPS == 0 {
		minPPS = 1_000_000
	}
	if minBPS == 0 {
		minBPS = 10_000_000_000
	}

	return &pb.WatchConfig{
		Prefixes: wp,
		HardThresholds: &pb.HardThresholds{
			Pps: uint64(minPPS),
			Bps: uint64(minBPS),
		},
	}, nil
}

// appendFlowConfig adds per-node flow listener/source config to a WatchConfig.
// Returns error if DB read fails.
func (h *GRPCHandler) appendFlowConfig(ctx context.Context, wc *pb.WatchConfig, nodeID string) error {
	listeners, err := h.store.FlowListeners().List(ctx, nodeID)
	if err != nil {
		return fmt.Errorf("load flow_listeners for %s: %w", nodeID, err)
	}
	for _, l := range listeners {
		if !l.Enabled {
			continue
		}
		flc := &pb.FlowListenerConfig{
			ListenAddress: l.ListenAddress,
			ProtocolMode:  l.ProtocolMode,
			Enabled:       l.Enabled,
		}
		sources, err := h.store.FlowSources().List(ctx, l.ID)
		if err != nil {
			return fmt.Errorf("load flow_sources for listener %d: %w", l.ID, err)
		}
		for _, s := range sources {
			if !s.Enabled {
				continue
			}
			flc.Sources = append(flc.Sources, &pb.FlowSourceConfig{
				DeviceIp:   s.DeviceIP,
				SampleMode: s.SampleMode,
				SampleRate: int32(s.SampleRate),
				Name:       s.Name,
				Enabled:    s.Enabled,
			})
		}
		wc.FlowListeners = append(wc.FlowListeners, flc)
	}
	return nil
}

// --- 1.3 StatsStream ---

func (h *GRPCHandler) StatsStream(stream grpc.ClientStreamingServer[pb.StatsReport, emptypb.Empty]) error {
	// Decouple Recv from processing: Recv into a bounded queue,
	// process in a separate goroutine. This prevents slow onStats
	// (e.g. ring lock contention) from blocking gRPC stream Recv.
	const queueSize = 16
	queue := make(chan *pb.StatsReport, queueSize)
	done := make(chan error, 1)

	// Processing goroutine
	go func() {
		for msg := range queue {
			if h.onStats != nil {
				h.onStats(msg.NodeId, msg)
			}
		}
		done <- nil
	}()

	// Recv loop — fast, only touches lightweight fields
	var recvErr error
	for {
		msg, err := stream.Recv()
		if err == io.EOF {
			close(queue)
			<-done
			return stream.SendAndClose(&emptypb.Empty{})
		}
		if err != nil {
			recvErr = err
			break
		}

		h.StatsReceived.Add(1)

		if msg.GapSeconds > 0 {
			log.Printf("grpc: stats node=%s gap=%ds (reconnect)", msg.NodeId, msg.GapSeconds)
		}
		if msg.IpStatsTruncated {
			log.Printf("grpc: stats node=%s ip_stats truncated (total_active=%d, reported=%d)",
				msg.NodeId, msg.TotalActiveIps, len(msg.IpStats))
		}

		select {
		case queue <- msg:
		default:
			// Queue full — drop oldest to keep Recv flowing
			h.StatsDropped.Add(1)
			select {
			case <-queue:
			default:
			}
			queue <- msg
			log.Printf("grpc: stats queue full for node=%s, dropped report (total_dropped=%d)",
				msg.NodeId, h.StatsDropped.Load())
		}
		// Always touch online status — msg is enqueued in both paths
		h.nodeState.TouchStats(msg.NodeId)
	}

	close(queue)
	<-done
	return recvErr
}

// --- 1.4 SampleStream ---

func (h *GRPCHandler) SampleStream(stream grpc.ClientStreamingServer[pb.SampleBatch, emptypb.Empty]) error {
	for {
		msg, err := stream.Recv()
		if err == io.EOF {
			return stream.SendAndClose(&emptypb.Empty{})
		}
		if err != nil {
			return err
		}

		h.SamplesReceived.Add(uint64(len(msg.Samples)))

		if h.samplePool != nil {
			h.samplePool.Submit(msg.NodeId, msg)
		}
	}
}

// --- 1.5 CriticalEventStream ---

func (h *GRPCHandler) CriticalEventStream(stream grpc.ClientStreamingServer[pb.CriticalEvent, emptypb.Empty]) error {
	for {
		msg, err := stream.Recv()
		if err == io.EOF {
			return stream.SendAndClose(&emptypb.Empty{})
		}
		if err != nil {
			return err
		}

		h.EventsReceived.Add(1)
		log.Printf("grpc: critical event node=%s type=%s dst=%v",
			msg.NodeId, msg.EventType, net.IP(msg.DstIp))

		if h.onCritical != nil {
			h.onCritical(msg.NodeId, msg)
		}
	}
}

// --- 1.6 ControlStream ---

func (h *GRPCHandler) ControlStream(stream grpc.BidiStreamingServer[pb.ControlMessage, pb.ControlMessage]) error {
	// Resolve nodeID from peer address (registered during Handshake).
	addr := peerAddr(stream.Context())
	h.peerNodesMu.RLock()
	nodeID := h.peerNodes[addr]
	h.peerNodesMu.RUnlock()

	if nodeID != "" {
		h.nodeState.SetControlStream(nodeID, stream)
		log.Printf("grpc: control stream opened for node=%s (peer=%s)", nodeID, addr)
	} else {
		log.Printf("grpc: control stream opened from unknown peer=%s (no prior handshake?)", addr)
	}

	defer func() {
		if nodeID != "" {
			h.nodeState.ClearControlStream(nodeID)
			log.Printf("grpc: control stream closed for node=%s", nodeID)
		}
		// Clean up peer mapping
		if addr != "" {
			h.peerNodesMu.Lock()
			delete(h.peerNodes, addr)
			h.peerNodesMu.Unlock()
		}
	}()

	for {
		msg, err := stream.Recv()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}

		switch p := msg.Payload.(type) {
		case *pb.ControlMessage_ConfigAck:
			ack := p.ConfigAck
			log.Printf("grpc: control ConfigAck node=%s version=%d success=%v",
				nodeID, ack.DeliveryVersionApplied, ack.Success)

			if nodeID == "" {
				continue
			}

			ctx := stream.Context()
			if ack.Success {
				if err := h.store.Nodes().UpdateACK(ctx, nodeID, int64(ack.DeliveryVersionApplied)); err != nil {
					log.Printf("grpc: update ACK for node %s: %v", nodeID, err)
				}
			} else {
				log.Printf("grpc: node %s config apply failed: %s", nodeID, ack.ErrorMessage)
			}
		}
	}
}

// SendConfigPush sends a ConfigPush to a specific node via its ControlStream.
func (h *GRPCHandler) SendConfigPush(nodeID string, config *pb.WatchConfig, version uint64) error {
	stream := h.nodeState.GetControlStream(nodeID)
	if stream == nil {
		return fmt.Errorf("node %s not connected", nodeID)
	}
	return stream.Send(&pb.ControlMessage{
		Payload: &pb.ControlMessage_ConfigPush{
			ConfigPush: &pb.ConfigPush{
				WatchConfig:            config,
				DeliveryVersionCurrent: version,
			},
		},
	})
}
