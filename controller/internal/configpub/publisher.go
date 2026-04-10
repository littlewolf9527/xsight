// Package configpub manages configuration publication to XDP Nodes.
package configpub

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	pb "github.com/littlewolf9527/xsight/controller/internal/pb"
	"github.com/littlewolf9527/xsight/controller/internal/store"
)

// NodePusher is the interface for sending ConfigPush to a Node.
// Implemented by GRPCHandler.SendConfigPush.
type NodePusher interface {
	SendConfigPush(nodeID string, config *pb.WatchConfig, version uint64) error
}

// Publisher manages the config publication lifecycle:
//   - Builds WatchConfig from DB state
//   - Increments delivery_version_current
//   - Pushes to all connected Nodes via ControlStream
//   - Tracks ACK status and drift
type Publisher struct {
	mu     sync.Mutex
	store  store.Store
	pusher NodePusher

	// Connected nodes (set externally from NodeState)
	connectedNodes func() []string
}

func New(s store.Store, pusher NodePusher, connectedNodes func() []string) *Publisher {
	return &Publisher{
		store:          s,
		pusher:         pusher,
		connectedNodes: connectedNodes,
	}
}

// Publish builds a WatchConfig from the current DB state and pushes it to all
// connected Nodes. Called when watch_prefixes/thresholds/responses change.
// Returns the new delivery_version.
func (p *Publisher) Publish(ctx context.Context, auditUserID *int, entityType, entityID, action string, diff json.RawMessage) (int64, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	// Build WatchConfig from current DB state
	watchConfig, err := p.buildWatchConfig(ctx)
	if err != nil {
		return 0, fmt.Errorf("build watch config: %w", err)
	}

	// Compute a single global delivery_version: max(all nodes' current) + 1
	nodes, err := p.store.Nodes().List(ctx)
	if err != nil {
		return 0, fmt.Errorf("list nodes: %w", err)
	}

	var maxVersion int64
	for _, node := range nodes {
		if node.DeliveryVersionCurrent > maxVersion {
			maxVersion = node.DeliveryVersionCurrent
		}
	}
	newVersion := maxVersion + 1

	// Set the same version on ALL enabled nodes
	for _, node := range nodes {
		if !node.Enabled {
			continue
		}
		if err := p.store.Nodes().UpdateDeliveryVersionCurrent(ctx, node.ID, newVersion); err != nil {
			log.Printf("configpub: update version for node %s: %v", node.ID, err)
		}
	}

	// Write audit log
	if err := p.store.AuditLog().Create(ctx, &store.AuditLog{
		UserID:          auditUserID,
		EntityType:      entityType,
		EntityID:        entityID,
		Action:          action,
		Diff:            diff,
		DeliveryVersion: &newVersion,
	}); err != nil {
		log.Printf("configpub: audit log: %v", err)
	}

	// Push to all connected Nodes (per-node config includes flow_listeners scoped to that node)
	connectedIDs := p.connectedNodes()
	pushed := 0
	// Pre-load node modes for mode-aware push
	allNodes, _ := p.store.Nodes().List(ctx)
	nodeModes := make(map[string]string, len(allNodes))
	for _, n := range allNodes {
		nodeModes[n.ID] = n.Mode
	}

	for _, nodeID := range connectedIDs {
		// Clone base config + append per-node flow config (only for flow nodes)
		nodeConfig := cloneWatchConfig(watchConfig)
		if nodeModes[nodeID] == "flow" {
			if err := p.appendFlowConfig(ctx, nodeConfig, nodeID); err != nil {
				log.Printf("configpub: flow config for %s failed, skipping push: %v", nodeID, err)
				continue
			}
		}
		if err := p.pusher.SendConfigPush(nodeID, nodeConfig, uint64(newVersion)); err != nil {
			log.Printf("configpub: push to %s failed: %v", nodeID, err)
			// Mark as pending/failed
			ctxTO, cancel := context.WithTimeout(ctx, 5*time.Second)
			_ = p.store.Nodes().UpdateDeliveryVersionCurrent(ctxTO, nodeID, newVersion)
			cancel()
		} else {
			pushed++
		}
	}

	log.Printf("configpub: published version=%d prefixes=%d pushed=%d/%d nodes",
		newVersion, len(watchConfig.Prefixes), pushed, len(connectedIDs))

	return newVersion, nil
}

// CheckDrift returns nodes where delivery_version_applied < delivery_version_current.
func (p *Publisher) CheckDrift(ctx context.Context) ([]store.Node, error) {
	nodes, err := p.store.Nodes().List(ctx)
	if err != nil {
		return nil, err
	}
	var drifted []store.Node
	for _, n := range nodes {
		if n.Enabled && n.DeliveryVersionApplied < n.DeliveryVersionCurrent {
			drifted = append(drifted, n)
		}
	}
	return drifted, nil
}

// RunDriftChecker periodically logs nodes with config drift.
// Reference: brainstorm "Alert on Node not ACKing for extended period (>5min out of sync)"
func (p *Publisher) RunDriftChecker(ctx context.Context) {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			drifted, err := p.CheckDrift(ctx)
			if err != nil {
				log.Printf("configpub: drift check: %v", err)
				continue
			}
			for _, n := range drifted {
				age := ""
				if n.LastACKAt != nil {
					age = fmt.Sprintf(" last_ack=%v ago", time.Since(*n.LastACKAt).Round(time.Second))
				}
				log.Printf("configpub: DRIFT node=%s current=%d applied=%d status=%s%s",
					n.ID, n.DeliveryVersionCurrent, n.DeliveryVersionApplied, n.ConfigStatus, age)
			}
		}
	}
}

// cloneWatchConfig creates a shallow copy of WatchConfig so per-node flow_listeners
// don't leak between nodes. Prefixes and HardThresholds are shared (read-only).
func cloneWatchConfig(wc *pb.WatchConfig) *pb.WatchConfig {
	return &pb.WatchConfig{
		Prefixes:       wc.Prefixes,
		HardThresholds: wc.HardThresholds,
	}
}

func (p *Publisher) buildWatchConfig(ctx context.Context) (*pb.WatchConfig, error) {
	prefixes, err := p.store.Prefixes().List(ctx)
	if err != nil {
		return nil, err
	}

	var wp []*pb.WatchPrefix
	for _, pf := range prefixes {
		if !pf.Enabled {
			continue
		}
		// 0.0.0.0/0 is a virtual global prefix — do NOT push to BPF trie.
		// It would match every packet, breaking per-prefix granularity.
		// Controller feeds global_stats into its ring instead.
		if pf.Prefix == "0.0.0.0/0" {
			continue
		}
		_, ipnet, err := net.ParseCIDR(pf.Prefix)
		if err != nil {
			continue
		}
		ones, _ := ipnet.Mask.Size()
		wp = append(wp, &pb.WatchPrefix{
			Prefix:    ipnet.IP,
			PrefixLen: uint32(ones),
			Name:      pf.Name,
		})
	}

	// Load aggregated hard thresholds: find the lowest per-IP pps/bps threshold
	// across all templates and per-prefix overrides. This gives the Node a
	// sensible CriticalEvent trigger without needing per-prefix granularity.
	allThresholds, _ := p.store.Thresholds().List(ctx)
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
		minPPS = 1_000_000 // fallback default
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
// Returns error if DB read fails (caller should treat as push failure, not silently degrade).
func (p *Publisher) appendFlowConfig(ctx context.Context, wc *pb.WatchConfig, nodeID string) error {
	listeners, err := p.store.FlowListeners().List(ctx, nodeID)
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
		sources, err := p.store.FlowSources().List(ctx, l.ID)
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
