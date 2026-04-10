// Package ingestion handles gRPC data collection from XDP Nodes.
package ingestion

import (
	"sync"
	"time"

	pb "github.com/littlewolf9527/xsight/controller/internal/pb"
)

// FlowMetrics holds the last-received flow node health metrics.
type FlowMetrics struct {
	DecodeErrors    uint64    `json:"decode_errors"`
	UnknownExporter uint64    `json:"unknown_exporter"`
	TemplateMisses  uint64    `json:"template_misses"`
	UpdatedAt       time.Time `json:"updated_at"`
}

// SourceStatus represents the last-known status of a flow exporter device.
type SourceStatus struct {
	DeviceIP        string `json:"device_ip"`
	Active          bool   `json:"active"`
	LastSeenAt      int64  `json:"last_seen_at"` // unix timestamp
	RecordsReceived int64  `json:"records_received"`
}

// ListenerStatus represents per-listener runtime metrics.
type ListenerStatus struct {
	ListenAddr      string `json:"listen_addr"`
	ProtocolMode    string `json:"protocol_mode"`
	RecordsDecoded     int64  `json:"records_decoded"`
	DecodeErrors    int64  `json:"decode_errors"`
	UnknownExporter int64  `json:"unknown_exporter"`
	TemplateMisses  int64  `json:"template_misses"`
	SourceCount     int    `json:"source_count"`
}

// NodeState tracks runtime state of a connected Node.
// Online status is derived (not stored in DB) per brainstorm decision.
type NodeState struct {
	mu               sync.RWMutex
	lastStatsAt      map[string]time.Time                                       // nodeID → last StatsReport time
	connectedAt      map[string]time.Time                                       // nodeID → handshake time (for uptime)
	controlStream    map[string]pb.XSightService_ControlStreamServer            // nodeID → bidi stream
	flowMetrics      map[string]*FlowMetrics                                    // nodeID → last flow metrics
	sourceStatuses   map[string][]SourceStatus                                  // nodeID → per-source statuses
	listenerStatuses map[string][]ListenerStatus                                // nodeID → per-listener statuses
}

func NewNodeState() *NodeState {
	return &NodeState{
		lastStatsAt:      make(map[string]time.Time),
		connectedAt:      make(map[string]time.Time),
		controlStream:    make(map[string]pb.XSightService_ControlStreamServer),
		flowMetrics:      make(map[string]*FlowMetrics),
		sourceStatuses:   make(map[string][]SourceStatus),
		listenerStatuses: make(map[string][]ListenerStatus),
	}
}

// TouchStats records that a StatsReport was received from the node.
func (ns *NodeState) TouchStats(nodeID string) {
	ns.mu.Lock()
	ns.lastStatsAt[nodeID] = time.Now()
	ns.mu.Unlock()
}

// IsOnline returns true if a StatsReport was received within the last 10s.
func (ns *NodeState) IsOnline(nodeID string) bool {
	ns.mu.RLock()
	defer ns.mu.RUnlock()
	t, ok := ns.lastStatsAt[nodeID]
	return ok && time.Since(t) < 10*time.Second
}

// LastStatsAt returns the last stats time for a node (zero if never seen).
func (ns *NodeState) LastStatsAt(nodeID string) time.Time {
	ns.mu.RLock()
	defer ns.mu.RUnlock()
	return ns.lastStatsAt[nodeID]
}

// ConnectedAt returns the handshake time for a node (zero if not connected).
func (ns *NodeState) ConnectedAt(nodeID string) time.Time {
	ns.mu.RLock()
	defer ns.mu.RUnlock()
	return ns.connectedAt[nodeID]
}

// SetControlStream registers a bidirectional ControlStream for a node.
func (ns *NodeState) SetControlStream(nodeID string, stream pb.XSightService_ControlStreamServer) {
	ns.mu.Lock()
	ns.controlStream[nodeID] = stream
	ns.connectedAt[nodeID] = time.Now()
	ns.mu.Unlock()
}

// ClearControlStream removes the ControlStream reference on disconnect.
// Also clears all ephemeral state so stale data doesn't persist.
func (ns *NodeState) ClearControlStream(nodeID string) {
	ns.mu.Lock()
	delete(ns.controlStream, nodeID)
	delete(ns.lastStatsAt, nodeID)
	delete(ns.connectedAt, nodeID)
	delete(ns.sourceStatuses, nodeID)
	delete(ns.listenerStatuses, nodeID)
	ns.mu.Unlock()
}

// GetControlStream returns the ControlStream for a node (nil if not connected).
func (ns *NodeState) GetControlStream(nodeID string) pb.XSightService_ControlStreamServer {
	ns.mu.RLock()
	defer ns.mu.RUnlock()
	return ns.controlStream[nodeID]
}

// ConnectedNodes returns a list of node IDs with active ControlStreams.
func (ns *NodeState) ConnectedNodes() []string {
	ns.mu.RLock()
	defer ns.mu.RUnlock()
	ids := make([]string, 0, len(ns.controlStream))
	for id := range ns.controlStream {
		ids = append(ids, id)
	}
	return ids
}

// UpdateFlowMetrics stores the latest SamplingMetrics for a flow node.
// Proto field mapping: dropped_kernel = template_misses, dropped_user = unknown_exporter.
func (ns *NodeState) UpdateFlowMetrics(nodeID string, decodeErrors, unknownExporter, templateMisses uint64) {
	ns.mu.Lock()
	ns.flowMetrics[nodeID] = &FlowMetrics{
		DecodeErrors:    decodeErrors,
		UnknownExporter: unknownExporter,
		TemplateMisses:  templateMisses,
		UpdatedAt:       time.Now(),
	}
	ns.mu.Unlock()
}

// GetFlowMetrics returns the last-received flow metrics for a node (nil if none).
func (ns *NodeState) GetFlowMetrics(nodeID string) *FlowMetrics {
	ns.mu.RLock()
	defer ns.mu.RUnlock()
	return ns.flowMetrics[nodeID]
}

// UpdateSourceStatuses stores per-source status for a flow node.
func (ns *NodeState) UpdateSourceStatuses(nodeID string, statuses []SourceStatus) {
	ns.mu.Lock()
	ns.sourceStatuses[nodeID] = statuses
	ns.mu.Unlock()
}

// GetSourceStatuses returns the last-known source statuses for a node.
func (ns *NodeState) GetSourceStatuses(nodeID string) []SourceStatus {
	ns.mu.RLock()
	defer ns.mu.RUnlock()
	return ns.sourceStatuses[nodeID]
}

// UpdateListenerStatuses stores per-listener status for a flow node.
func (ns *NodeState) UpdateListenerStatuses(nodeID string, statuses []ListenerStatus) {
	ns.mu.Lock()
	ns.listenerStatuses[nodeID] = statuses
	ns.mu.Unlock()
}

// GetListenerStatuses returns the last-known listener statuses for a node.
func (ns *NodeState) GetListenerStatuses(nodeID string) []ListenerStatus {
	ns.mu.RLock()
	defer ns.mu.RUnlock()
	return ns.listenerStatuses[nodeID]
}
