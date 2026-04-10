package flow

import (
	"fmt"
	"log"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	flowpb "github.com/netsampler/goflow2/v2/pb"
	producerpb "github.com/netsampler/goflow2/v2/producer/proto"
	"github.com/netsampler/goflow2/v2/utils"
	"google.golang.org/protobuf/proto"
)

// Source represents a registered exporter device on a listener.
type Source struct {
	Name       string
	DeviceIP   netip.Addr
	SampleMode string // "auto" | "force" | "none"
	SampleRate int
	Enabled    bool

	// Runtime metrics
	RecordsReceived atomic.Int64
	LastSeenAt      atomic.Int64 // unix timestamp
}

// ResolveSampleRate returns the effective sample rate for a flow record.
func (s *Source) ResolveSampleRate(recordRate uint32) uint32 {
	switch s.SampleMode {
	case "force":
		return uint32(s.SampleRate)
	case "none":
		return 1
	default: // "auto"
		if recordRate > 0 {
			return recordRate
		}
		return 1
	}
}

// Listener manages a UDP socket that receives flow exports from one or more devices.
// It uses goflow2's AutoFlowPipe for protocol detection + decoding + producing FlowMessages.
type Listener struct {
	ListenAddr   string
	ProtocolMode string // "auto" | "sflow" | "netflow" | "ipfix"

	mu      sync.RWMutex
	sources map[string]*Source // device IP string → Source

	aggregator *FlowAggregator
	receiver   *utils.UDPReceiver
	pipe       *utils.AutoFlowPipe

	// Metrics
	UnknownExporter atomic.Int64
	DecodeErrors    atomic.Int64
	RecordsDecoded     atomic.Int64
	TemplateMisses  atomic.Int64

	stopCh chan struct{}
}

// ListenerConfig holds the config for creating a Listener.
type ListenerConfig struct {
	ListenAddr   string
	ProtocolMode string
	Sources      []SourceConfig
	Aggregator   *FlowAggregator
}

// SourceConfig is the config for a single exporter device.
type SourceConfig struct {
	Name       string
	DeviceIP   string
	SampleMode string
	SampleRate int
	Enabled    bool
}

// NewListener creates a flow listener (does not start it).
func NewListener(cfg ListenerConfig) (*Listener, error) {
	l := &Listener{
		ListenAddr:   cfg.ListenAddr,
		ProtocolMode: cfg.ProtocolMode,
		sources:      make(map[string]*Source),
		aggregator:   cfg.Aggregator,
		stopCh:       make(chan struct{}),
	}

	for _, sc := range cfg.Sources {
		// Strip /32 or /128 suffix if present (PostgreSQL INET stores "10.0.0.1/32")
		ipStr, _, _ := strings.Cut(sc.DeviceIP, "/")
		addr, err := netip.ParseAddr(ipStr)
		if err != nil {
			return nil, fmt.Errorf("invalid device_ip %q: %w", sc.DeviceIP, err)
		}
		l.sources[addr.Unmap().String()] = &Source{
			Name:       sc.Name,
			DeviceIP:   addr.Unmap(),
			SampleMode: sc.SampleMode,
			SampleRate: sc.SampleRate,
			Enabled:    sc.Enabled,
		}
	}

	return l, nil
}

// xsightTransport implements goflow2 transport.TransportInterface.
// It receives formatted FlowMessages and feeds them to our aggregator.
// Source IP filtering is done here using SamplerAddress from the FlowMessage
// (which goflow2 sets from the UDP source address for sFlow, and from the
// packet header for NetFlow/IPFIX).
type xsightTransport struct {
	listener *Listener
}

func (t *xsightTransport) Send(key, data []byte) error {
	// data is protobuf-encoded FlowMessage
	var fm flowpb.FlowMessage
	if err := proto.Unmarshal(data, &fm); err != nil {
		t.listener.DecodeErrors.Add(1)
		return nil
	}

	t.listener.RecordsDecoded.Add(1)

	// Template arrived — clear warm-up misses so the counter doesn't scare users
	if t.listener.TemplateMisses.Load() > 0 {
		t.listener.TemplateMisses.Store(0)
	}

	// Source filtering by SamplerAddress (set by goflow2 from UDP source addr)
	srcAddr, ok := netip.AddrFromSlice(fm.SamplerAddress)
	if !ok {
		t.listener.UnknownExporter.Add(1)
		return nil
	}
	srcKey := srcAddr.Unmap().String()

	t.listener.mu.RLock()
	source, registered := t.listener.sources[srcKey]
	t.listener.mu.RUnlock()

	if !registered || !source.Enabled {
		t.listener.UnknownExporter.Add(1)
		return nil
	}

	source.RecordsReceived.Add(1)
	source.LastSeenAt.Store(time.Now().Unix())

	// Convert to FlowRecord
	rec := FlowRecord{
		SrcIP:      net.IP(fm.SrcAddr),
		DstIP:      net.IP(fm.DstAddr),
		SrcPort:    uint16(fm.SrcPort),
		DstPort:    uint16(fm.DstPort),
		Protocol:   uint8(fm.Proto),
		TCPFlags:   uint8(fm.TcpFlags),
		Packets:    fm.Packets,
		Bytes:      fm.Bytes,
		SampleRate: uint32(fm.SamplingRate),
	}

	// Time fields (NetFlow/IPFIX — goflow2 normalizes to nanosecond UTC)
	if fm.TimeFlowStartNs > 0 {
		rec.StartTime = time.Unix(0, int64(fm.TimeFlowStartNs)).UTC()
	}
	if fm.TimeFlowEndNs > 0 {
		rec.EndTime = time.Unix(0, int64(fm.TimeFlowEndNs)).UTC()
	}
	if !rec.StartTime.IsZero() && !rec.EndTime.IsZero() {
		rec.Duration = int(rec.EndTime.Sub(rec.StartTime).Seconds())
		if rec.Duration < 0 {
			rec.Duration = 0
		}
	}

	// Feed to aggregator
	t.listener.aggregator.Add(rec, source)

	return nil
}

// protoFormat marshals ProtoProducerMessage via proto.Marshal (standard protobuf wire format).
// goflow2's built-in "bin" format uses MarshalBinary which is NOT standard protobuf.
type protoFormat struct{}

func (f *protoFormat) Format(data interface{}) ([]byte, []byte, error) {
	if msg, ok := data.(interface{ GetFlowMessage() *producerpb.ProtoProducerMessage }); ok {
		fm := msg.GetFlowMessage()
		b, err := proto.Marshal(&fm.FlowMessage)
		return nil, b, err
	}
	return nil, nil, fmt.Errorf("unexpected message type: %T", data)
}

// decodeFlowFiltered wraps the pipe's DecodeFlow with protocol_mode enforcement
// and template miss detection.
func (l *Listener) decodeFlowFiltered(msg interface{}) error {
	if l.ProtocolMode != "auto" {
		// In explicit mode, check protocol before decoding
		pkt, ok := msg.(*utils.Message)
		if ok && len(pkt.Payload) >= 4 {
			if !l.matchesProtocolMode(pkt.Payload) {
				return nil // silently drop mismatched protocol
			}
		}
	}
	err := l.pipe.DecodeFlow(msg)
	if err != nil && strings.Contains(err.Error(), "template not found") {
		l.TemplateMisses.Add(1)
		return nil // template miss is expected during warm-up, don't propagate
	}
	return err
}

// matchesProtocolMode checks if the payload matches the configured protocol.
func (l *Listener) matchesProtocolMode(payload []byte) bool {
	// sFlow: first 4 bytes are version (5) as uint32
	// NetFlow: first 2 bytes are version (5, 9, 10) as uint16
	proto := uint32(payload[0])<<24 | uint32(payload[1])<<16 | uint32(payload[2])<<8 | uint32(payload[3])
	nfVersion := (proto & 0xFFFF0000) >> 16

	switch l.ProtocolMode {
	case "sflow":
		return proto == 5 // sFlow v5
	case "netflow":
		return nfVersion == 5 || nfVersion == 9
	case "ipfix":
		return nfVersion == 10
	}
	return true // auto
}

// Start begins receiving UDP packets and decoding flow data.
func (l *Listener) Start() error {
	// Create goflow2 pipeline: producer → protobufFormat → transport(our callback)
	samplingFactory := func() producerpb.SamplingRateSystem {
		return producerpb.CreateSamplingSystem()
	}
	prodCfg, err := (&producerpb.ProducerConfig{}).Compile()
	if err != nil {
		return fmt.Errorf("compile producer config: %w", err)
	}
	prod, err := producerpb.CreateProtoProducer(prodCfg, samplingFactory)
	if err != nil {
		return fmt.Errorf("create proto producer: %w", err)
	}

	tr := &xsightTransport{listener: l}
	fmtr := &protoFormat{} // marshal via proto.Marshal (not goflow2's binary format)

	l.pipe = utils.NewFlowPipe(&utils.PipeConfig{
		Producer:  prod,
		Format:    fmtr,
		Transport: tr,
	})

	rcvCfg := &utils.UDPReceiverConfig{
		Workers:   1,
		Sockets:   1,
		QueueSize: 100000,
	}
	l.receiver, err = utils.NewUDPReceiver(rcvCfg)
	if err != nil {
		return fmt.Errorf("create UDP receiver: %w", err)
	}

	// Parse listen address
	host, portStr, err := net.SplitHostPort(l.ListenAddr)
	if err != nil {
		return fmt.Errorf("parse listen_address %q: %w", l.ListenAddr, err)
	}
	var port int
	fmt.Sscanf(portStr, "%d", &port)

	log.Printf("flow-listener: starting on %s (protocol=%s, sources=%d)", l.ListenAddr, l.ProtocolMode, len(l.sources))

	if err := l.receiver.Start(host, port, l.decodeFlowFiltered); err != nil {
		return fmt.Errorf("start UDP receiver on %s: %w", l.ListenAddr, err)
	}

	// Log receiver errors in background
	go func() {
		for err := range l.receiver.Errors() {
			log.Printf("flow-receiver: %v", err)
		}
	}()

	return nil
}

// Stop shuts down the listener.
func (l *Listener) Stop() {
	if l.receiver != nil {
		l.receiver.Stop()
	}
	if l.pipe != nil {
		l.pipe.Close()
	}
	close(l.stopCh)
	log.Printf("flow-listener: stopped %s", l.ListenAddr)
}

// UpdateSources replaces the source table (called on ConfigPush).
func (l *Listener) UpdateSources(sources []SourceConfig) {
	newMap := make(map[string]*Source, len(sources))
	for _, sc := range sources {
		// Strip /32 or /128 suffix if present (PostgreSQL INET stores "10.0.0.1/32")
		ipStr, _, _ := strings.Cut(sc.DeviceIP, "/")
		addr, err := netip.ParseAddr(ipStr)
		if err != nil {
			continue
		}
		newMap[addr.Unmap().String()] = &Source{
			Name:       sc.Name,
			DeviceIP:   addr.Unmap(),
			SampleMode: sc.SampleMode,
			SampleRate: sc.SampleRate,
			Enabled:    sc.Enabled,
		}
	}

	l.mu.Lock()
	l.sources = newMap
	l.mu.Unlock()
}
