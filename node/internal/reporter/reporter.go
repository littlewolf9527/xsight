// Package reporter manages gRPC connection to Controller with handshake,
// three reporting streams, and a bidirectional control channel.
//
package reporter

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"sync/atomic"

	"github.com/littlewolf9527/xsight/node/internal/collector"
	"github.com/littlewolf9527/xsight/node/internal/pb"
	"github.com/littlewolf9527/xsight/node/internal/sampler"
)

// Config holds reporter configuration.
type Config struct {
	ControllerAddr string
	NodeID         string
	APIKey         string
	InterfaceName  string
	AgentVersion   string
	UpstreamRate   uint32
	Mode           string // "xdp" (default) | "flow" — v3.0
}

// ApplyConfigFunc is called when the reporter receives a new watch config
// from the Controller (via handshake or ControlStream ConfigPush).
// The reporter passes the proto WatchConfig and delivery version;
// the caller is responsible for HotSwap + snapshot save.
type ApplyConfigFunc func(wc *pb.WatchConfig, deliveryVersion uint64) error

// Reporter manages gRPC streams to Controller.
type Reporter struct {
	cfg Config

	// Data sources (XDP mode uses reports, flow mode uses flowReports)
	reports     <-chan *collector.Report
	flowReports <-chan *pb.StatsReport // v3.0: direct protobuf input from FlowAggregator
	batches     chan []sampler.PacketSample

	// Callback for applying config (HotSwap + snapshot)
	applyConfig       ApplyConfigFunc
	deliveryVersion   uint64

	// Metrics source for SamplingMetrics (set via SetBatcher)
	batcher           *sampler.Batcher
	localRate         atomic.Uint32 // current sample rate, updated from StatsStream
	batchSendLatencyUs atomic.Int64  // last SampleStream.Send() latency in microseconds

	// State
	conn           *grpc.ClientConn
	client         pb.XSightServiceClient
	connected      bool
	lastDisconnect time.Time
	mu             sync.Mutex
}

// New creates a Reporter for XDP mode.
// applyConfig is called when Controller delivers a new watch config.
func New(cfg Config, reports <-chan *collector.Report, applyConfig ApplyConfigFunc) *Reporter {
	return &Reporter{
		cfg:         cfg,
		reports:     reports,
		batches:     make(chan []sampler.PacketSample, 16),
		applyConfig: applyConfig,
	}
}

// NewFlow creates a Reporter for flow mode.
// flowReports receives pre-built StatsReport protobufs from FlowAggregator.
func NewFlow(cfg Config, flowReports <-chan *pb.StatsReport, applyConfig ApplyConfigFunc) *Reporter {
	return &Reporter{
		cfg:         cfg,
		flowReports: flowReports,
		batches:     make(chan []sampler.PacketSample, 16),
		applyConfig: applyConfig,
	}
}

// SetDeliveryVersion sets the current delivery version from a loaded snapshot.
func (r *Reporter) SetDeliveryVersion(v uint64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.deliveryVersion = v
}

// SetBatcher sets the batcher reference for SamplingMetrics.
// Must be called before Run().
func (r *Reporter) SetBatcher(b *sampler.Batcher) {
	r.batcher = b
}

// BatchSendLatencyMs returns the last SampleStream.Send() latency in milliseconds.
func (r *Reporter) BatchSendLatencyMs() float32 {
	return float32(r.batchSendLatencyUs.Load()) / 1000.0
}

// BatchHandler returns a function suitable for sampler.NewBatcher handler
// that forwards batches to the reporter's internal channel.
func (r *Reporter) BatchHandler() func([]sampler.PacketSample) {
	return func(batch []sampler.PacketSample) {
		select {
		case r.batches <- batch:
		default:
			// Drop if reporter can't keep up (brainstorm: samples are best-effort)
			if r.batcher != nil {
				r.batcher.Metrics.DroppedUser.Add(uint64(len(batch)))
			}
		}
	}
}

// Run connects to Controller, performs handshake, and starts all streams.
// Blocks until ctx is cancelled. Handles reconnection with backoff.
func (r *Reporter) Run(ctx context.Context) {
	backoff := time.Second

	for {
		select {
		case <-ctx.Done():
			r.disconnect()
			return
		default:
		}

		if err := r.connectAndServe(ctx); err != nil {
			log.Printf("reporter: %v (reconnecting in %v)", err, backoff)
		}

		r.disconnect()

		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}

		// Exponential backoff capped at 30s
		backoff = backoff * 2
		if backoff > 30*time.Second {
			backoff = 30 * time.Second
		}
	}
}

// connectAndServe dials, handshakes, and runs all streams until error or ctx cancel.
func (r *Reporter) connectAndServe(ctx context.Context) error {
	log.Printf("reporter: connecting to %s", r.cfg.ControllerAddr)

	conn, err := grpc.NewClient(
		r.cfg.ControllerAddr,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		return err
	}
	r.conn = conn
	r.client = pb.NewXSightServiceClient(conn)

	// Handshake
	resp, err := r.handshake(ctx)
	if err != nil {
		return err
	}
	if !resp.Accepted {
		log.Printf("reporter: handshake rejected: %s", resp.RejectReason)
		return errRejected
	}
	log.Printf("reporter: handshake accepted, delivery_version=%d, prefixes=%d",
		resp.DeliveryVersionCurrent,
		len(resp.GetWatchConfig().GetPrefixes()))

	// Apply watch_config from handshake (P6: reconciliation)
	if wc := resp.GetWatchConfig(); wc != nil && r.applyConfig != nil {
		if err := r.applyConfig(wc, resp.DeliveryVersionCurrent); err != nil {
			log.Printf("reporter: apply handshake config: %v", err)
		} else {
			r.mu.Lock()
			r.deliveryVersion = resp.DeliveryVersionCurrent
			r.mu.Unlock()
		}
	}

	r.mu.Lock()
	r.connected = true
	r.mu.Unlock()

	// Calculate gap_seconds from last disconnect
	gapSeconds := uint32(0)
	if !r.lastDisconnect.IsZero() {
		gapSeconds = uint32(time.Since(r.lastDisconnect).Seconds())
	}

	// Start all streams in parallel; first error cancels all
	streamCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	errCh := make(chan error, 4)
	var wg sync.WaitGroup

	// StatsStream
	wg.Add(1)
	go func() {
		defer wg.Done()
		errCh <- r.runStatsStream(streamCtx, gapSeconds)
	}()

	// SampleStream — skip in flow mode (no raw packet samples)
	if r.cfg.Mode != "flow" {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errCh <- r.runSampleStream(streamCtx)
		}()
	}

	// CriticalEventStream — placeholder for now (events come from collector in future)
	wg.Add(1)
	go func() {
		defer wg.Done()
		<-streamCtx.Done()
		errCh <- nil
	}()

	// ControlStream
	wg.Add(1)
	go func() {
		defer wg.Done()
		errCh <- r.runControlStream(streamCtx)
	}()

	// Wait for first error
	select {
	case err := <-errCh:
		cancel()
		wg.Wait()
		r.mu.Lock()
		r.connected = false
		r.lastDisconnect = time.Now()
		r.mu.Unlock()
		return err
	case <-ctx.Done():
		cancel()
		wg.Wait()
		return ctx.Err()
	}
}

func (r *Reporter) handshake(ctx context.Context) (*pb.HandshakeResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	r.mu.Lock()
	dv := r.deliveryVersion
	r.mu.Unlock()

	req := &pb.NodeHandshake{
		NodeId:                  r.cfg.NodeID,
		ApiKey:                  r.cfg.APIKey,
		Interfaces:              []string{r.cfg.InterfaceName},
		AgentVersion:            r.cfg.AgentVersion,
		DeliveryVersionApplied:  dv,
		Mode:                    r.cfg.Mode,
	}

	resp, err := r.client.Handshake(ctx, req)
	if err != nil {
		return nil, err
	}
	return resp, nil
}

// sendWithTimeout wraps stream.SendMsg with a deadline to prevent blocking forever
// when the server is experiencing lock contention or network issues.
func sendWithTimeout(ctx context.Context, stream grpc.ClientStream, msg any) error {
	done := make(chan error, 1)
	go func() { done <- stream.SendMsg(msg) }()
	select {
	case err := <-done:
		return err
	case <-time.After(5 * time.Second):
		return fmt.Errorf("stream send timeout (5s)")
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (r *Reporter) runStatsStream(ctx context.Context, initialGap uint32) error {
	stream, err := r.client.StatsStream(ctx)
	if err != nil {
		return err
	}

	gapSeconds := initialGap

	// Flow mode: receive pre-built StatsReport directly
	if r.flowReports != nil {
		for {
			select {
			case <-ctx.Done():
				stream.CloseAndRecv()
				return nil
			case msg, ok := <-r.flowReports:
				if !ok {
					stream.CloseAndRecv()
					return nil
				}
				msg.GapSeconds = gapSeconds
				if err := sendWithTimeout(ctx, stream, msg); err != nil {
					return err
				}
				gapSeconds = 0
			}
		}
	}

	// XDP mode: convert collector.Report to protobuf
	for {
		select {
		case <-ctx.Done():
			stream.CloseAndRecv()
			return nil
		case report, ok := <-r.reports:
			if !ok {
				stream.CloseAndRecv()
				return nil
			}
			r.localRate.Store(report.SampleRate)
			msg := reportToProto(report, r.cfg.NodeID, r.cfg.InterfaceName, r.cfg.UpstreamRate, gapSeconds, r.batcher, r.BatchSendLatencyMs())
			if err := sendWithTimeout(ctx, stream, msg); err != nil {
				return err
			}
			gapSeconds = 0
		}
	}
}

func (r *Reporter) runSampleStream(ctx context.Context) error {
	stream, err := r.client.SampleStream(ctx)
	if err != nil {
		return err
	}

	for {
		select {
		case <-ctx.Done():
			stream.CloseAndRecv()
			return nil
		case batch, ok := <-r.batches:
			if !ok {
				stream.CloseAndRecv()
				return nil
			}
			msg := batchToProto(batch, r.cfg.NodeID, r.cfg.InterfaceName, r.cfg.UpstreamRate, r.localRate.Load())
			t0 := time.Now()
			if err := sendWithTimeout(ctx, stream, msg); err != nil {
				return err
			}
			r.batchSendLatencyUs.Store(time.Since(t0).Microseconds())
		}
	}
}

func (r *Reporter) runControlStream(ctx context.Context) error {
	stream, err := r.client.ControlStream(ctx)
	if err != nil {
		return err
	}

	// Send ACK for config applied during handshake (before ControlStream existed).
	// Without this, controller never learns that handshake-applied config succeeded.
	r.mu.Lock()
	dv := r.deliveryVersion
	r.mu.Unlock()
	if dv > 0 {
		ack := &pb.ControlMessage{
			Payload: &pb.ControlMessage_ConfigAck{
				ConfigAck: &pb.ConfigAck{
					DeliveryVersionApplied: dv,
					Success:                true,
				},
			},
		}
		if err := sendWithTimeout(ctx, stream, ack); err != nil {
			return err
		}
		log.Printf("reporter: sent handshake config ACK version=%d", dv)
	}

	for {
		msg, err := stream.Recv()
		if err != nil {
			return err
		}
		switch p := msg.Payload.(type) {
		case *pb.ControlMessage_ConfigPush:
			cp := p.ConfigPush
			log.Printf("reporter: received ConfigPush version=%d prefixes=%d",
				cp.DeliveryVersionCurrent,
				len(cp.GetWatchConfig().GetPrefixes()))

			// Apply config (HotSwap + snapshot)
			success := true
			errMsg := ""
			if r.applyConfig != nil {
				if err := r.applyConfig(cp.GetWatchConfig(), cp.DeliveryVersionCurrent); err != nil {
					success = false
					errMsg = err.Error()
					log.Printf("reporter: apply ConfigPush failed: %v", err)
				} else {
					r.mu.Lock()
					r.deliveryVersion = cp.DeliveryVersionCurrent
					r.mu.Unlock()
				}
			}

			ack := &pb.ControlMessage{
				Payload: &pb.ControlMessage_ConfigAck{
					ConfigAck: &pb.ConfigAck{
						DeliveryVersionApplied: cp.DeliveryVersionCurrent,
						Success:                success,
						ErrorMessage:           errMsg,
					},
				},
			}
			if err := sendWithTimeout(ctx, stream, ack); err != nil {
				return err
			}
		}
	}
}

func (r *Reporter) disconnect() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.connected = false
	if r.conn != nil {
		r.conn.Close()
		r.conn = nil
	}
}

// Connected returns whether the reporter has an active gRPC connection.
func (r *Reporter) Connected() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.connected
}

type rejectedError struct{}

func (rejectedError) Error() string { return "handshake rejected" }

var errRejected = rejectedError{}
