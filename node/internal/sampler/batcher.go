// Package sampler — batcher.go collects parsed PacketSamples into batches
// and delivers them via a callback when a batch is full.
//
// Batch cutting triggers (whichever comes first):
//   - MaxCount samples (default 1000)
//   - MaxBytes total raw_header bytes (default 512 KB)
//   - MaxLatency since first sample in batch (default 100 ms)
//
// Also tracks unique source IPs and sampling metrics.
//
package sampler

import (
	"fmt"
	"log"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// BatchConfig controls batch cutting thresholds.
type BatchConfig struct {
	MaxCount   int           // samples per batch (default 1000)
	MaxBytes   int           // raw_header bytes per batch (default 512 KB)
	MaxLatency time.Duration // max time before flush (default 100 ms)
}

// DefaultBatchConfig returns sensible defaults per brainstorm.
func DefaultBatchConfig() BatchConfig {
	return BatchConfig{
		MaxCount:   1000,
		MaxBytes:   512 * 1024, // 512 KB
		MaxLatency: 100 * time.Millisecond,
	}
}

// SamplingMetrics tracks P4 observability counters.
// These are reported alongside StatsReport in P5.
type SamplingMetrics struct {
	DecodeErrors atomic.Uint64 // gopacket parse failures
	DroppedUser  atomic.Uint64 // samples dropped due to backpressure
	BatchesSent  atomic.Uint64 // total batches delivered
	SamplesSent  atomic.Uint64 // total samples delivered in batches
}

// Batcher collects PacketSamples and flushes them in batches.
type Batcher struct {
	config  BatchConfig
	handler func([]PacketSample) // called on flush; must be goroutine-safe

	mu         sync.Mutex
	batch      []PacketSample
	batchBytes int
	timer      *time.Timer

	// unique source IP tracking (reset per flush window)
	uniqueSrc map[string]struct{}

	Metrics SamplingMetrics
}

// NewBatcher creates a Batcher that delivers batches to handler.
// handler is called in the Batcher's goroutine context.
func NewBatcher(cfg BatchConfig, handler func([]PacketSample)) *Batcher {
	if cfg.MaxCount <= 0 {
		cfg.MaxCount = 1000
	}
	if cfg.MaxBytes <= 0 {
		cfg.MaxBytes = 512 * 1024
	}
	if cfg.MaxLatency <= 0 {
		cfg.MaxLatency = 100 * time.Millisecond
	}
	return &Batcher{
		config:    cfg,
		handler:   handler,
		uniqueSrc: make(map[string]struct{}),
	}
}

// Add enqueues a parsed sample. If the batch is full, it flushes synchronously.
func (b *Batcher) Add(ps PacketSample) {
	b.mu.Lock()
	defer b.mu.Unlock()

	// Track unique source IP
	if ps.SrcIP != nil {
		b.uniqueSrc[string(ps.SrcIP)] = struct{}{}
	}

	b.batch = append(b.batch, ps)
	b.batchBytes += len(ps.RawHeader)

	// Start latency timer on first sample
	if len(b.batch) == 1 && b.timer == nil {
		b.timer = time.AfterFunc(b.config.MaxLatency, func() {
			b.mu.Lock()
			defer b.mu.Unlock()
			b.flushLocked()
		})
	}

	// Check count/byte thresholds
	if len(b.batch) >= b.config.MaxCount || b.batchBytes >= b.config.MaxBytes {
		b.flushLocked()
	}
}

// flushLocked delivers the current batch and resets state. Caller must hold mu.
func (b *Batcher) flushLocked() {
	if len(b.batch) == 0 {
		return
	}

	if b.timer != nil {
		b.timer.Stop()
		b.timer = nil
	}

	batch := b.batch
	b.batch = nil
	b.batchBytes = 0

	b.Metrics.BatchesSent.Add(1)
	b.Metrics.SamplesSent.Add(uint64(len(batch)))

	b.handler(batch)
}

// UniqueSourceCount returns the number of unique source IPs since last reset.
func (b *Batcher) UniqueSourceCount() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.uniqueSrc)
}

// ResetUniqueSources clears the unique source tracker and returns the count.
func (b *Batcher) ResetUniqueSources() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	n := len(b.uniqueSrc)
	b.uniqueSrc = make(map[string]struct{})
	return n
}

// Close flushes any remaining samples.
func (b *Batcher) Close() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.flushLocked()
}

// LogBatchHandler returns a batch handler that logs a summary of each batch.
// Useful for P4 terminal verification; replaced by gRPC sender in P5.
func LogBatchHandler() func([]PacketSample) {
	return func(batch []PacketSample) {
		if len(batch) == 0 {
			return
		}

		// Count protocols
		var tcp, udp, icmp, other int
		for _, ps := range batch {
			switch ps.Protocol {
			case 6:
				tcp++
			case 17:
				udp++
			case 1, 58: // ICMPv4, ICMPv6
				icmp++
			default:
				other++
			}
		}

		// Show first few samples
		var details strings.Builder
		n := 5
		if n > len(batch) {
			n = len(batch)
		}
		for i := 0; i < n; i++ {
			ps := batch[i]
			fmt.Fprintf(&details, "    %s:%d → %s:%d proto=%d len=%d",
				ps.SrcIP, ps.SrcPort, ps.DstIP, ps.DstPort,
				ps.Protocol, ps.PacketLength)
			if ps.TCPFlags != 0 {
				fmt.Fprintf(&details, " flags=0x%02x", ps.TCPFlags)
			}
			if ps.ICMPType != 0 || ps.ICMPCode != 0 {
				fmt.Fprintf(&details, " icmp=%d/%d", ps.ICMPType, ps.ICMPCode)
			}
			details.WriteString("\n")
		}
		if len(batch) > n {
			fmt.Fprintf(&details, "    ... and %d more\n", len(batch)-n)
		}

		log.Printf("batch: %d samples (tcp=%d udp=%d icmp=%d other=%d)\n%s",
			len(batch), tcp, udp, icmp, other, details.String())
	}
}
