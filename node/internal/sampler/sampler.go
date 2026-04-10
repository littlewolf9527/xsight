// Package sampler consumes packet samples from the BPF ring buffer.
package sampler

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"sync/atomic"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/littlewolf9527/xsight/node/internal/bpf"
)

// Sampler reads raw packet bytes from the BPF ring buffer.
type Sampler struct {
	reader  *ringbuf.Reader
	stopped atomic.Bool

	// Metrics (P2 sampling observability)
	DroppedKernel atomic.Uint64 // ring buffer full, BPF side drops
	DroppedUser   atomic.Uint64 // userspace can't keep up
	TotalSamples  atomic.Uint64
}

// New creates a Sampler from the BPF samples ring buffer map.
func New(samplesMap *ebpf.Map) (*Sampler, error) {
	rd, err := ringbuf.NewReader(samplesMap)
	if err != nil {
		return nil, fmt.Errorf("ringbuf reader: %w", err)
	}
	return &Sampler{reader: rd}, nil
}

// Sample represents a parsed ring buffer record with header metadata.
type Sample struct {
	CapLen uint32 // actual captured bytes
	PktLen uint32 // original packet length on wire
	Data   []byte // packet data (cap_len bytes, no trailing padding)
}

// Run consumes ring buffer records and calls handler for each sample.
// Blocks until Close() is called. Run this in a dedicated goroutine.
func (s *Sampler) Run(handler func(sample Sample)) {
	for {
		record, err := s.reader.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return // normal shutdown
			}
			if s.stopped.Load() {
				return
			}
			log.Printf("sampler: read error: %v", err)
			// Backoff to prevent CPU burn on persistent errors
			time.Sleep(100 * time.Millisecond)
			continue
		}

		raw := record.RawSample
		if len(raw) < bpf.SampleHdrSize {
			log.Printf("sampler: short record (%d bytes), skipping", len(raw))
			continue
		}

		capLen := binary.LittleEndian.Uint32(raw[0:4])
		pktLen := binary.LittleEndian.Uint32(raw[4:8])
		data := raw[bpf.SampleHdrSize:]

		// Trim to cap_len (rest is zero-padded reservation)
		if capLen > 0 && int(capLen) <= len(data) {
			data = data[:capLen]
		}

		s.TotalSamples.Add(1)
		handler(Sample{CapLen: capLen, PktLen: pktLen, Data: data})
	}
}

// Close stops the sampler and releases resources.
func (s *Sampler) Close() {
	s.stopped.Store(true)
	s.reader.Close()
}

// HexDumpHandler returns a handler that logs hex dumps of samples.
// Useful for P2 verification.
func HexDumpHandler(maxDump int) func(Sample) {
	return func(s Sample) {
		dumpLen := len(s.Data)
		if dumpLen > maxDump {
			dumpLen = maxDump
		}
		log.Printf("sample (cap=%d pkt=%d):\n%s", s.CapLen, s.PktLen, hex.Dump(s.Data[:dumpLen]))
	}
}
