// Package sampler — worker_pool.go implements the three-stage parallel parse pipeline.
//
// Architecture: Reader → N Workers → Aggregator
//   - Reader: reads from BPF ring buffer, round-robin dispatches to workers
//   - Workers: each has an independent PacketParser, zero-allocation decode
//   - Aggregator: single goroutine consuming parsed results into FlowTable + Batcher
//
// When workers=1, the pipeline is bypassed: reader directly parses and aggregates
// in a single goroutine (identical to the original single-threaded path).
//
package sampler

import (
	"log"
	"sync"
	"sync/atomic"
)

const (
	rawChSize    = 512
	parsedChSize = 2048
)

// WorkerPool manages the reader → workers → aggregator pipeline.
type WorkerPool struct {
	workers   int
	flowTable *FlowTable
	batcher   *Batcher

	// metrics
	DispatchDropped atomic.Uint64
	ParsedTotal     atomic.Uint64
}

// NewWorkerPool creates a worker pool with the given number of parse workers.
func NewWorkerPool(workers int, ft *FlowTable, bat *Batcher) *WorkerPool {
	if workers < 1 {
		workers = 1
	}
	if workers > 16 {
		workers = 16
	}
	return &WorkerPool{
		workers:   workers,
		flowTable: ft,
		batcher:   bat,
	}
}

// Start launches the pipeline. The provided sampler is consumed in the reader goroutine.
// Blocks until the sampler is closed.
func (wp *WorkerPool) Start(s *Sampler) {
	if wp.workers == 1 {
		wp.runDirect(s)
		return
	}
	wp.runParallel(s)
}

// Workers returns the configured worker count.
func (wp *WorkerPool) Workers() int { return wp.workers }

// runDirect is the single-threaded fast path (workers=1).
// No channels, no extra goroutines — identical to the original code path.
func (wp *WorkerPool) runDirect(s *Sampler) {
	parser := NewPacketParser()
	s.Run(func(sample Sample) {
		ps := parser.Parse(sample.Data, sample.PktLen)
		if ps.SrcIP == nil && ps.DstIP == nil {
			wp.batcher.Metrics.DecodeErrors.Add(1)
			return
		}
		wp.ParsedTotal.Add(1)
		wp.batcher.Add(ps)
		wp.flowTable.Add(ps)
	})
}

// runParallel is the multi-worker pipeline.
func (wp *WorkerPool) runParallel(s *Sampler) {
	// Create per-worker input channels
	rawChs := make([]chan Sample, wp.workers)
	for i := range rawChs {
		rawChs[i] = make(chan Sample, rawChSize)
	}

	// Shared output channel for parsed results
	parsedCh := make(chan PacketSample, parsedChSize)

	// Start workers
	var workerWg sync.WaitGroup
	for i := 0; i < wp.workers; i++ {
		workerWg.Add(1)
		go func(id int) {
			defer workerWg.Done()
			wp.workerLoop(id, rawChs[id], parsedCh)
		}(i)
	}

	// Start aggregator
	var aggDone sync.WaitGroup
	aggDone.Add(1)
	go func() {
		defer aggDone.Done()
		wp.aggregatorLoop(parsedCh)
	}()

	// Reader: read from ring buffer, round-robin dispatch
	var rr int
	s.Run(func(sample Sample) {
		ch := rawChs[rr%wp.workers]
		rr++
		select {
		case ch <- sample:
		default:
			wp.DispatchDropped.Add(1)
			s.DroppedUser.Add(1)
		}
	})

	// Sampler closed — close all raw channels to signal workers to drain and exit
	for _, ch := range rawChs {
		close(ch)
	}

	// Wait for all workers to finish parsing
	workerWg.Wait()

	// All workers done — close parsedCh to signal aggregator
	close(parsedCh)

	// Wait for aggregator to drain
	aggDone.Wait()

	log.Printf("worker_pool: shutdown complete (workers=%d parsed=%d dropped=%d)",
		wp.workers, wp.ParsedTotal.Load(), wp.DispatchDropped.Load())
}

// workerLoop runs in its own goroutine. Reads raw samples from rawCh,
// parses them with a per-worker PacketParser, and sends results to parsedCh.
func (wp *WorkerPool) workerLoop(id int, rawCh <-chan Sample, parsedCh chan<- PacketSample) {
	parser := NewPacketParser()
	for sample := range rawCh {
		ps := parser.Parse(sample.Data, sample.PktLen)
		if ps.SrcIP == nil && ps.DstIP == nil {
			wp.batcher.Metrics.DecodeErrors.Add(1)
			continue
		}
		wp.ParsedTotal.Add(1)
		parsedCh <- ps
	}
}

// aggregatorLoop runs in its own goroutine. Reads parsed PacketSamples
// and feeds them to FlowTable + Batcher. Single-threaded — no lock contention.
func (wp *WorkerPool) aggregatorLoop(parsedCh <-chan PacketSample) {
	for ps := range parsedCh {
		wp.batcher.Add(ps)
		wp.flowTable.Add(ps)
	}
}
