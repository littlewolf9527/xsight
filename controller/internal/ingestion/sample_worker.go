package ingestion

import (
	"log"
	"sync"
	"sync/atomic"

	pb "github.com/littlewolf9527/xsight/controller/internal/pb"
)

// SampleMetrics tracks sample processing statistics.
// Reference: brainstorm-controller.md "SampleStream performance budget"
type SampleMetrics struct {
	ReceivedTotal atomic.Uint64
	DroppedTotal  atomic.Uint64
	ParseErrors   atomic.Uint64
}

// SampleWorkerPool manages per-Node sample processing channels.
// Design: per-Node channel (cap 1024), drop oldest when full,
// 2 workers per Node, max 20 total workers.
const maxTotalWorkers = 20 // brainstorm: "2 workers per Node, total <= 20"

type SampleWorkerPool struct {
	mu           sync.RWMutex
	channels     map[string]chan *pb.SampleBatch // nodeID → channel
	Metrics      SampleMetrics
	wg           sync.WaitGroup
	handler      SampleHandler
	workerCount  int // current total workers across all nodes
}

// SampleHandler is called for each received SampleBatch.
// Phase 1: logs/counts. Later phases: gopacket DPI + classifier feed.
type SampleHandler func(nodeID string, batch *pb.SampleBatch)

// NewSampleWorkerPool creates a new pool with the given handler.
func NewSampleWorkerPool(handler SampleHandler) *SampleWorkerPool {
	return &SampleWorkerPool{
		channels: make(map[string]chan *pb.SampleBatch),
		handler:  handler,
	}
}

// Submit sends a SampleBatch to the node's channel.
// Drops oldest if full (brainstorm: "drop oldest").
func (p *SampleWorkerPool) Submit(nodeID string, batch *pb.SampleBatch) {
	p.Metrics.ReceivedTotal.Add(uint64(len(batch.Samples)))

	p.mu.RLock()
	ch, ok := p.channels[nodeID]
	p.mu.RUnlock()

	if !ok {
		p.mu.Lock()
		ch, ok = p.channels[nodeID]
		if !ok {
			ch = make(chan *pb.SampleBatch, 1024)
			p.channels[nodeID] = ch
			// Start up to 2 workers per Node, respecting global cap
			toStart := 2
			if p.workerCount+toStart > maxTotalWorkers {
				toStart = maxTotalWorkers - p.workerCount
			}
			for i := 0; i < toStart; i++ {
				p.wg.Add(1)
				p.workerCount++
				go p.worker(nodeID, ch)
			}
			if toStart > 0 {
				log.Printf("sample_worker: started %d workers for node %s (total=%d/%d)", toStart, nodeID, p.workerCount, maxTotalWorkers)
			} else {
				log.Printf("sample_worker: worker cap reached (%d/%d), node %s shares channel only", p.workerCount, maxTotalWorkers, nodeID)
			}
		}
		p.mu.Unlock()
	}

	select {
	case ch <- batch:
	default:
		// Channel full — drop oldest (drain one, push new)
		select {
		case old := <-ch:
			p.Metrics.DroppedTotal.Add(uint64(len(old.Samples)))
		default:
		}
		select {
		case ch <- batch:
		default:
			p.Metrics.DroppedTotal.Add(uint64(len(batch.Samples)))
		}
	}
}

func (p *SampleWorkerPool) worker(nodeID string, ch <-chan *pb.SampleBatch) {
	defer func() {
		p.mu.Lock()
		p.workerCount--
		p.mu.Unlock()
		p.wg.Done()
	}()
	for batch := range ch {
		p.handler(nodeID, batch)
	}
}

// RemoveNode closes the node's channel and stops its workers.
func (p *SampleWorkerPool) RemoveNode(nodeID string) {
	p.mu.Lock()
	ch, ok := p.channels[nodeID]
	if ok {
		delete(p.channels, nodeID)
		close(ch)
	}
	p.mu.Unlock()
}

// Close shuts down all workers.
func (p *SampleWorkerPool) Close() {
	p.mu.Lock()
	for id, ch := range p.channels {
		close(ch)
		delete(p.channels, id)
	}
	p.mu.Unlock()
	p.wg.Wait()
}
