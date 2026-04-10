package ingestion

import (
	"context"
	"log"
	"sync"
	"time"

	"github.com/littlewolf9527/xsight/controller/internal/store"
	"github.com/littlewolf9527/xsight/controller/internal/store/ring"
	"github.com/littlewolf9527/xsight/shared/decoder"
)

// DBWriter periodically flushes ring buffer data to ts_stats via pgx.CopyFrom.
// Multiple ticks are aggregated into one row per key (node+prefix or node+ip)
// to reduce write volume. The flush interval controls the time granularity
// of ts_stats (default 5s = 5-second resolution in historical data).
// Detection is NOT affected — it uses the in-memory ring buffer (1s granularity).
//
type DBWriter struct {
	rings    *ring.RingStore
	stats    store.StatsRepo
	interval time.Duration

	mu      sync.Mutex
	pending map[statKey]*statAcc // aggregation buffer
}

// statKey uniquely identifies a ts_stats row (node + prefix-or-IP + direction).
// v2.11 Phase 3: Direction added to prevent send/receive from merging in same flush window.
type statKey struct {
	NodeID    string
	DstIP     string // empty = prefix aggregate
	Prefix    string
	Direction string // "receives" | "sends"
}

// statAcc accumulates multiple ticks into one aggregated point.
type statAcc struct {
	FirstTime  time.Time // earliest timestamp in the window
	LastTime   time.Time // latest timestamp in the window
	Ticks      int       // number of ticks aggregated
	PPS        int64
	BPS        int64
	DecoderPPS [decoder.MaxDecoders]int64 // accumulated decoder PPS (sum of ticks, divided on flush)
	DecoderBPS [decoder.MaxDecoders]int64 // accumulated decoder BPS
}

func NewDBWriter(rings *ring.RingStore, stats store.StatsRepo, interval time.Duration) *DBWriter {
	if interval <= 0 {
		interval = 5 * time.Second
	}
	return &DBWriter{
		rings:    rings,
		stats:    stats,
		interval: interval,
		pending:  make(map[statKey]*statAcc),
	}
}

// Enqueue adds stat points to the aggregation buffer.
// Points with the same key are merged (summed) across ticks.
func (w *DBWriter) Enqueue(points []store.StatPoint) {
	w.mu.Lock()
	for i := range points {
		p := &points[i]
		key := statKey{NodeID: p.NodeID, Direction: p.Direction}
		if p.DstIP != nil {
			key.DstIP = *p.DstIP
		}
		if p.Prefix != nil {
			key.Prefix = *p.Prefix
		}

		acc, ok := w.pending[key]
		if !ok {
			acc = &statAcc{FirstTime: p.Time, LastTime: p.Time}
			w.pending[key] = acc
		}
		if p.Time.Before(acc.FirstTime) {
			acc.FirstTime = p.Time
		}
		if p.Time.After(acc.LastTime) {
			acc.LastTime = p.Time
		}
		acc.Ticks++
		acc.PPS += p.PPS
		acc.BPS += p.BPS
		for j := 0; j < decoder.MaxDecoders; j++ {
			acc.DecoderPPS[j] += int64(p.DecoderPPS[j])
			acc.DecoderBPS[j] += p.DecoderBPS[j]
		}
	}
	w.mu.Unlock()
}

// Run starts the background flush loop. Blocks until ctx is cancelled.
func (w *DBWriter) Run(ctx context.Context) {
	ticker := time.NewTicker(w.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			// Final flush
			w.flush(context.Background())
			return
		case <-ticker.C:
			w.flush(ctx)
		}
	}
}

func (w *DBWriter) flush(ctx context.Context) {
	w.mu.Lock()
	if len(w.pending) == 0 {
		w.mu.Unlock()
		return
	}
	agg := w.pending
	w.pending = make(map[statKey]*statAcc)
	w.mu.Unlock()

	// All points in one flush share the same timestamp (truncated to flush interval).
	// This ensures the chart's avg() doesn't mix timestamps with wildly different
	// row counts (which causes displayed values to be much lower than actual).
	flushTime := time.Now().Truncate(w.interval)

	// Convert aggregated data to StatPoints.
	// Values are averaged over ticks to maintain per-second semantics
	// (ts_stats stores rates like PPS/BPS, not totals).
	batch := make([]store.StatPoint, 0, len(agg))
	for key, acc := range agg {
		n := int64(acc.Ticks)
		if n == 0 {
			n = 1
		}
		dir := key.Direction
		if dir == "" {
			dir = "receives" // default for backward compat
		}
		sp := store.StatPoint{
			Time:      flushTime,
			NodeID:    key.NodeID,
			Direction: dir,
			PPS:       acc.PPS / n,
			BPS:       acc.BPS / n,
		}
		for j := 0; j < decoder.MaxDecoders; j++ {
			sp.DecoderPPS[j] = int32(acc.DecoderPPS[j] / n)
			sp.DecoderBPS[j] = acc.DecoderBPS[j] / n
		}
		if key.DstIP != "" {
			ip := key.DstIP
			sp.DstIP = &ip
		}
		if key.Prefix != "" {
			prefix := key.Prefix
			sp.Prefix = &prefix
		}
		batch = append(batch, sp)
	}

	if err := w.stats.BulkInsert(ctx, batch); err != nil {
		log.Printf("db_writer: bulk insert %d points failed: %v", len(batch), err)
		// Re-enqueue original accumulators (not averaged batch) to preserve tick weights.
		// This avoids distorting averages when merged with new incoming data.
		w.mu.Lock()
		for key, failedAcc := range agg {
			if len(w.pending) >= 100_000 {
				log.Printf("db_writer: dropping points (retry buffer full)")
				break
			}
			if existing, ok := w.pending[key]; ok {
				// Merge with data that arrived during our flush attempt
				existing.Ticks += failedAcc.Ticks
				existing.PPS += failedAcc.PPS
				existing.BPS += failedAcc.BPS
				for j := 0; j < decoder.MaxDecoders; j++ {
					existing.DecoderPPS[j] += failedAcc.DecoderPPS[j]
					existing.DecoderBPS[j] += failedAcc.DecoderBPS[j]
				}
				if failedAcc.FirstTime.Before(existing.FirstTime) {
					existing.FirstTime = failedAcc.FirstTime
				}
				if failedAcc.LastTime.After(existing.LastTime) {
					existing.LastTime = failedAcc.LastTime
				}
			} else {
				w.pending[key] = failedAcc
			}
		}
		w.mu.Unlock()
		return
	}

	log.Printf("db_writer: flushed %d points to ts_stats", len(batch))
}

// PendingCount returns the number of unique keys in the aggregation buffer.
func (w *DBWriter) PendingCount() int {
	w.mu.Lock()
	defer w.mu.Unlock()
	return len(w.pending)
}
