package sampler

import (
	"net"
	"testing"
	"time"
)

func TestBatcherUniqueSourcesBoundedByResetWindow(t *testing.T) {
	const (
		windows          = 32
		uniquePerWindow  = 256
		maxCountPerBatch = 8
	)

	b := NewBatcher(BatchConfig{
		MaxCount:   maxCountPerBatch,
		MaxBytes:   1 << 20,
		MaxLatency: time.Hour,
	}, func([]PacketSample) {})
	defer b.Close()

	for window := 0; window < windows; window++ {
		for i := 0; i < uniquePerWindow; i++ {
			b.Add(PacketSample{
				SrcIP: net.IPv4(byte(window), byte(i>>8), byte(i), 1),
			})
		}

		if got := b.ResetUniqueSources(); got != uniquePerWindow {
			t.Fatalf("window %d reset count = %d, want %d", window, got, uniquePerWindow)
		}
		if got := b.UniqueSourceCount(); got != 0 {
			t.Fatalf("window %d live count after reset = %d, want 0", window, got)
		}
	}

	wantBatches := uint64(windows * uniquePerWindow / maxCountPerBatch)
	if got := b.Metrics.BatchesSent.Load(); got != wantBatches {
		t.Fatalf("BatchesSent = %d, want %d", got, wantBatches)
	}
}

func TestBatcherResetUniqueSources(t *testing.T) {
	b := NewBatcher(DefaultBatchConfig(), func([]PacketSample) {})
	defer b.Close()

	for i := 0; i < 10; i++ {
		b.Add(PacketSample{SrcIP: net.IPv4(10, 0, 0, byte(i))})
	}

	if got := b.ResetUniqueSources(); got != 10 {
		t.Fatalf("ResetUniqueSources() = %d, want 10", got)
	}
	if got := b.UniqueSourceCount(); got != 0 {
		t.Fatalf("UniqueSourceCount() after reset = %d, want 0", got)
	}
	if got := b.ResetUniqueSources(); got != 0 {
		t.Fatalf("second ResetUniqueSources() = %d, want 0", got)
	}
}

func TestBatcherUniqueSourceCountDoesNotReset(t *testing.T) {
	b := NewBatcher(DefaultBatchConfig(), func([]PacketSample) {})
	defer b.Close()

	b.Add(PacketSample{SrcIP: net.IPv4(10, 0, 0, 1)})
	b.Add(PacketSample{SrcIP: net.IPv4(10, 0, 0, 1)})
	b.Add(PacketSample{SrcIP: net.IPv4(10, 0, 0, 2)})

	if got := b.UniqueSourceCount(); got != 2 {
		t.Fatalf("first UniqueSourceCount() = %d, want 2", got)
	}
	if got := b.UniqueSourceCount(); got != 2 {
		t.Fatalf("second UniqueSourceCount() = %d, want 2", got)
	}
}
