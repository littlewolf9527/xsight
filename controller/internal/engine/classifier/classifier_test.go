package classifier

import (
	"net"
	"testing"
	"time"

	pb "github.com/littlewolf9527/xsight/controller/internal/pb"
)

func TestAccumulatorBounds(t *testing.T) {
	tests := []struct {
		name       string
		uniqueDst  int
		sweepAfter time.Duration
		want       int
	}{
		{
			name:       "million destinations expire after TTL",
			uniqueDst:  1_000_000,
			sweepAfter: accumulatorMaxAge + time.Second,
			want:       0,
		},
		{
			name:      "destinations stay within hard cap",
			uniqueDst: maxAccumulators + 1_000,
			want:      maxAccumulators,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := New()
			ingestUniqueDestinations(c, tt.uniqueDst)

			if got := accumulatorCount(c); got > maxAccumulators {
				t.Fatalf("samples count = %d, want <= %d", got, maxAccumulators)
			}
			if tt.sweepAfter > 0 {
				c.Sweep(time.Now().Add(tt.sweepAfter))
			}
			if got := accumulatorCount(c); got != tt.want {
				t.Fatalf("samples count = %d, want %d", got, tt.want)
			}
			if got := accumulatorOrderCount(c); got != tt.want {
				t.Fatalf("sample order count = %d, want %d", got, tt.want)
			}
		})
	}
}

func TestSourcePortCapPreservesClassification(t *testing.T) {
	reflectionSamples := make([]uint32, 0, 6_001)
	for port := uint32(20_000); port < 22_001; port++ {
		reflectionSamples = append(reflectionSamples, port)
	}
	for i := 0; i < 4_000; i++ {
		reflectionSamples = append(reflectionSamples, 53)
	}

	uniformSamples := make([]uint32, 0, 2_001)
	for port := uint32(20_000); port < 22_001; port++ {
		uniformSamples = append(uniformSamples, port)
	}

	tests := []struct {
		name       string
		srcPorts   []uint32
		attackType string
	}{
		{
			name:       "known reflection port remains dominant after cap",
			srcPorts:   reflectionSamples,
			attackType: "dns_reflection",
		},
		{
			name:       "uniform distribution remains generic flood after cap",
			srcPorts:   uniformSamples,
			attackType: "generic_udp_flood",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := New()
			dstIP := net.IPv4(192, 0, 2, 1)
			c.Ingest(sampleBatch(dstIP, tt.srcPorts))

			if got := sourcePortCount(c, dstIP.String()); got > maxSrcPortsPerAccumulator {
				t.Fatalf("srcPorts count = %d, want <= %d", got, maxSrcPortsPerAccumulator)
			} else if got <= 10 {
				t.Fatalf("srcPorts count = %d, want > 10 to preserve the generic flood signal", got)
			}

			result := c.Classify(dstIP)
			if result == nil {
				t.Fatal("Classify() = nil, want classification")
			}
			if result.AttackType != tt.attackType {
				t.Fatalf("AttackType = %q, want %q", result.AttackType, tt.attackType)
			}
			if got := accumulatorCount(c); got != 0 {
				t.Fatalf("samples count after Classify = %d, want 0", got)
			}
			if got := accumulatorOrderCount(c); got != 0 {
				t.Fatalf("sample order count after Classify = %d, want 0", got)
			}
		})
	}
}

func TestSweepKeepsRecentlyUpdatedAccumulator(t *testing.T) {
	c := New()
	dstIP := net.IPv4(198, 51, 100, 10)
	batch := sampleBatch(dstIP, []uint32{53})

	steps := []struct {
		name        string
		update      bool
		sweepOffset time.Duration
		wantPresent bool
	}{
		{name: "active tick 1", update: true, sweepOffset: accumulatorMaxAge - time.Second, wantPresent: true},
		{name: "active tick 2", update: true, sweepOffset: accumulatorMaxAge - time.Second, wantPresent: true},
		{name: "active tick 3", update: true, sweepOffset: accumulatorMaxAge - time.Second, wantPresent: true},
		{name: "idle past TTL", sweepOffset: accumulatorMaxAge + time.Second, wantPresent: false},
	}

	for _, tt := range steps {
		t.Run(tt.name, func(t *testing.T) {
			if tt.update {
				c.Ingest(batch)
			}
			c.Sweep(time.Now().Add(tt.sweepOffset))
			if got := hasAccumulator(c, dstIP.String()); got != tt.wantPresent {
				t.Fatalf("accumulator present = %v, want %v", got, tt.wantPresent)
			}
		})
	}
}

func TestAccumulatorMaxAgeExceedsClassificationCycle(t *testing.T) {
	if accumulatorMaxAge < time.Minute {
		t.Fatalf("accumulatorMaxAge = %s, want at least 1m", accumulatorMaxAge)
	}
}

func ingestUniqueDestinations(c *Classifier, count int) {
	const batchSize = 4_096

	samples := make([]*pb.PacketSample, batchSize)
	for i := range samples {
		samples[i] = &pb.PacketSample{
			DstIp:      make([]byte, net.IPv4len),
			IpProtocol: 17,
			SrcPort:    53,
		}
	}
	batch := &pb.SampleBatch{}

	for start := 0; start < count; start += batchSize {
		batchCount := min(batchSize, count-start)
		batch.Samples = samples[:batchCount]
		for i, sample := range batch.Samples {
			n := uint32(start + i + 1)
			sample.DstIp[0] = byte(n >> 24)
			sample.DstIp[1] = byte(n >> 16)
			sample.DstIp[2] = byte(n >> 8)
			sample.DstIp[3] = byte(n)
		}
		c.Ingest(batch)
	}
}

func sampleBatch(dstIP net.IP, srcPorts []uint32) *pb.SampleBatch {
	samples := make([]*pb.PacketSample, len(srcPorts))
	for i, srcPort := range srcPorts {
		samples[i] = &pb.PacketSample{
			DstIp:      dstIP.To4(),
			IpProtocol: 17,
			SrcPort:    srcPort,
		}
	}
	return &pb.SampleBatch{Samples: samples}
}

func accumulatorCount(c *Classifier) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.samples)
}

func accumulatorOrderCount(c *Classifier) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.sampleOrder.Len()
}

func sourcePortCount(c *Classifier, dstIP string) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.samples[dstIP].srcPorts)
}

func hasAccumulator(c *Classifier, dstIP string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	_, ok := c.samples[dstIP]
	return ok
}
