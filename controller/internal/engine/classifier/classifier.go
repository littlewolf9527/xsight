// Package classifier identifies specific attack types from sample data.
package classifier

import (
	"net"
	"sync"

	"github.com/littlewolf9527/xsight/controller/internal/engine"
	pb "github.com/littlewolf9527/xsight/controller/internal/pb"
)

// Known reflection source ports.
// Reference: brainstorm-controller.md "src_port distribution identifies reflection/amplification types"
var reflectionPorts = map[uint32]string{
	53:    "dns_reflection",
	123:   "ntp_reflection",
	11211: "memcached_reflection",
	1900:  "ssdp_reflection",
	389:   "cldap_reflection",
	161:   "snmp_reflection",
	19:    "chargen_reflection",
}

// Classifier analyzes packet samples to identify specific attack types.
type Classifier struct {
	mu      sync.Mutex
	// Per dst_ip sample accumulator (reset after classification)
	samples map[string]*sampleAcc // dstIP string → accumulator
}

type sampleAcc struct {
	srcPorts map[uint32]int // src_port → count
	total    int
}

func New() *Classifier {
	return &Classifier{
		samples: make(map[string]*sampleAcc),
	}
}

// Ingest processes a SampleBatch, accumulating src_port distribution per dst_ip.
func (c *Classifier) Ingest(batch *pb.SampleBatch) {
	c.mu.Lock()
	defer c.mu.Unlock()

	for _, s := range batch.Samples {
		if s.IpProtocol != 17 { // UDP only for reflection classification
			continue
		}
		dstIP := net.IP(s.DstIp).String()
		acc, ok := c.samples[dstIP]
		if !ok {
			acc = &sampleAcc{srcPorts: make(map[uint32]int)}
			c.samples[dstIP] = acc
		}
		acc.srcPorts[s.SrcPort]++
		acc.total++
	}
}

// Classify analyzes accumulated samples for a dst_ip and returns a classification.
// Returns nil if insufficient data or no clear classification.
// Consumes (resets) the accumulated samples for this IP.
func (c *Classifier) Classify(dstIP net.IP) *engine.ClassificationResult {
	ipStr := dstIP.String()

	c.mu.Lock()
	acc, ok := c.samples[ipStr]
	if ok {
		delete(c.samples, ipStr) // consume
	}
	c.mu.Unlock()

	if !ok || acc.total < 10 {
		return nil // insufficient samples
	}

	// Find dominant src_port
	var dominantPort uint32
	var dominantCount int
	for port, count := range acc.srcPorts {
		if count > dominantCount {
			dominantPort = port
			dominantCount = count
		}
	}

	dominantRatio := float64(dominantCount) / float64(acc.total)

	// Check for known reflection attack (dominant port > 60% of samples)
	if dominantRatio > 0.6 {
		if attackType, known := reflectionPorts[dominantPort]; known {
			return &engine.ClassificationResult{
				DstIP:      dstIP,
				AttackType: attackType,
				Confidence: float32(dominantRatio),
				Reasons: []string{
					"src_port_dominant",
					portReason(dominantPort, dominantCount, acc.total),
				},
			}
		}
	}

	// Check for generic UDP flood (src_port distribution is uniform)
	uniquePorts := len(acc.srcPorts)
	if uniquePorts > 10 && dominantRatio < 0.3 {
		return &engine.ClassificationResult{
			DstIP:      dstIP,
			AttackType: "generic_udp_flood",
			Confidence: 0.7,
			Reasons:    []string{"src_port_uniform", "many_unique_ports"},
		}
	}

	return nil
}

// Reset clears all accumulated samples.
func (c *Classifier) Reset() {
	c.mu.Lock()
	c.samples = make(map[string]*sampleAcc)
	c.mu.Unlock()
}

func portReason(port uint32, count, total int) string {
	return "src_port_" + portName(port) + "_dominant"
}

func portName(port uint32) string {
	switch port {
	case 53:
		return "53_dns"
	case 123:
		return "123_ntp"
	case 11211:
		return "11211_memcached"
	case 1900:
		return "1900_ssdp"
	case 389:
		return "389_cldap"
	case 161:
		return "161_snmp"
	case 19:
		return "19_chargen"
	default:
		return "unknown"
	}
}
