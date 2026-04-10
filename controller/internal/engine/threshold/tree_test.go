package threshold

import (
	"testing"

	"github.com/littlewolf9527/xsight/controller/internal/engine"
)

// TestForPrefixSplitCached verifies that ForPrefixSplit returns cached results
// that match the underlying byPrefix data after manual setup.
func TestForPrefixSplitCached(t *testing.T) {
	tree := NewTree()

	// Manually populate tree state (simulating what Rebuild does)
	rules := []engine.ResolvedThreshold{
		{ThresholdID: 1, Domain: "subnet", Decoder: "ip", Unit: "pps", Comparison: "over", Value: 1000},
		{ThresholdID: 2, Domain: "internal_ip", Decoder: "tcp", Unit: "pps", Comparison: "over", Value: 500},
		{ThresholdID: 3, Domain: "internal_ip", Decoder: "udp", Unit: "pps", Comparison: "over", Value: 300},
	}

	tree.mu.Lock()
	tree.byPrefix = map[string][]engine.ResolvedThreshold{
		"10.0.0.0/24": rules,
	}
	// Build split cache
	split := make(map[string]splitResult)
	for prefix, rs := range tree.byPrefix {
		var s splitResult
		for _, r := range rs {
			switch r.Domain {
			case "subnet":
				s.subnet = append(s.subnet, r)
			case "internal_ip":
				s.internalIP = append(s.internalIP, r)
			}
		}
		split[prefix] = s
	}
	tree.bySplit = split
	tree.allPrefixes = []string{"10.0.0.0/24"}
	tree.mu.Unlock()

	// Verify ForPrefixSplit
	subnet, ip := tree.ForPrefixSplit("10.0.0.0/24")
	if len(subnet) != 1 {
		t.Errorf("subnet rules = %d, want 1", len(subnet))
	}
	if len(ip) != 2 {
		t.Errorf("internal_ip rules = %d, want 2", len(ip))
	}
	if subnet[0].ThresholdID != 1 {
		t.Errorf("subnet[0].ThresholdID = %d, want 1", subnet[0].ThresholdID)
	}

	// Verify AllPrefixes
	prefixes := tree.AllPrefixes()
	if len(prefixes) != 1 || prefixes[0] != "10.0.0.0/24" {
		t.Errorf("AllPrefixes = %v, want [10.0.0.0/24]", prefixes)
	}

	// Non-existent prefix
	s, i := tree.ForPrefixSplit("192.168.0.0/24")
	if len(s) != 0 || len(i) != 0 {
		t.Error("expected empty results for non-existent prefix")
	}
}

// TestCacheInvalidationOnRebuild verifies that updating the tree
// (simulating Rebuild) properly refreshes the cached split and prefix list.
func TestCacheInvalidationOnRebuild(t *testing.T) {
	tree := NewTree()

	// Initial state
	tree.mu.Lock()
	tree.byPrefix = map[string][]engine.ResolvedThreshold{
		"10.0.0.0/24": {{ThresholdID: 1, Domain: "subnet"}},
	}
	tree.bySplit = map[string]splitResult{
		"10.0.0.0/24": {subnet: []engine.ResolvedThreshold{{ThresholdID: 1, Domain: "subnet"}}},
	}
	tree.allPrefixes = []string{"10.0.0.0/24"}
	tree.mu.Unlock()

	subnet, _ := tree.ForPrefixSplit("10.0.0.0/24")
	if len(subnet) != 1 {
		t.Fatal("initial state wrong")
	}

	// Simulate rebuild with new data (replace all caches atomically)
	tree.mu.Lock()
	tree.byPrefix = map[string][]engine.ResolvedThreshold{
		"172.16.0.0/16": {
			{ThresholdID: 10, Domain: "subnet"},
			{ThresholdID: 11, Domain: "internal_ip"},
		},
	}
	tree.bySplit = map[string]splitResult{
		"172.16.0.0/16": {
			subnet:     []engine.ResolvedThreshold{{ThresholdID: 10, Domain: "subnet"}},
			internalIP: []engine.ResolvedThreshold{{ThresholdID: 11, Domain: "internal_ip"}},
		},
	}
	tree.allPrefixes = []string{"172.16.0.0/16"}
	tree.mu.Unlock()

	// Old prefix should be gone
	s, i := tree.ForPrefixSplit("10.0.0.0/24")
	if len(s) != 0 || len(i) != 0 {
		t.Error("old prefix should not exist after rebuild")
	}

	// New prefix should be present
	s, i = tree.ForPrefixSplit("172.16.0.0/16")
	if len(s) != 1 || s[0].ThresholdID != 10 {
		t.Errorf("new subnet = %v, want [{ThresholdID:10}]", s)
	}
	if len(i) != 1 || i[0].ThresholdID != 11 {
		t.Errorf("new internal_ip = %v, want [{ThresholdID:11}]", i)
	}

	// AllPrefixes should reflect new state
	prefixes := tree.AllPrefixes()
	if len(prefixes) != 1 || prefixes[0] != "172.16.0.0/16" {
		t.Errorf("AllPrefixes = %v, want [172.16.0.0/16]", prefixes)
	}
}
