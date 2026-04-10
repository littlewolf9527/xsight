// Package threshold implements threshold inheritance tree and hard threshold detection.
package threshold

import (
	"context"
	"log"
	"net"
	"sync"

	"github.com/littlewolf9527/xsight/controller/internal/engine"
	"github.com/littlewolf9527/xsight/controller/internal/store"
)

// splitResult caches the ForPrefixSplit output to avoid per-tick allocation.
// Also pre-splits by direction to eliminate append allocations in Detector.Tick().
type splitResult struct {
	subnet     []engine.ResolvedThreshold
	internalIP []engine.ResolvedThreshold
	// Pre-split by direction (avoids per-tick append allocation in Detector.Tick)
	subnetRecv []engine.ResolvedThreshold
	subnetSend []engine.ResolvedThreshold
	ipRecv     []engine.ResolvedThreshold
	ipSend     []engine.ResolvedThreshold
}

// Tree manages the threshold inheritance hierarchy with Template support.
type Tree struct {
	mu              sync.RWMutex
	byPrefix        map[string][]engine.ResolvedThreshold
	bySplit         map[string]splitResult // pre-computed ForPrefixSplit cache
	allPrefixes     []string              // pre-computed prefix list
	prefixes        []prefixNode
	hasGlobalPrefix bool // true if 0.0.0.0/0 is an enabled watched prefix
}

type prefixNode struct {
	ID                  int
	Prefix              string
	ParentID            *int
	ThresholdTemplateID *int
	IPNet               *net.IPNet
}

// ruleKey is the override key for threshold deduplication.
type ruleKey struct {
	Decoder   string
	Unit      string
	Direction string
	Domain    string
}

func NewTree() *Tree {
	return &Tree{
		byPrefix: make(map[string][]engine.ResolvedThreshold),
	}
}

// Rebuild loads all prefixes, templates, and thresholds from DB and resolves inheritance.
func (t *Tree) Rebuild(ctx context.Context, s store.Store) error {
	prefixes, err := s.Prefixes().List(ctx)
	if err != nil {
		return err
	}
	thresholds, err := s.Thresholds().List(ctx)
	if err != nil {
		return err
	}

	// Build prefix nodes
	nodes := make([]prefixNode, 0, len(prefixes))
	nodeByID := make(map[int]*prefixNode)
	for _, p := range prefixes {
		if !p.Enabled {
			continue
		}
		_, ipnet, err := net.ParseCIDR(p.Prefix)
		if err != nil {
			log.Printf("threshold_tree: skip bad prefix %q: %v", p.Prefix, err)
			continue
		}
		n := prefixNode{ID: p.ID, Prefix: p.Prefix, ParentID: p.ParentID, ThresholdTemplateID: p.ThresholdTemplateID, IPNet: ipnet}
		nodes = append(nodes, n)
		nodeByID[p.ID] = &nodes[len(nodes)-1]
	}

	// Group thresholds by template_id and prefix_id
	threshByTemplate := make(map[int][]store.Threshold)
	threshByPrefix := make(map[int][]store.Threshold)
	for _, th := range thresholds {
		if !th.Enabled {
			continue
		}
		if th.TemplateID != nil {
			threshByTemplate[*th.TemplateID] = append(threshByTemplate[*th.TemplateID], th)
		}
		if th.PrefixID != nil {
			threshByPrefix[*th.PrefixID] = append(threshByPrefix[*th.PrefixID], th)
		}
	}

	// Resolve for each prefix
	result := make(map[string][]engine.ResolvedThreshold)
	for _, node := range nodes {
		resolved := resolveForPrefix(node, nodeByID, threshByTemplate, threshByPrefix)
		if len(resolved) > 0 {
			result[node.Prefix] = resolved
		}
	}

	// Pre-compute ForPrefixSplit cache and prefix list
	split := make(map[string]splitResult, len(result))
	for prefix, rules := range result {
		var s splitResult
		isGlobal := prefix == "0.0.0.0/0"
		for _, r := range rules {
			switch r.Domain {
			case "subnet":
				s.subnet = append(s.subnet, r)
			case "internal_ip":
				// 0.0.0.0/0 has no per-IP data (only global aggregate) — skip internal_ip rules
				if isGlobal {
					continue
				}
				s.internalIP = append(s.internalIP, r)
			}
		}
		// Pre-split by direction for Detector.Tick()
		for _, r := range s.subnet {
			if r.Direction == "sends" {
				s.subnetSend = append(s.subnetSend, r)
			} else {
				s.subnetRecv = append(s.subnetRecv, r)
			}
		}
		for _, r := range s.internalIP {
			if r.Direction == "sends" {
				s.ipSend = append(s.ipSend, r)
			} else {
				s.ipRecv = append(s.ipRecv, r)
			}
		}
		split[prefix] = s
	}

	allPfx := make([]string, 0, len(nodes))
	for _, n := range nodes {
		allPfx = append(allPfx, n.Prefix)
	}

	t.mu.Lock()
	t.byPrefix = result
	t.bySplit = split
	t.allPrefixes = allPfx
	t.prefixes = nodes
	// Check if 0.0.0.0/0 is in the enabled prefix list
	t.hasGlobalPrefix = false
	for _, p := range allPfx {
		if p == "0.0.0.0/0" {
			t.hasGlobalPrefix = true
			break
		}
	}
	t.mu.Unlock()

	total := 0
	for _, v := range result {
		total += len(v)
	}
	log.Printf("threshold_tree: rebuilt %d prefixes, %d resolved rules", len(result), total)
	return nil
}

// resolveForPrefix resolves thresholds for a prefix using:
//   Priority: per-prefix override > self template > parent template (recursive)
func resolveForPrefix(node prefixNode, nodeByID map[int]*prefixNode,
	threshByTemplate, threshByPrefix map[int][]store.Threshold) []engine.ResolvedThreshold {

	merged := make(map[ruleKey]engine.ResolvedThreshold)

	// 1. Walk parent chain to find template rules (lowest priority first)
	chain := collectAncestorChain(node, nodeByID)
	for i := len(chain) - 1; i >= 0; i-- {
		ancestor := chain[i]
		if ancestor.ThresholdTemplateID == nil {
			continue
		}
		isSelf := (ancestor.ID == node.ID)
		for _, th := range threshByTemplate[*ancestor.ThresholdTemplateID] {
			// inheritable=false rules only apply to the prefix that directly binds the template
			if !isSelf && !th.Inheritable {
				continue
			}
			key := ruleKey{Decoder: th.Decoder, Unit: th.Unit, Direction: th.Direction, Domain: th.Domain}
			merged[key] = thresholdToResolved(th, node)
		}
	}

	// 2. Apply per-prefix overrides from parent chain (parent first, child last = highest priority)
	for i := len(chain) - 1; i >= 0; i-- {
		ancestor := chain[i]
		isSelf := (ancestor.ID == node.ID)
		for _, th := range threshByPrefix[ancestor.ID] {
			if !isSelf && !th.Inheritable {
				continue
			}
			key := ruleKey{Decoder: th.Decoder, Unit: th.Unit, Direction: th.Direction, Domain: th.Domain}
			if th.Value == 0 {
				delete(merged, key) // cancel inheritance
				continue
			}
			merged[key] = thresholdToResolved(th, node)
		}
	}

	result := make([]engine.ResolvedThreshold, 0, len(merged))
	for _, r := range merged {
		result = append(result, r)
	}
	return result
}

func collectAncestorChain(node prefixNode, nodeByID map[int]*prefixNode) []prefixNode {
	chain := []prefixNode{node}
	cur := node.ParentID
	for cur != nil {
		parent := nodeByID[*cur]
		if parent == nil {
			break
		}
		chain = append(chain, *parent)
		cur = parent.ParentID
	}
	return chain
}

func thresholdToResolved(th store.Threshold, node prefixNode) engine.ResolvedThreshold {
	return engine.ResolvedThreshold{
		ThresholdID: th.ID,
		PrefixID:    node.ID,
		Prefix:      node.Prefix,
		Domain:      th.Domain,
		Direction:   th.Direction,
		Decoder:     th.Decoder,
		Unit:        th.Unit,
		Comparison:  th.Comparison,
		Value:       th.Value,
		ResponseID:  th.ResponseID,
	}
}

// ForPrefix returns the resolved thresholds for a given prefix.
func (t *Tree) ForPrefix(prefix string) []engine.ResolvedThreshold {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.byPrefix[prefix]
}

// ForPrefixSplit returns cached subnet-level and internal_ip-level rules.
// The returned slices must not be mutated by the caller.
func (t *Tree) ForPrefixSplit(prefix string) (subnet, internalIP []engine.ResolvedThreshold) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	s := t.bySplit[prefix]
	return s.subnet, s.internalIP
}

// ForPrefixDirectionSplit returns cached rules pre-split by domain AND direction.
// Zero allocation — all slices are computed at Rebuild() time.
func (t *Tree) ForPrefixDirectionSplit(prefix string) (subnetRecv, subnetSend, ipRecv, ipSend []engine.ResolvedThreshold) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	s := t.bySplit[prefix]
	return s.subnetRecv, s.subnetSend, s.ipRecv, s.ipSend
}

// AllPrefixes returns all tracked prefix CIDR strings.
// The returned slice must not be mutated by the caller.
func (t *Tree) AllPrefixes() []string {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.allPrefixes
}

// HasGlobalPrefix returns true if 0.0.0.0/0 is an enabled watched prefix.
// Used by StatsWriter to decide whether to write global_stats to the virtual ring.
func (t *Tree) HasGlobalPrefix() bool {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.hasGlobalPrefix
}

// FindPrefixForIP returns the most specific prefix containing the IP.
func (t *Tree) FindPrefixForIP(ip net.IP) string {
	t.mu.RLock()
	defer t.mu.RUnlock()
	var best string
	var bestOnes int
	for _, n := range t.prefixes {
		if n.IPNet.Contains(ip) {
			ones, _ := n.IPNet.Mask.Size()
			if ones > bestOnes {
				best = n.Prefix
				bestOnes = ones
			}
		}
	}
	return best
}
