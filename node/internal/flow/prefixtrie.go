package flow

import (
	"net"
	"net/netip"
	"sort"
	"sync"
)

// PrefixTrie is a Go userspace LPM (Longest Prefix Match) trie.
// Used by Flow Node to match flow record IPs against watch_prefixes.
// Thread-safe for concurrent reads; Rebuild() is exclusive.
type PrefixTrie struct {
	mu       sync.RWMutex
	prefixes []prefixEntry
}

type prefixEntry struct {
	prefix netip.Prefix
	cidr   string // original CIDR string for return value
}

// NewPrefixTrie creates an empty trie.
func NewPrefixTrie() *PrefixTrie {
	return &PrefixTrie{}
}

// Rebuild replaces the entire trie with new prefixes.
// Called when Controller pushes new watch_prefixes via ConfigPush.
func (t *PrefixTrie) Rebuild(cidrs []string) {
	t.mu.Lock()
	defer t.mu.Unlock()

	t.prefixes = t.prefixes[:0]
	for _, cidr := range cidrs {
		p, err := netip.ParsePrefix(cidr)
		if err != nil {
			continue
		}
		t.prefixes = append(t.prefixes, prefixEntry{prefix: p.Masked(), cidr: cidr})
	}
	// Sort by prefix length descending (longest first) for LPM
	sort.Slice(t.prefixes, func(i, j int) bool {
		return t.prefixes[i].prefix.Bits() > t.prefixes[j].prefix.Bits()
	})
}

// Match returns the longest matching prefix CIDR for the given IP, or "" if no match.
func (t *PrefixTrie) Match(ip net.IP) string {
	addr, ok := netip.AddrFromSlice(ip)
	if !ok {
		return ""
	}
	addr = addr.Unmap() // normalize IPv4-mapped IPv6

	t.mu.RLock()
	defer t.mu.RUnlock()

	for _, e := range t.prefixes {
		if e.prefix.Contains(addr) {
			return e.cidr
		}
	}
	return ""
}

// MatchAddr is like Match but takes netip.Addr directly (avoids allocation).
func (t *PrefixTrie) MatchAddr(addr netip.Addr) string {
	addr = addr.Unmap() // normalize IPv4-mapped IPv6, consistent with Match()

	t.mu.RLock()
	defer t.mu.RUnlock()

	for _, e := range t.prefixes {
		if e.prefix.Contains(addr) {
			return e.cidr
		}
	}
	return ""
}

// Count returns the number of prefixes in the trie.
func (t *PrefixTrie) Count() int {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return len(t.prefixes)
}
