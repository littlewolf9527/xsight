package flow

import (
	"net"
	"net/netip"
	"testing"
)

func TestPrefixTrieExactMatch(t *testing.T) {
	trie := NewPrefixTrie()
	trie.Rebuild([]string{"10.0.0.0/24", "192.168.1.0/24"})

	if m := trie.Match(net.ParseIP("10.0.0.50")); m != "10.0.0.0/24" {
		t.Errorf("expected 10.0.0.0/24, got %q", m)
	}
	if m := trie.Match(net.ParseIP("192.168.1.100")); m != "192.168.1.0/24" {
		t.Errorf("expected 192.168.1.0/24, got %q", m)
	}
}

func TestPrefixTrieLongestMatch(t *testing.T) {
	trie := NewPrefixTrie()
	trie.Rebuild([]string{"10.0.0.0/8", "10.0.0.0/16", "10.0.0.0/24"})

	// Should match the longest (most specific) prefix
	if m := trie.Match(net.ParseIP("10.0.0.50")); m != "10.0.0.0/24" {
		t.Errorf("expected longest match 10.0.0.0/24, got %q", m)
	}
	if m := trie.Match(net.ParseIP("10.0.1.50")); m != "10.0.0.0/16" {
		t.Errorf("expected 10.0.0.0/16, got %q", m)
	}
	if m := trie.Match(net.ParseIP("10.1.0.50")); m != "10.0.0.0/8" {
		t.Errorf("expected 10.0.0.0/8, got %q", m)
	}
}

func TestPrefixTrieNoMatch(t *testing.T) {
	trie := NewPrefixTrie()
	trie.Rebuild([]string{"10.0.0.0/24"})

	if m := trie.Match(net.ParseIP("192.168.1.1")); m != "" {
		t.Errorf("expected no match, got %q", m)
	}
}

func TestPrefixTrieIPv6(t *testing.T) {
	trie := NewPrefixTrie()
	trie.Rebuild([]string{"2001:db8::/32", "10.0.0.0/24"})

	if m := trie.Match(net.ParseIP("2001:db8::1")); m != "2001:db8::/32" {
		t.Errorf("expected 2001:db8::/32, got %q", m)
	}
	// IPv4 still works
	if m := trie.Match(net.ParseIP("10.0.0.1")); m != "10.0.0.0/24" {
		t.Errorf("expected 10.0.0.0/24, got %q", m)
	}
}

func TestPrefixTrieBadCIDRSkipped(t *testing.T) {
	trie := NewPrefixTrie()
	trie.Rebuild([]string{"not-a-cidr", "10.0.0.0/24", "also-bad"})

	if trie.Count() != 1 {
		t.Errorf("expected 1 valid prefix, got %d", trie.Count())
	}
	if m := trie.Match(net.ParseIP("10.0.0.1")); m != "10.0.0.0/24" {
		t.Errorf("expected 10.0.0.0/24, got %q", m)
	}
}

func TestPrefixTrieMatchAddrConsistency(t *testing.T) {
	trie := NewPrefixTrie()
	trie.Rebuild([]string{"10.0.0.0/24"})

	ip := net.ParseIP("10.0.0.50")
	addr, _ := netip.AddrFromSlice(ip)

	m1 := trie.Match(ip)
	m2 := trie.MatchAddr(addr)
	if m1 != m2 {
		t.Errorf("Match and MatchAddr disagree: %q vs %q", m1, m2)
	}

	// IPv4-mapped IPv6
	mapped := netip.AddrFrom16(addr.As16())
	m3 := trie.MatchAddr(mapped)
	if m1 != m3 {
		t.Errorf("Match and MatchAddr(mapped) disagree: %q vs %q", m1, m3)
	}
}

func TestPrefixTrieRebuild(t *testing.T) {
	trie := NewPrefixTrie()
	trie.Rebuild([]string{"10.0.0.0/24"})
	if trie.Count() != 1 {
		t.Fatalf("expected 1, got %d", trie.Count())
	}

	trie.Rebuild([]string{"192.168.0.0/16", "172.16.0.0/12"})
	if trie.Count() != 2 {
		t.Fatalf("expected 2, got %d", trie.Count())
	}
	if m := trie.Match(net.ParseIP("10.0.0.1")); m != "" {
		t.Errorf("old prefix should not match after rebuild, got %q", m)
	}
}
