package action

// v1.2 Phase 9: FRR orphan detection.
//
// BootstrapBGPOrphans runs once at controller startup after RecoverBGPRoutes.
// It scans FRR running-config + BGP RIB for prefixes that are not represented
// in bgp_announcements (non-withdrawn), and marks them as:
//
//   - dismissed_on_upgrade  — if this is the very first v1.2 startup on this
//                             deployment (no operational history yet).
//                             Suppresses the banner to avoid scaring operators
//                             with pre-existing FRR state from v1.1/manual work.
//   - orphan                — otherwise. Surfaces in the Mitigations warning
//                             banner so the operator can Dismiss / Force Withdraw.
//
// Idempotent. The UpsertOrphan SQL only overwrites rows whose current status
// is 'withdrawn' — so operator-dismissed rows never get re-pestered, and
// active/delayed routes are never demoted.
//
// Scope: this bootstrap only handles orphan detection. The roadmap's phase-C
// "attack record but FRR missing → re-announce" compensation is a separate
// path covered by RecoverBGPRoutes (which re-injects vtysh commands for
// active attacks' BGP success logs). A unified reconciliation that also
// re-creates bgp_announcement rows from historical logs is out of scope for
// v1.2 — deferred to v1.2.1 if needed.

import (
	"context"
	"fmt"
	"log"
	"net"
	"regexp"
	"strings"

	"github.com/littlewolf9527/xsight/controller/internal/store"
)

const (
	bgpOrphanStatusRuntime = "orphan"
	bgpOrphanStatusUpgrade = "dismissed_on_upgrade"
)

// routeKey identifies one BGP announcement row at (prefix, route_map).
// connector_id is added by the caller when matching parsed FRR output to
// configured connectors.
type routeKey struct {
	Prefix   string
	RouteMap string
}

// BootstrapBGPOrphans scans FRR once at startup and creates orphan marker
// rows for prefixes that the controller does not know about.
func BootstrapBGPOrphans(ctx context.Context, s store.Store) {
	connectors, err := s.BGPConnectors().List(ctx)
	if err != nil {
		log.Printf("bgp bootstrap: list connectors: %v", err)
		return
	}
	if len(connectors) == 0 {
		return
	}

	hadHistory, err := s.BGPAnnouncements().HasOperationalHistory(ctx)
	if err != nil {
		log.Printf("bgp bootstrap: check history: %v", err)
		return
	}

	orphanStatus := bgpOrphanStatusRuntime
	if !hadHistory {
		orphanStatus = bgpOrphanStatusUpgrade
	}

	// Probe each unique vtysh path once — multiple connectors on the same
	// host typically share /usr/bin/vtysh.
	type probe struct {
		runningConfig string
		rib           map[string]bool
	}
	probes := make(map[string]*probe)
	for _, conn := range connectors {
		if !conn.Enabled || conn.VtyshPath == "" {
			continue
		}
		if _, ok := probes[conn.VtyshPath]; ok {
			continue
		}
		p := &probe{rib: make(map[string]bool)}
		out, err := runVtysh(ctx, conn.VtyshPath, "show running-config")
		if err != nil {
			log.Printf("bgp bootstrap: show running-config %q: %v", conn.VtyshPath, err)
			continue
		}
		p.runningConfig = out
		for _, af := range []string{"ipv4 unicast", "ipv6 unicast"} {
			out, err := runVtysh(ctx, conn.VtyshPath, "show bgp "+af)
			if err != nil {
				// AF may not be configured on this FRR — not fatal.
				continue
			}
			for pfx := range parseBGPRIBPrefixes(out) {
				p.rib[pfx] = true
			}
		}
		probes[conn.VtyshPath] = p
	}

	totalFound, newlyMarked := 0, 0
	for _, conn := range connectors {
		if !conn.Enabled {
			continue
		}
		p, ok := probes[conn.VtyshPath]
		if !ok {
			continue
		}
		routes := parseRunningConfigRoutes(p.runningConfig, conn.BGPASN)
		for key := range routes {
			totalFound++
			// Config + RIB must both confirm the route is live. A `network`
			// line without a RIB entry is either config-only leftover or a
			// race; don't surface it in the banner.
			if !p.rib[key.Prefix] {
				continue
			}
			created, err := s.BGPAnnouncements().UpsertOrphan(ctx, key.Prefix, key.RouteMap, conn.ID, orphanStatus)
			if err != nil {
				log.Printf("bgp bootstrap: upsert %s/%s connector=%d: %v",
					key.Prefix, key.RouteMap, conn.ID, err)
				continue
			}
			if created {
				newlyMarked++
				log.Printf("bgp bootstrap: orphan %s route-map=%s connector=%d status=%s",
					key.Prefix, key.RouteMap, conn.ID, orphanStatus)
			}
		}
	}
	log.Printf("bgp bootstrap: scanned=%d marked=%d first_boot=%v",
		totalFound, newlyMarked, !hadHistory)
}

// parseRunningConfigRoutes extracts `network <prefix> route-map <name>`
// entries under the `router bgp <asn>` block that matches our connector's
// ASN. Lines are matched regardless of being inside an `address-family`
// stanza, which is how FRR emits both IPv4 and IPv6 networks.
func parseRunningConfigRoutes(output string, asn int) map[routeKey]bool {
	out := make(map[routeKey]bool)
	ourMarker := fmt.Sprintf("router bgp %d", asn)
	inOurBGP := false

	for _, raw := range strings.Split(output, "\n") {
		line := strings.TrimSpace(raw)
		if strings.HasPrefix(line, "router bgp ") {
			inOurBGP = line == ourMarker
			continue
		}
		if inOurBGP && line == "!" {
			// `!` inside the `router bgp` block is a separator, not a
			// block end. FRR's real end is the next un-indented stanza.
			continue
		}
		// A top-level (un-indented) line not starting with `router bgp` ends
		// our block. In practice FRR indents everything inside, so any line
		// that equals trimmed-self at index 0 of the raw form and doesn't
		// match our prefix is outside. Keep it simple: look for the next
		// `router bgp <other_asn>` or `line vty` etc.
		if strings.HasPrefix(line, "router bgp ") && line != ourMarker {
			inOurBGP = false
			continue
		}
		if !inOurBGP {
			continue
		}
		if !strings.HasPrefix(line, "network ") {
			continue
		}
		parts := strings.Fields(line)
		// Expected shape: network <prefix> route-map <name>
		// Ignore plain `network X` (no route-map) — those are customer-
		// announced routes, not xSight-managed mitigations.
		if len(parts) >= 4 && parts[2] == "route-map" {
			out[routeKey{Prefix: parts[1], RouteMap: parts[3]}] = true
		}
	}
	return out
}

// bgpRIBPrefixTokenRegex picks out a prefix/length token anywhere in a line.
// We rely on net.ParseCIDR to validate before accepting, so false positives
// (IP addresses, non-CIDR tokens) are filtered downstream. This is more
// robust than trying to match the full "status code | prefix" shape because
// FRR emits data rows without status characters when routes aren't validated
// or best-path selected (e.g., a stand-alone `network X route-map Y`
// injected with no peers receiving it).
var bgpRIBPrefixTokenRegex = regexp.MustCompile(`\b([0-9a-fA-F:.]+/\d+)\b`)

// bgpRIBHeaderPrefixes — data rows are anything that doesn't start with one
// of these labels. Whitespace-only lines are also filtered.
var bgpRIBHeaderPrefixes = []string{
	"BGP table", "Status codes:", "Origin codes:", "Network",
	"Default local", "Nexthop codes:", "RPKI validation",
	"Displayed", "Total number", "No BGP",
}

func isBGPRIBHeaderLine(line string) bool {
	trimmed := strings.TrimSpace(line)
	if trimmed == "" {
		return true
	}
	for _, p := range bgpRIBHeaderPrefixes {
		if strings.HasPrefix(trimmed, p) {
			return true
		}
	}
	return false
}

// parseBGPRIBPrefixes returns the set of prefixes FRR reports as present in
// the BGP RIB. Header lines are skipped; on each data row the first CIDR-
// shaped token that parses as a valid prefix is taken as the row's prefix
// column (BGP output always places the prefix in column 1 of the table).
func parseBGPRIBPrefixes(output string) map[string]bool {
	out := make(map[string]bool)
	for _, raw := range strings.Split(output, "\n") {
		if isBGPRIBHeaderLine(raw) {
			continue
		}
		for _, m := range bgpRIBPrefixTokenRegex.FindAllStringSubmatch(raw, -1) {
			if _, _, err := net.ParseCIDR(m[1]); err == nil {
				out[m[1]] = true
				break
			}
		}
	}
	return out
}

// ParseRunningConfigRoutesForTest is a test-only wrapper that flattens the
// routeKey map into string keys ("prefix|routemap") for easier assertions
// from the external tests package.
func ParseRunningConfigRoutesForTest(output string, asn int) map[string]bool {
	in := parseRunningConfigRoutes(output, asn)
	out := make(map[string]bool, len(in))
	for k := range in {
		out[k.Prefix+"|"+k.RouteMap] = true
	}
	return out
}

// ParseBGPRIBPrefixesForTest exposes parseBGPRIBPrefixes to the tests
// package. Kept as a thin wrapper so the production surface stays small.
func ParseBGPRIBPrefixesForTest(output string) map[string]bool {
	return parseBGPRIBPrefixes(output)
}
