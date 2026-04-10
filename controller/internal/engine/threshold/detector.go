package threshold

import (
	"net"
	"time"

	"github.com/littlewolf9527/xsight/controller/internal/engine"
	"github.com/littlewolf9527/xsight/controller/internal/store/ring"
	"github.com/littlewolf9527/xsight/shared/decoder"
)

// Detector performs per-second threshold checking against ring buffer data.
type Detector struct {
	tree  *Tree
	rings *ring.RingStore
}

func NewDetector(tree *Tree, rings *ring.RingStore) *Detector {
	return &Detector{tree: tree, rings: rings}
}

// Tick checks all active data against thresholds for each connected node.
// v2.11 Phase 2: rules are split by direction — receives checks inbound rings, sends checks outbound rings.
func (d *Detector) Tick(connectedNodes []string) []engine.ThresholdExceeded {
	var exceeded []engine.ThresholdExceeded

	for _, nodeID := range connectedNodes {
		for _, prefix := range d.tree.AllPrefixes() {
			// Pre-split by direction — zero allocation (cached at tree Rebuild time)
			subnetRecv, subnetSend, ipRecv, ipSend := d.tree.ForPrefixDirectionSplit(prefix)

			// --- Inbound (receives) subnet rules → inbound prefix ring ---
			if len(subnetRecv) > 0 {
				pr := d.rings.GetPrefixRing(nodeID, prefix)
				if pr != nil {
					if dp, ok := pr.LatestOne(5 * time.Second); ok {
						for _, r := range subnetRecv {
							if breach := checkRule(r, dp, prefix, nil, nodeID); breach != nil {
								exceeded = append(exceeded, *breach)
							}
						}
					}
				}
			}

			// --- Outbound (sends) subnet rules → outbound prefix ring ---
			if len(subnetSend) > 0 {
				pr := d.rings.GetSrcPrefixRing(nodeID, prefix)
				if pr != nil {
					if dp, ok := pr.LatestOne(5 * time.Second); ok {
						for _, r := range subnetSend {
							if breach := checkRule(r, dp, prefix, nil, nodeID); breach != nil {
								exceeded = append(exceeded, *breach)
							}
						}
					}
				}
			}

			// --- Inbound (receives) per-IP rules → inbound IP rings ---
			// IPKeysForPrefix copies the key slice under RLock then releases it.
			// Do NOT use ForEach callback — it holds RLock during iteration,
			// causing self-deadlock when callback re-enters RLock and a writer is pending.
			if len(ipRecv) > 0 {
				for _, ipStr := range d.rings.IPKeysForPrefix(nodeID, prefix) {
					ir := d.rings.GetIPRingByKey(nodeID, prefix, ipStr)
					if ir == nil {
						continue
					}
					dp, ok := ir.LatestOne(5 * time.Second)
					if !ok {
						continue
					}
					for _, r := range ipRecv {
						if breach := checkRuleStr(r, dp, prefix, ipStr, nodeID); breach != nil {
							exceeded = append(exceeded, *breach)
						}
					}
				}
			}

			// --- Outbound (sends) per-IP rules → outbound IP rings ---
			if len(ipSend) > 0 {
				for _, ipStr := range d.rings.SrcIPKeysForPrefix(nodeID, prefix) {
					ir := d.rings.GetSrcIPRingByKey(nodeID, prefix, ipStr)
					if ir == nil {
						continue
					}
					dp, ok := ir.LatestOne(5 * time.Second)
					if !ok {
						continue
					}
					for _, r := range ipSend {
						if breach := checkRuleStr(r, dp, prefix, ipStr, nodeID); breach != nil {
							exceeded = append(exceeded, *breach)
						}
					}
				}
			}
		}
	}

	return exceeded
}

// evaluateRule is the shared rule evaluation logic used by both checkRule and checkRuleStr.
// Returns (actual value, breached) or (-1, false) if the rule should be skipped.
func evaluateRule(r engine.ResolvedThreshold, dp ring.DataPoint) (int64, bool) {
	var actual int64
	if r.Decoder == "ip" {
		actual = selectUnit(r.Unit, dp.PPS, dp.BPS, dp.PPS)
	} else {
		idx := decoder.Index(r.Decoder)
		if idx < 0 {
			return -1, false
		}
		actual = selectUnit(r.Unit, int64(dp.DecoderPPS[idx]), dp.DecoderBPS[idx], dp.PPS)
	}

	switch r.Comparison {
	case "over":
		return actual, actual > r.Value
	case "under":
		return actual, actual < r.Value
	}
	return actual, false
}

// checkRule evaluates a threshold rule with a net.IP (used for subnet-level checks).
func checkRule(r engine.ResolvedThreshold, dp ring.DataPoint, prefix string, ip net.IP, nodeID string) *engine.ThresholdExceeded {
	actual, breached := evaluateRule(r, dp)
	if !breached {
		return nil
	}
	return &engine.ThresholdExceeded{
		DstIP:       ip,
		Prefix:      prefix,
		PrefixID:    r.PrefixID,
		Direction:   r.Direction,
		Decoder:     r.Decoder,
		Unit:        r.Unit,
		ThresholdID: r.ThresholdID,
		ResponseID:  r.ResponseID,
		Value:       r.Value,
		Actual:      actual,
		Domain:      r.Domain,
		NodeID:      nodeID,
	}
}

// checkRuleStr is the string-key variant for the hot detection path.
// It avoids net.ParseIP allocation by only parsing the IP on breach (rare).
func checkRuleStr(r engine.ResolvedThreshold, dp ring.DataPoint, prefix, ipStr, nodeID string) *engine.ThresholdExceeded {
	actual, breached := evaluateRule(r, dp)
	if !breached {
		return nil
	}
	return &engine.ThresholdExceeded{
		DstIP:       net.ParseIP(ipStr), // only allocates on breach (rare path)
		Prefix:      prefix,
		PrefixID:    r.PrefixID,
		Direction:   r.Direction,
		Decoder:     r.Decoder,
		Unit:        r.Unit,
		ThresholdID: r.ThresholdID,
		ResponseID:  r.ResponseID,
		Value:       r.Value,
		Actual:      actual,
		Domain:      r.Domain,
		NodeID:      nodeID,
	}
}

func selectUnit(unit string, pps, bps, totalPPS int64) int64 {
	switch unit {
	case "bps":
		return bps
	case "pct":
		if totalPPS == 0 {
			return 0
		}
		return pps * 100 / totalPPS
	default:
		return pps
	}
}
