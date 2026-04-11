// Package tracker implements the AttackTracker state machine.
package tracker

import (
	"context"
	"fmt"
	"log"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/littlewolf9527/xsight/controller/internal/engine"
	"github.com/littlewolf9527/xsight/controller/internal/engine/dedup"
	"github.com/littlewolf9527/xsight/controller/internal/store"
	"github.com/littlewolf9527/xsight/controller/internal/store/ring"
)

// Attack states
const (
	StateConfirming = "confirming"
	StateActive     = "active"
	StateExpiring   = "expiring"
	StateExpired    = "expired"
)

// Config holds tracker parameters.
type Config struct {
	HardConfirmSeconds     int     // default 3
	DynamicConfirmSeconds  int     // default 5
	ExpiryIntervalSeconds  int     // default 300
	ExpiryFunction         string  // "static" | "dynamic", default "static"
	ExpiryScaleBaseSeconds int     // attack duration for 1x scale (default 300)
	ExpiryMaxScale         float64 // max multiplier (default 4.0)
	MaxActiveAttacks       int     // default 10000, 0 = no limit
}

// attackKey uniquely identifies an attack.
// Reference: brainstorm-controller.md "Attack Identity"
type attackKey struct {
	DstIP         string // IP string or prefix CIDR for carpet bombing
	Direction     string
	DecoderFamily string
}

// trackedAttack is the in-memory state of a single attack.
type trackedAttack struct {
	Key       attackKey
	State     string
	DBID      int    // attacks table ID (0 until INSERT)
	Prefix    string // owning prefix CIDR

	// Confirmation
	ConsecutiveExceeded int
	ConfirmThreshold    int // seconds needed to confirm

	// Peak tracking
	PeakPPS    int64
	PeakBPS    int64
	CurrentPPS int64
	CurrentBPS int64

	// Threshold info
	PrefixID    int
	ThresholdID int
	ResponseID  *int
	Decoder     string
	Unit        string
	ThreshValue int64

	// Attack classification
	AttackType  string
	Severity    string
	ReasonCodes []string
	NodeSources []string

	// Timing
	FirstSeen time.Time
	LastSeen  time.Time
	ExpiresAt time.Time // only set in expiring state

	// Flags
	SeenThisTick bool // reset each tick, set when threshold exceeded
}

// ActionCallback is called when an attack state changes.
// Phase 5 wires this to the Action Engine.
type ActionCallback func(event AttackEvent)

// AttackEvent describes a state change in an attack's lifecycle.
type AttackEvent struct {
	Type   string // "confirmed" | "updated" | "type_upgrade" | "expired"
	Attack *store.Attack
	DBID   int
}

// Tracker manages the lifecycle of all tracked attacks.
type Tracker struct {
	mu       sync.RWMutex
	attacks  map[attackKey]*trackedAttack
	cfg      Config
	store    store.Store
	rings    *ring.RingStore
	dedup    *dedup.Dedup
	onAction ActionCallback

	// Periodic update tracking
	lastPeriodicUpdate time.Time

	// Metrics (read concurrently by API handlers)
	CreatedTotal    atomic.Int64
	SuppressedTotal atomic.Int64
	EvictedTotal    atomic.Int64
}

func New(cfg Config, s store.Store, rings *ring.RingStore, d *dedup.Dedup, onAction ActionCallback) *Tracker {
	return &Tracker{
		attacks:            make(map[attackKey]*trackedAttack),
		cfg:                cfg,
		rings:              rings,
		lastPeriodicUpdate: time.Now(),
		store:    s,
		dedup:    d,
		onAction: onAction,
	}
}

// Feed processes threshold exceeded events from the detection engine.
// Called after each detection tick (1/second).
func (t *Tracker) Feed(exceeded []engine.ThresholdExceeded) {
	t.mu.Lock()
	defer t.mu.Unlock()

	now := time.Now()

	// Reset per-tick flags
	for _, a := range t.attacks {
		a.SeenThisTick = false
	}

	// Process exceeded events
	for _, evt := range exceeded {
		dstIP := ""
		if evt.DstIP != nil {
			dstIP = evt.DstIP.String()
		} else if evt.Domain == "subnet" {
			dstIP = evt.Prefix // carpet bombing uses prefix as key
		}

		key := attackKey{
			DstIP:         dstIP,
			Direction:     evt.Direction,
			DecoderFamily: evt.Decoder,
		}

		a, exists := t.attacks[key]
		if !exists {
			// New potential attack — use confirm seconds based on detection source
			confirmSec := t.cfg.HardConfirmSeconds
			if evt.Source == "dynamic" {
				confirmSec = t.cfg.DynamicConfirmSeconds
			}
			a = &trackedAttack{
				Key:              key,
				State:            StateConfirming,
				Prefix:           evt.Prefix,
				PrefixID:         evt.PrefixID,
				ConfirmThreshold: confirmSec,
				Decoder:          evt.Decoder,
				Unit:             evt.Unit,
				ThresholdID:      evt.ThresholdID,
				ResponseID:       evt.ResponseID,
				ThreshValue:      evt.Value,
				FirstSeen:        now,
				NodeSources:      []string{evt.NodeID},
			}
			// Set initial attack type from decoder
			a.AttackType = decoderToAttackType(evt.Decoder)
			t.attacks[key] = a
		}

		a.SeenThisTick = true
		a.LastSeen = now
		// NOTE: ownership fields (PrefixID, ThresholdID, ResponseID) are intentionally NOT refreshed
		// on subsequent threshold hits. This is first-writer-wins: the earliest matching rule determines
		// the response binding for the entire attack lifecycle. Changing response mid-attack would risk
		// xDrop rule conflicts and inconsistent action execution.
		a.CurrentPPS = max(a.CurrentPPS, evt.Actual)
		if evt.Unit == "pps" && evt.Actual > a.PeakPPS {
			a.PeakPPS = evt.Actual
		}
		if evt.Unit == "bps" && evt.Actual > a.PeakBPS {
			a.PeakBPS = evt.Actual
		}

		// Add node source if new + protect its ring from eviction
		if evt.NodeID != "" {
			found := false
			for _, ns := range a.NodeSources {
				if ns == evt.NodeID {
					found = true
					break
				}
			}
			if !found {
				a.NodeSources = append(a.NodeSources, evt.NodeID)
				// Protect new node's IP ring from LRU eviction
				if a.State == StateActive {
					if ip := net.ParseIP(a.Key.DstIP); ip != nil && t.rings != nil {
						if a.Key.Direction == "sends" {
							t.rings.MarkSrcActive(evt.NodeID, a.Prefix, ip)
						} else {
							t.rings.MarkActive(evt.NodeID, a.Prefix, ip)
						}
					}
				}
			}
		}
	}

	// Tick state machine for all tracked attacks
	t.tick(now)
}

// tick advances all attack state machines.
func (t *Tracker) tick(now time.Time) {
	var toDelete []attackKey

	for key, a := range t.attacks {
		switch a.State {
		case StateConfirming:
			if a.SeenThisTick {
				a.ConsecutiveExceeded++
				if a.ConsecutiveExceeded >= a.ConfirmThreshold {
					t.transitionToActive(a, now)
				}
			} else {
				// Reset — not consecutive
				toDelete = append(toDelete, key)
			}

		case StateActive:
			if a.SeenThisTick {
				// Still active — peaks already updated in Feed.
				// Periodic update: emit attack_update every 5 minutes for ongoing attacks.
			} else {
				// Dropped below threshold → start expiry timer
				a.State = StateExpiring
				expirySec := t.cfg.ExpiryIntervalSeconds
				if t.cfg.ExpiryFunction == "dynamic" {
					duration := now.Sub(a.FirstSeen).Seconds()
					scale := duration / float64(t.cfg.ExpiryScaleBaseSeconds)
					if scale < 1.0 {
						scale = 1.0
					}
					if scale > t.cfg.ExpiryMaxScale {
						scale = t.cfg.ExpiryMaxScale
					}
					expirySec = int(float64(expirySec) * scale)
				}
				a.ExpiresAt = now.Add(time.Duration(expirySec) * time.Second)
				log.Printf("tracker: attack %s/%s expiring (expires in %ds)",
					a.Key.DstIP, a.Key.DecoderFamily, expirySec)
			}

		case StateExpiring:
			if a.SeenThisTick {
				// Re-exceeded — back to active
				a.State = StateActive
				a.ExpiresAt = time.Time{}
				log.Printf("tracker: attack %s/%s back to active (re-exceeded)",
					a.Key.DstIP, a.Key.DecoderFamily)
			} else if now.After(a.ExpiresAt) {
				// Timer expired → archive
				t.transitionToExpired(a, now)
				toDelete = append(toDelete, key)
			}
		}
	}

	// Remove expired/discarded attacks from memory
	for _, key := range toDelete {
		delete(t.attacks, key)
	}

	// Periodic updates: every 5 minutes, emit attack_update for all active attacks
	if now.Sub(t.lastPeriodicUpdate) >= 5*time.Minute {
		t.lastPeriodicUpdate = now
		for _, a := range t.attacks {
			if a.State == StateActive && a.DBID > 0 {
				// Update DB with latest peaks
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				attack := &store.Attack{
					ID:          a.DBID,
					AttackType:  a.AttackType,
					Severity:    a.Severity,
					Confidence:  0.9,
					PeakPPS:     a.PeakPPS,
					PeakBPS:     a.PeakBPS,
					ReasonCodes: a.ReasonCodes,
					NodeSources: a.NodeSources,
					ResponseID:  a.ResponseID,
				}
				if err := t.store.Attacks().Update(ctx, attack); err != nil {
					log.Printf("tracker: periodic update attack %d: %v", a.DBID, err)
				}
				cancel()

				// Notify action engine with "updated" event
				if t.onAction != nil {
					t.onAction(AttackEvent{Type: "updated", Attack: attack, DBID: a.DBID})
				}
			}
		}
	}
}

func (t *Tracker) transitionToActive(a *trackedAttack, now time.Time) {
	a.Severity = classifySeverity(a.PeakPPS, a.PeakBPS)
	a.ReasonCodes = []string{a.Decoder + "_exceeded"}

	// Check active cap before creating
	if t.cfg.MaxActiveAttacks > 0 {
		activeCount := t.countActive()
		if activeCount >= t.cfg.MaxActiveAttacks {
			// Find lowest priority active attack
			lowest := t.findLowestActive()
			if lowest != nil && attackPriorityLess(lowest, a) {
				// Evict lowest, make room for new higher-priority attack
				t.evictAttack(lowest, now)
				log.Printf("tracker: attack evicted: %s/%s severity=%s pps=%d (replaced by %s severity=%s pps=%d)",
					lowest.Key.DstIP, lowest.Key.DecoderFamily, lowest.Severity, lowest.PeakPPS,
					a.Key.DstIP, a.Severity, a.PeakPPS)
			} else {
				// New attack is lower priority — suppress
				t.SuppressedTotal.Add(1)
				log.Printf("tracker: attack suppressed: %s/%s pps=%d (cap %d reached, min active pps=%d)",
					a.Key.DstIP, a.Key.DecoderFamily, a.PeakPPS,
					t.cfg.MaxActiveAttacks, t.lowestActivePPS())
				a.State = StateConfirming // keep in confirming, will be discarded next tick
				return
			}
		}
	}

	a.State = StateActive
	t.CreatedTotal.Add(1)

	log.Printf("tracker: ATTACK CONFIRMED %s decoder=%s type=%s pps=%d prefix=%s",
		a.Key.DstIP, a.Key.DecoderFamily, a.AttackType, a.PeakPPS, a.Prefix)

	// Register with dedup + ring eviction protection (all nodes)
	t.dedup.MarkActive(a.Key.DstIP, a.Key.Direction, a.Key.DecoderFamily)
	if ip := net.ParseIP(a.Key.DstIP); ip != nil && t.rings != nil {
		for _, nodeID := range a.NodeSources {
			if a.Key.Direction == "sends" {
				t.rings.MarkSrcActive(nodeID, a.Prefix, ip)
			} else {
				t.rings.MarkActive(nodeID, a.Prefix, ip)
			}
		}
	}

	// INSERT into DB
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	dstIP := a.Key.DstIP
	var prefixID *int
	if a.PrefixID > 0 {
		prefixID = &a.PrefixID
	}
	attack := &store.Attack{
		DstIP:         dstIP,
		PrefixID:      prefixID,
		Direction:     a.Key.Direction,
		DecoderFamily: a.Key.DecoderFamily,
		AttackType:    a.AttackType,
		Severity:      a.Severity,
		Confidence:    0.9,
		PeakPPS:       a.PeakPPS,
		PeakBPS:       a.PeakBPS,
		ReasonCodes:   a.ReasonCodes,
		NodeSources:   a.NodeSources,
		ResponseID:      a.ResponseID,
		ThresholdRuleID: func() *int { if a.ThresholdID > 0 { v := a.ThresholdID; return &v }; return nil }(),
		StartedAt:       a.FirstSeen,
	}

	// Snapshot template name + rule summary for historical display
	if a.ThresholdID > 0 {
		if rule, err := t.store.Thresholds().Get(ctx, a.ThresholdID); err == nil {
			summary := rule.Decoder + " " + rule.Comparison + " " + fmt.Sprintf("%d", rule.Value) + " " + rule.Unit
			attack.RuleSummary = &summary
			if rule.TemplateID != nil {
				if tmpl, err := t.store.ThresholdTemplates().Get(ctx, *rule.TemplateID); err == nil {
					attack.TemplateName = &tmpl.Name
				}
			}
		}
	}

	id, err := t.store.Attacks().Create(ctx, attack)
	if err != nil {
		log.Printf("tracker: DB insert attack: %v", err)
	} else {
		a.DBID = id
		attack.ID = id
	}

	// Notify action engine
	if t.onAction != nil {
		t.onAction(AttackEvent{Type: "confirmed", Attack: attack, DBID: id})
	}
}

func (t *Tracker) transitionToExpired(a *trackedAttack, now time.Time) {
	a.State = StateExpired

	log.Printf("tracker: ATTACK EXPIRED %s decoder=%s duration=%v peak_pps=%d",
		a.Key.DstIP, a.Key.DecoderFamily, now.Sub(a.FirstSeen).Round(time.Second), a.PeakPPS)

	// Clear from dedup + ring eviction protection (all nodes)
	t.dedup.ClearActive(a.Key.DstIP, a.Key.Direction, a.Key.DecoderFamily)
	if ip := net.ParseIP(a.Key.DstIP); ip != nil && t.rings != nil {
		for _, nodeID := range a.NodeSources {
			if a.Key.Direction == "sends" {
				t.rings.ClearSrcActive(nodeID, a.Prefix, ip)
			} else {
				t.rings.ClearActive(nodeID, a.Prefix, ip)
			}
		}
	}

	// UPDATE DB with ended_at
	if a.DBID > 0 {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		attack := &store.Attack{
			ID:            a.DBID,
			AttackType:    a.AttackType,
			Severity:      a.Severity,
			Confidence:    0.9,
			PeakPPS:       a.PeakPPS,
			PeakBPS:       a.PeakBPS,
			ReasonCodes:   a.ReasonCodes,
			NodeSources:   a.NodeSources,
			ResponseID:    a.ResponseID,
			EndedAt:       &now,
		}
		if err := t.store.Attacks().Update(ctx, attack); err != nil {
			log.Printf("tracker: DB update expired attack %d: %v", a.DBID, err)
		}

		// Notify action engine — reload full attack from DB so all fields
		// (DstIP, PrefixID, ThresholdRuleID, ResponseID etc.) are available.
		if t.onAction != nil {
			fullAttack, err := t.store.Attacks().Get(ctx, a.DBID)
			if err != nil {
				log.Printf("tracker: DB reload expired attack %d: %v", a.DBID, err)
				fullAttack = attack // fallback to partial
			}
			t.onAction(AttackEvent{Type: "expired", Attack: fullAttack, DBID: a.DBID})
		}
	}
}

// ForceExpire manually expires an attack by DB ID. Returns true if found and expired.
func (t *Tracker) ForceExpire(dbID int) bool {
	t.mu.Lock()
	defer t.mu.Unlock()

	for key, a := range t.attacks {
		if a.DBID == dbID {
			now := time.Now()
			log.Printf("tracker: force-expire attack %s/%s (id=%d) by user", key.DstIP, key.DecoderFamily, dbID)
			t.transitionToExpired(a, now)
			delete(t.attacks, key)
			return true
		}
	}
	return false
}

// NotifyExpired sends an on_expired event to the action engine for a DB-only expire.
// Used by manual expire API when the attack is not in tracker memory (degraded recovery / stale row).
func (t *Tracker) NotifyExpired(attack *store.Attack) {
	if t.onAction != nil {
		t.onAction(AttackEvent{Type: "expired", Attack: attack, DBID: attack.ID})
	}
}

// ActiveTimers returns expiry timer info for all tracked attacks, keyed by DB ID.
// Used by the API to show countdown timers on active attacks.
type AttackTimer struct {
	State     string  `json:"state"`      // "active" | "expiring"
	ExpiresIn float64 `json:"expires_in"` // seconds until expiry (0 if active/not expiring)
}

func (t *Tracker) ActiveTimers() map[int]AttackTimer {
	t.mu.RLock()
	defer t.mu.RUnlock()

	now := time.Now()
	result := make(map[int]AttackTimer, len(t.attacks))
	for _, a := range t.attacks {
		if a.DBID <= 0 {
			continue
		}
		timer := AttackTimer{State: a.State}
		if a.State == StateExpiring && a.ExpiresAt.After(now) {
			timer.ExpiresIn = a.ExpiresAt.Sub(now).Seconds()
		}
		result[a.DBID] = timer
	}
	return result
}

// UpgradeType updates the attack type based on classifier results.
// Reference: brainstorm-controller.md "Type upgrade rules"
func (t *Tracker) UpgradeType(dstIP net.IP, newType string, confidence float32, reasons []string) {
	t.mu.Lock()
	defer t.mu.Unlock()

	ipStr := dstIP.String()
	for _, a := range t.attacks {
		if a.Key.DstIP == ipStr && a.State == StateActive {
			// Only upgrade UDP attacks with classifier results
			// (classifier only analyzes UDP src_port distribution)
			if a.Key.DecoderFamily != "udp" {
				continue
			}
			if a.AttackType == newType {
				continue
			}
			oldType := a.AttackType
			a.AttackType = newType
			a.ReasonCodes = append(a.ReasonCodes, reasons...)

			log.Printf("tracker: type upgrade %s: %s → %s (confidence=%.2f)",
				ipStr, oldType, newType, confidence)

			// Update DB
			if a.DBID > 0 {
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				attack := &store.Attack{
					ID:          a.DBID,
					AttackType:  newType,
					Severity:    a.Severity, // preserve existing severity
					Confidence:  confidence,
					PeakPPS:     a.PeakPPS,
					PeakBPS:     a.PeakBPS,
					ReasonCodes: a.ReasonCodes,
					NodeSources: a.NodeSources,
				}
				if err := t.store.Attacks().Update(ctx, attack); err != nil {
					log.Printf("tracker: DB update type upgrade %d: %v", a.DBID, err)
				}

				// Notify action engine — immediate re-evaluation
				if t.onAction != nil {
					t.onAction(AttackEvent{Type: "type_upgrade", Attack: attack, DBID: a.DBID})
				}
			}
		}
	}
}

// RecoverFromDB rebuilds in-memory state from active attacks in DB.
// Called on Controller startup for crash recovery.
func (t *Tracker) RecoverFromDB(ctx context.Context) error {
	attacks, err := t.store.Attacks().ListActive(ctx, 1000) // limit recovery to 1000
	if err != nil {
		return err
	}

	t.mu.Lock()
	defer t.mu.Unlock()

	for _, a := range attacks {
		key := attackKey{
			DstIP:         a.DstIP,
			Direction:     a.Direction,
			DecoderFamily: a.DecoderFamily,
		}
		ta := &trackedAttack{
			Key:         key,
			State:       StateActive,
			DBID:        a.ID,
			Prefix:      "", // will be resolved on next detection tick
			AttackType:  a.AttackType,
			Severity:    a.Severity,
			PeakPPS:     a.PeakPPS,
			PeakBPS:     a.PeakBPS,
			ReasonCodes: a.ReasonCodes,
			NodeSources: a.NodeSources,
			FirstSeen:   a.StartedAt,
			LastSeen:    time.Now(),
		}
		if a.ResponseID != nil {
			ta.ResponseID = a.ResponseID
		}
		t.attacks[key] = ta
		t.dedup.MarkActive(key.DstIP, key.Direction, key.DecoderFamily)
	}

	if len(attacks) > 0 {
		// Check if recovery was truncated
		totalActive, _ := t.store.Attacks().CountActive(ctx)
		if totalActive > len(attacks) {
			log.Printf("tracker: DEGRADED RECOVERY — restored %d/%d active attacks (truncated, %d not loaded)",
				len(attacks), totalActive, totalActive-len(attacks))
		} else {
			log.Printf("tracker: recovered %d active attacks from DB", len(attacks))
		}
	}
	return nil
}

// ActiveDstIPs returns the dst IP strings of all active/expiring attacks.
// Used by the classifier to attempt type upgrades on active attacks.
func (t *Tracker) ActiveDstIPs() []string {
	t.mu.Lock()
	defer t.mu.Unlock()
	seen := make(map[string]bool)
	var ips []string
	for _, a := range t.attacks {
		if (a.State == StateActive || a.State == StateExpiring) && !seen[a.Key.DstIP] {
			seen[a.Key.DstIP] = true
			ips = append(ips, a.Key.DstIP)
		}
	}
	return ips
}

// ActiveCount returns the number of currently tracked attacks.
func (t *Tracker) ActiveCount() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	count := 0
	for _, a := range t.attacks {
		if a.State == StateActive || a.State == StateExpiring {
			count++
		}
	}
	return count
}


func decoderToAttackType(decoder string) string {
	switch decoder {
	case "tcp_syn":
		return "syn_flood"
	case "tcp":
		return "tcp_flood"
	case "udp":
		return "udp_flood"
	case "icmp":
		return "icmp_flood"
	case "fragment":
		return "fragment_flood"
	case "ip":
		return "volumetric_generic"
	default:
		return "unknown"
	}
}

func classifySeverity(peakPPS, peakBPS int64) string {
	if peakPPS > 1_000_000 || peakBPS > 10_000_000_000 {
		return "critical"
	}
	if peakPPS > 100_000 || peakBPS > 1_000_000_000 {
		return "high"
	}
	if peakPPS > 10_000 || peakBPS > 100_000_000 {
		return "medium"
	}
	return "low"
}

func max(a, b int64) int64 {
	if a > b {
		return a
	}
	return b
}

// --- Active cap helpers (must be called with t.mu held) ---

// severityScore maps severity string to a numeric rank for priority comparison.
// Higher score = higher priority = less likely to be evicted.
func severityScore(s string) int {
	switch s {
	case "critical":
		return 4
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	default:
		return 0
	}
}

// attackPriorityLess returns true if a is lower priority than b.
// Compares severity first, then PeakPPS as tiebreaker.
func attackPriorityLess(a, b *trackedAttack) bool {
	sa, sb := severityScore(a.Severity), severityScore(b.Severity)
	if sa != sb {
		return sa < sb
	}
	return a.PeakPPS < b.PeakPPS
}

// countActive returns the number of active/expiring attacks.
func (t *Tracker) countActive() int {
	count := 0
	for _, a := range t.attacks {
		if a.State == StateActive || a.State == StateExpiring {
			count++
		}
	}
	return count
}

// findLowestActive returns the active attack with the lowest priority (severity then PeakPPS).
func (t *Tracker) findLowestActive() *trackedAttack {
	var lowest *trackedAttack
	for _, a := range t.attacks {
		if a.State == StateActive {
			if lowest == nil || attackPriorityLess(a, lowest) {
				lowest = a
			}
		}
	}
	return lowest
}

// lowestActivePPS returns the minimum peak_pps among active attacks.
func (t *Tracker) lowestActivePPS() int64 {
	l := t.findLowestActive()
	if l == nil {
		return 0
	}
	return l.PeakPPS
}

// evictAttack removes an active attack due to cap pressure.
// Writes ended_at to DB with evicted reason, notifies action engine.
func (t *Tracker) evictAttack(a *trackedAttack, now time.Time) {
	t.EvictedTotal.Add(1)

	// Clear from dedup + ring (all nodes)
	t.dedup.ClearActive(a.Key.DstIP, a.Key.Direction, a.Key.DecoderFamily)
	if ip := net.ParseIP(a.Key.DstIP); ip != nil && t.rings != nil {
		for _, nodeID := range a.NodeSources {
			if a.Key.Direction == "sends" {
				t.rings.ClearSrcActive(nodeID, a.Prefix, ip)
			} else {
				t.rings.ClearActive(nodeID, a.Prefix, ip)
			}
		}
	}

	// Update DB — mark as ended with evicted reason
	if a.DBID > 0 {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		attack := &store.Attack{
			ID:          a.DBID,
			AttackType:  a.AttackType,
			Severity:    a.Severity,
			Confidence:  0.9,
			PeakPPS:     a.PeakPPS,
			PeakBPS:     a.PeakBPS,
			ReasonCodes: append(a.ReasonCodes, "evicted_by_cap"),
			NodeSources: a.NodeSources,
			EndedAt:     &now,
		}
		_ = t.store.Attacks().Update(ctx, attack)

		// Notify action engine — evicted, not naturally expired
		if t.onAction != nil {
			t.onAction(AttackEvent{Type: "evicted", Attack: attack, DBID: a.DBID})
		}
	}

	// Remove from tracker
	delete(t.attacks, a.Key)
}
