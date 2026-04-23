//go:build linux

// Package bpf provides BPF program loading and XDP attachment for xsight-node.
package bpf

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

// PinBasePath is the base directory for BPF pin persistence.
const PinBasePath = "/sys/fs/bpf/xsight"

// bpfHashStateDir is where per-interface BPF hash stamps live. NOT under
// /sys/fs/bpf/ — bpffs rejects regular-file creation with EPERM. /run is
// a tmpfs that survives systemctl restart but clears on reboot, which is
// exactly the lifecycle we want: BPF map pins also clear on reboot, so a
// fresh boot needs no hash stamp (first Load just writes it).
const bpfHashStateDir = "/run/xsight/bpf-hashes"

// bpfHashFilePath returns the per-interface hash stamp path. The filename
// is just the iface name — keep it flat so an operator tailing /run/xsight
// can eyeball all stamps at once.
func bpfHashFilePath(iface string) string {
	return filepath.Join(bpfHashStateDir, iface+".sha256")
}

// currentBPFHash returns the SHA-256 of the embedded BPF ELF as a hex string.
// Cheap enough to recompute each Load; cached not worth it.
func currentBPFHash() string {
	sum := sha256.Sum256(_XsightBytes)
	return hex.EncodeToString(sum[:])
}

// readBPFHash returns the hash previously written for this iface, or empty
// string if no stamp exists (first-boot case or /run cleared).
func readBPFHash(iface string) string {
	b, err := os.ReadFile(bpfHashFilePath(iface))
	if err != nil {
		return ""
	}
	return string(b)
}

// writeBPFHash stamps the current BPF hash for this iface. Called after a
// successful Load so subsequent restarts can compare. Creates the state
// dir if missing. Failure is logged but non-fatal — the hash check just
// degrades to "always rebuild never triggers", same behavior as pre-v1.3.4.
func writeBPFHash(iface, hash string) {
	if err := os.MkdirAll(bpfHashStateDir, 0700); err != nil {
		log.Printf("warning: mkdir %s: %v", bpfHashStateDir, err)
		return
	}
	p := bpfHashFilePath(iface)
	if err := os.WriteFile(p, []byte(hash), 0600); err != nil {
		log.Printf("warning: write %s: %v", p, err)
	}
}

// detachPinnedXDP removes the pinned XDP link if present, which releases the
// kernel's reference to the old program on the iface. Called during forced
// rebuild so the stale program stops running before new maps are created.
// Errors are logged but not fatal — if no pinned link exists, that's fine.
func detachPinnedXDP(pinPath string) {
	linkPinPath := filepath.Join(pinPath, "link")
	oldLink, err := link.LoadPinnedLink(linkPinPath, nil)
	if err != nil {
		// No pinned link or unreadable — AttachXDP's own cleanup will retry.
		return
	}
	if err := oldLink.Unpin(); err != nil {
		log.Printf("forced rebuild: unpin old XDP link: %v", err)
	}
	if err := oldLink.Close(); err != nil {
		log.Printf("forced rebuild: close old XDP link: %v", err)
	}
	_ = os.Remove(linkPinPath)
}

// XDPAttachment holds a single interface's XDP link and program reference.
type XDPAttachment struct {
	Iface   string
	Link    link.Link
	PinPath string // e.g. /sys/fs/bpf/xsight/ens38
}

// Manager holds the loaded BPF collection and all XDP attachments.
type Manager struct {
	Objs             *xsightObjects
	Attachments      []XDPAttachment
	PinPath          string // per-interface pin directory (empty = no pin)
	Recovered        bool   // true if loaded from existing pins
	batchUnsupported bool   // sticky: set true after first batch op failure, skip retries
}

// Load loads the compiled BPF objects. If ifaceName is non-empty, enables pin
// persistence at /sys/fs/bpf/xsight/<iface>/.
// maxEntries overrides the ip_stats map size (0 = use compiled default 1M).
//
// Pin behavior (P7):
//   - If pin directory exists and map specs match → hot recovery (reuse existing maps)
//   - If pin directory exists but specs mismatch → controlled rebuild (remove old, load fresh)
//   - If no pin directory → cold start (load fresh, pin if ifaceName given)
//   - If ifaceName is empty → no pinning (testing/dev mode)
func Load(ifaceName string, maxEntries uint32) (*Manager, error) {
	pinPath := ""
	if ifaceName != "" {
		pinPath = filepath.Join(PinBasePath, ifaceName)
	}

	objs := &xsightObjects{}

	if pinPath == "" {
		// No pinning — simple load
		spec, err := loadXsight()
		if err != nil {
			return nil, fmt.Errorf("load BPF spec: %w", err)
		}
		applyMaxEntries(spec, maxEntries)
		if err := spec.LoadAndAssign(objs, nil); err != nil {
			return nil, fmt.Errorf("load BPF objects: %w", err)
		}
		return &Manager{Objs: objs}, nil
	}

	// Pin mode: load spec, enable PinByName on all maps, then load
	if err := os.MkdirAll(pinPath, 0700); err != nil {
		return nil, fmt.Errorf("create pin dir %s: %w", pinPath, err)
	}

	// BPF hash check (v1.3.4): if the embedded BPF ELF differs from what the
	// existing pins were created with, those pinned maps + link reference a
	// stale program. Force a clean rebuild so new bytecode actually takes
	// effect on restart (previously required manual rm -rf + xdp off).
	newHash := currentBPFHash()
	pinnedHash := readBPFHash(ifaceName)
	hashMismatch := pinnedHash != "" && pinnedHash != newHash
	if hashMismatch {
		log.Printf("BPF ELF hash changed (old=%s… new=%s…), forcing clean rebuild on %s",
			shortHash(pinnedHash), shortHash(newHash), ifaceName)
		// Detach pinned XDP link first so the stale program stops running
		// before we drop its maps. Safe to call even if no link is pinned.
		detachPinnedXDP(pinPath)
		if rmErr := os.RemoveAll(pinPath); rmErr != nil {
			log.Printf("forced rebuild: remove pin dir: %v", rmErr)
		}
		if mkErr := os.MkdirAll(pinPath, 0700); mkErr != nil {
			return nil, fmt.Errorf("forced rebuild: recreate pin dir: %w", mkErr)
		}
	}

	recovered := false
	err := loadPinned(objs, pinPath, maxEntries)
	if err != nil {
		// Spec mismatch or corrupted pins — controlled rebuild
		log.Printf("pin load failed (%v), rebuilding", err)
		if rmErr := os.RemoveAll(pinPath); rmErr != nil {
			log.Printf("remove old pins: %v", rmErr)
		}
		if mkErr := os.MkdirAll(pinPath, 0700); mkErr != nil {
			return nil, fmt.Errorf("recreate pin dir: %w", mkErr)
		}
		objs = &xsightObjects{}
		err = loadPinned(objs, pinPath, maxEntries)
	}
	if err != nil {
		return nil, fmt.Errorf("load BPF objects: %w", err)
	}

	// Check if we recovered from existing pins (skipped on hash-mismatch
	// rebuild — those pins were just created, Recovered=false is correct).
	var gs GlobalStats
	key := uint32(0)
	if !hashMismatch {
		if lookErr := objs.GlobalStats.Lookup(&key, &gs); lookErr == nil && gs.TotalPkts > 0 {
			recovered = true
			log.Printf("pin recovery: hot restored (total_pkts=%d)", gs.TotalPkts)
		}
	}

	// Stamp the hash so next restart can compare. Writing AFTER successful
	// load is intentional: a failed load must not stamp a hash that claims
	// the pins match the new bytecode.
	writeBPFHash(ifaceName, newHash)

	return &Manager{Objs: objs, PinPath: pinPath, Recovered: recovered}, nil
}

// shortHash returns the first 8 chars of a hex hash for log readability.
// Empty input returns "(none)" so "old=(none)" reads cleanly in the "first
// boot after upgrade" log line.
func shortHash(h string) string {
	if h == "" {
		return "(none)"
	}
	if len(h) > 8 {
		return h[:8]
	}
	return h
}

// loadPinned loads BPF objects with PinByName enabled on all maps.
// This causes cilium/ebpf to reuse existing pinned maps at pinPath.
func loadPinned(objs *xsightObjects, pinPath string, maxEntries uint32) error {
	spec, err := loadXsight()
	if err != nil {
		return err
	}
	// Pin counter/trie maps for hot recovery. Skip pinning the ring buffer
	// (samples) — it must be fresh each restart so the new BPF program and
	// userspace reader share the same clean instance.
	for name, ms := range spec.Maps {
		if name == "samples" {
			continue
		}
		ms.Pinning = ebpf.PinByName
	}
	// Clean up stale ring buffer pin from older versions
	_ = os.Remove(filepath.Join(pinPath, "samples"))
	applyMaxEntries(spec, maxEntries)
	return spec.LoadAndAssign(objs, &ebpf.CollectionOptions{
		Maps: ebpf.MapOptions{PinPath: pinPath},
	})
}

// applyMaxEntries overrides ip_stats map max_entries from config.
// Only applies when maxEntries > 0; 0 keeps the compiled-in default.
func applyMaxEntries(spec *ebpf.CollectionSpec, maxEntries uint32) {
	if maxEntries == 0 {
		return
	}
	for name, ms := range spec.Maps {
		if name == "ip_stats_a" || name == "ip_stats_b" {
			ms.MaxEntries = maxEntries
		}
	}
}

// AttachXDP attaches the XDP program to the given interface.
// If pins are enabled, the link is pinned for persistence across restarts.
// On restart, attempts to recover a pinned link first.
func (m *Manager) AttachXDP(ifaceName string) error {
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return fmt.Errorf("interface %s: %w", ifaceName, err)
	}

	linkPinPath := ""
	if m.PinPath != "" {
		linkPinPath = filepath.Join(m.PinPath, "link")
	}

	// Always do a fresh attach with the current program (which has correct
	// map FDs, especially for the unpinned ring buffer). We do NOT recover
	// the old pinned link because the old program references a stale ring
	// buffer map FD — that causes the sampler to never receive samples while
	// BPF side reports all as sample_drops.
	// Counter maps ARE preserved via map pins, so no data loss.
	if linkPinPath != "" {
		// Clean up old pinned link (detaches old XDP)
		if old, err := link.LoadPinnedLink(linkPinPath, nil); err == nil {
			_ = old.Unpin()
			_ = old.Close()
			log.Printf("unpinned old XDP link on %s (reattaching with fresh program)", ifaceName)
		}
		_ = os.Remove(linkPinPath)
	}

	// Fresh attach: try native (driver) mode explicitly, fallback to generic.
	// Must use XDPDriverMode flag — zero value silently falls back to generic.
	l, err := link.AttachXDP(link.XDPOptions{
		Program:   m.Objs.XsightMain,
		Interface: iface.Index,
		Flags:     link.XDPDriverMode,
	})
	if err != nil {
		log.Printf("native XDP attach failed on %s (%v), trying generic mode", ifaceName, err)
		l, err = link.AttachXDP(link.XDPOptions{
			Program:   m.Objs.XsightMain,
			Interface: iface.Index,
			Flags:     link.XDPGenericMode,
		})
		if err != nil {
			return fmt.Errorf("attach XDP to %s: %w", ifaceName, err)
		}
		log.Printf("XDP attached to %s (generic mode)", ifaceName)
	} else {
		log.Printf("XDP attached to %s (native/driver mode)", ifaceName)
	}

	// Pin the link for persistence
	if linkPinPath != "" {
		if err := l.Pin(linkPinPath); err != nil {
			log.Printf("warning: pin XDP link failed: %v (XDP will detach on exit)", err)
		}
	}

	m.Attachments = append(m.Attachments, XDPAttachment{
		Iface: ifaceName, Link: l, PinPath: linkPinPath,
	})
	return nil
}

// Close releases all FDs. Pinned objects survive (XDP stays attached).
// Use Unload() for complete cleanup.
func (m *Manager) Close() {
	for _, att := range m.Attachments {
		if err := att.Link.Close(); err != nil {
			log.Printf("close link on %s: %v", att.Iface, err)
		}
	}
	m.Attachments = nil
	if m.Objs != nil {
		m.Objs.Close()
	}
}

// Unload performs a complete cleanup: detach XDP, remove all pins.
// Reference: brainstorm-node.md "Signal Handling" --unload
func (m *Manager) Unload() {
	for _, att := range m.Attachments {
		// Unpin link first (otherwise Close just releases FD, pin keeps XDP alive)
		if att.PinPath != "" {
			if err := att.Link.Unpin(); err != nil {
				log.Printf("unpin link on %s: %v", att.Iface, err)
			}
		}
		if err := att.Link.Close(); err != nil {
			log.Printf("detach XDP from %s: %v", att.Iface, err)
		} else {
			log.Printf("XDP detached from %s", att.Iface)
		}
	}
	m.Attachments = nil

	if m.Objs != nil {
		m.Objs.Close()
	}

	// Remove pin directory
	if m.PinPath != "" {
		if err := os.RemoveAll(m.PinPath); err != nil {
			log.Printf("remove pin dir %s: %v", m.PinPath, err)
		} else {
			log.Printf("pin directory removed: %s", m.PinPath)
		}
	}
}

// PopulateTrie writes prefix entries into the active watch trie (slot A by default).
func (m *Manager) PopulateTrie(prefixes []PrefixEntry) error {
	for _, p := range prefixes {
		key := p.LPMKey()
		val := p.Prefixlen

		if err := m.Objs.WatchTrieA.Update(&key, &val, ebpf.UpdateAny); err != nil {
			return fmt.Errorf("update watch_trie_a for %s: %w", p.String(), err)
		}

		pkey := p.PrefixKey()
		pstats := PrefixStats{}
		if err := m.Objs.PrefixStatsMap.Update(&pkey, &pstats, ebpf.UpdateNoExist); err != nil {
			_ = m.Objs.PrefixStatsMap.Update(&pkey, &pstats, ebpf.UpdateAny)
		}
	}
	log.Printf("populated watch_trie_a with %d prefixes", len(prefixes))
	return nil
}

// SetConfig writes a value to the BPF config map at the given index.
func (m *Manager) SetConfig(index uint32, value uint64) error {
	if err := m.Objs.XsightConfig.Update(&index, &value, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("set config[%d]=%d: %w", index, value, err)
	}
	return nil
}

// ApplyInterfaceConfig writes per-interface BPF config map entries.
func (m *Manager) ApplyInterfaceConfig(mode string, sampleBytes, upstreamRate uint32) error {
	if err := m.SetConfig(1, uint64(sampleBytes)); err != nil {
		return fmt.Errorf("apply sample_bytes: %w", err)
	}
	var modeVal uint64
	if mode == "erspan" {
		modeVal = 1
	}
	if err := m.SetConfig(2, modeVal); err != nil {
		return fmt.Errorf("apply mode: %w", err)
	}
	if err := m.SetConfig(3, uint64(upstreamRate)); err != nil {
		return fmt.Errorf("apply upstream_rate: %w", err)
	}
	log.Printf("BPF config applied: mode=%s sample_bytes=%d upstream_rate=%d", mode, sampleBytes, upstreamRate)
	return nil
}

// GlobalStats returns the current global stats from BPF map.
func (m *Manager) GlobalStats() (*GlobalStats, error) {
	var gs GlobalStats
	key := uint32(0)
	if err := m.Objs.GlobalStats.Lookup(&key, &gs); err != nil {
		return nil, fmt.Errorf("read global_stats: %w", err)
	}
	return &gs, nil
}

// ReadActiveSlot returns the current active buffer slot (0=A, 1=B).
func (m *Manager) ReadActiveSlot() (uint32, error) {
	var slot uint32
	key := uint32(0)
	if err := m.Objs.ActiveSlot.Lookup(&key, &slot); err != nil {
		return 0, fmt.Errorf("read active_slot: %w", err)
	}
	return slot, nil
}

// IterIPStats returns an iterator for the active ip_stats map.
func (m *Manager) IterIPStats() (*ebpf.MapIterator, error) {
	slot, err := m.ReadActiveSlot()
	if err != nil {
		return nil, err
	}
	if slot == 0 {
		return m.Objs.IpStatsA.Iterate(), nil
	}
	return m.Objs.IpStatsB.Iterate(), nil
}

// IterPrefixStats returns an iterator for prefix_stats_map.
func (m *Manager) IterPrefixStats() *ebpf.MapIterator {
	return m.Objs.PrefixStatsMap.Iterate()
}

// IterSrcPrefixStats returns an iterator for src_prefix_stats_map (outbound).
func (m *Manager) IterSrcPrefixStats() *ebpf.MapIterator {
	return m.Objs.SrcPrefixStatsMap.Iterate()
}

// BatchReadSrcIPStats reads all entries from the active src_stats map (outbound).
// Uses the same batch + fallback logic as inbound BatchReadIPStats.
func (m *Manager) BatchReadSrcIPStats() (map[LPMKey]DstIPStats, error) {
	slot, err := m.ReadActiveSlot()
	if err != nil {
		return nil, err
	}
	var statsMap *ebpf.Map
	if slot == 0 {
		statsMap = m.Objs.SrcStatsA
	} else {
		statsMap = m.Objs.SrcStatsB
	}
	return m.batchOrIterRead(statsMap)
}

// BatchReadIPStats reads all entries from the active ip_stats map (inbound).
func (m *Manager) BatchReadIPStats() (map[LPMKey]DstIPStats, error) {
	slot, err := m.ReadActiveSlot()
	if err != nil {
		return nil, err
	}
	var statsMap *ebpf.Map
	if slot == 0 {
		statsMap = m.Objs.IpStatsA
	} else {
		statsMap = m.Objs.IpStatsB
	}
	return m.batchOrIterRead(statsMap)
}

// batchOrIterRead reads all entries from a hash map using batch syscalls,
// with sticky fallback to iterator if batch is not supported.
// Shared by both inbound (ip_stats) and outbound (src_stats) reads.
func (m *Manager) batchOrIterRead(statsMap *ebpf.Map) (map[LPMKey]DstIPStats, error) {
	if m.batchUnsupported {
		return m.iterReadIPStats(statsMap)
	}

	result := make(map[LPMKey]DstIPStats)

	const batchSize = 256
	keys := make([]LPMKey, batchSize)
	vals := make([]DstIPStats, batchSize)
	var cursor ebpf.MapBatchCursor

	for {
		n, err := statsMap.BatchLookup(&cursor, keys, vals, nil)
		for i := 0; i < n; i++ {
			result[keys[i]] = vals[i]
		}
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			break
		}
		if err != nil {
			log.Printf("bpf: BatchLookup not supported, switching to iterator permanently: %v", err)
			m.batchUnsupported = true
			return m.iterReadIPStats(statsMap)
		}
	}

	return result, nil
}

// iterReadIPStats is the fallback iterator-based reader.
func (m *Manager) iterReadIPStats(statsMap *ebpf.Map) (map[LPMKey]DstIPStats, error) {
	result := make(map[LPMKey]DstIPStats)
	iter := statsMap.Iterate()
	var k LPMKey
	var v DstIPStats
	for iter.Next(&k, &v) {
		result[k] = v
	}
	if err := iter.Err(); err != nil {
		return nil, fmt.Errorf("ip_stats iter: %w", err)
	}
	return result, nil
}

// SetSampleRate writes the dynamic sample rate to BPF config map index 0.
func (m *Manager) SetSampleRate(rate uint32) error {
	return m.SetConfig(0, uint64(rate))
}

// HotSwap performs a double-buffer swap of watch_prefix configuration.
func (m *Manager) HotSwap(prefixes []PrefixEntry) error {
	slot, err := m.ReadActiveSlot()
	if err != nil {
		return fmt.Errorf("hotswap: read slot: %w", err)
	}

	var activeTrie, shadowTrie *ebpf.Map
	var activeStats, shadowStats *ebpf.Map
	var activeSrcStats, shadowSrcStats *ebpf.Map
	var newSlot uint32
	if slot == 0 {
		activeTrie = m.Objs.WatchTrieA
		shadowTrie = m.Objs.WatchTrieB
		activeStats = m.Objs.IpStatsA
		shadowStats = m.Objs.IpStatsB
		activeSrcStats = m.Objs.SrcStatsA
		shadowSrcStats = m.Objs.SrcStatsB
		newSlot = 1
	} else {
		activeTrie = m.Objs.WatchTrieB
		shadowTrie = m.Objs.WatchTrieA
		activeStats = m.Objs.IpStatsB
		shadowStats = m.Objs.IpStatsA
		activeSrcStats = m.Objs.SrcStatsB
		shadowSrcStats = m.Objs.SrcStatsA
		newSlot = 0
	}

	if err := clearMap(shadowTrie); err != nil {
		return fmt.Errorf("hotswap: clear shadow trie: %w", err)
	}
	if err := clearIPStatsMap(shadowStats); err != nil {
		return fmt.Errorf("hotswap: clear shadow ip_stats: %w", err)
	}
	// Clear outbound shadow stats
	if err := clearIPStatsMap(shadowSrcStats); err != nil {
		return fmt.Errorf("hotswap: clear shadow src_stats: %w", err)
	}

	for _, p := range prefixes {
		key := p.LPMKey()
		val := p.Prefixlen
		if err := shadowTrie.Update(&key, &val, ebpf.UpdateAny); err != nil {
			return fmt.Errorf("hotswap: write shadow trie %s: %w", p.String(), err)
		}
	}

	newPrefixSet := make(map[PrefixKeyGo]bool)
	for _, p := range prefixes {
		pkey := p.PrefixKey()
		newPrefixSet[pkey] = true
		pstats := PrefixStats{}
		_ = m.Objs.PrefixStatsMap.Update(&pkey, &pstats, ebpf.UpdateNoExist)
		_ = m.Objs.SrcPrefixStatsMap.Update(&pkey, &pstats, ebpf.UpdateNoExist)
	}
	var staleKeys []PrefixKeyGo
	iter := m.Objs.PrefixStatsMap.Iterate()
	var pk PrefixKeyGo
	var pv PrefixStats
	for iter.Next(&pk, &pv) {
		if !newPrefixSet[pk] {
			staleKeys = append(staleKeys, pk)
		}
	}
	for _, k := range staleKeys {
		k := k
		_ = m.Objs.PrefixStatsMap.Delete(&k)
		_ = m.Objs.SrcPrefixStatsMap.Delete(&k)
	}

	watchNets := buildIPNets(prefixes)

	// Migrate inbound ip_stats entries that still match a watched prefix
	var ik LPMKey
	var iv DstIPStats
	activeIter := activeStats.Iterate()
	migrated := 0
	for activeIter.Next(&ik, &iv) {
		ip := lpmKeyToIP(ik)
		if containedInAny(ip, watchNets) {
			if err := shadowStats.Update(&ik, &iv, ebpf.UpdateAny); err != nil {
				continue
			}
			migrated++
		}
	}

	// Migrate outbound src_stats entries (same logic, different maps)
	srcMigrated := 0
	srcIter := activeSrcStats.Iterate()
	for srcIter.Next(&ik, &iv) {
		ip := lpmKeyToIP(ik)
		if containedInAny(ip, watchNets) {
			if err := shadowSrcStats.Update(&ik, &iv, ebpf.UpdateAny); err != nil {
				continue
			}
			srcMigrated++
		}
	}

	key := uint32(0)
	if err := m.Objs.ActiveSlot.Update(&key, &newSlot, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("hotswap: swap active_slot: %w", err)
	}

	_ = clearMap(activeTrie)
	_ = clearIPStatsMap(activeStats)
	_ = clearIPStatsMap(activeSrcStats)

	log.Printf("hotswap: slot %d→%d, %d prefixes, %d ip_stats migrated, %d src_stats migrated",
		slot, newSlot, len(prefixes), migrated, srcMigrated)
	return nil
}

// clearIPStatsMap clears an ip_stats hash map using batch delete (kernel 5.6+).
// Key/value types are specific to ip_stats (LPMKey/DstIPStats).
// Falls back to clearMap if batch is not supported.
func clearIPStatsMap(m *ebpf.Map) error {
	const batchSize = 256
	keys := make([]LPMKey, batchSize)
	vals := make([]DstIPStats, batchSize)
	var cursor ebpf.MapBatchCursor

	for {
		n, err := m.BatchLookupAndDelete(&cursor, keys, vals, nil)
		if n == 0 && errors.Is(err, ebpf.ErrKeyNotExist) {
			return nil // done
		}
		if err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			// Batch not supported — fall back to legacy clearMap
			log.Printf("bpf: BatchLookupAndDelete not supported, falling back: %v", err)
			return clearMap(m)
		}
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return nil // last batch
		}
	}
}

func clearMap(m *ebpf.Map) error {
	// Try Iterate() first; if it fails (e.g. LPM trie on some kernels),
	// fall back to NextKey loop.
	iter := m.Iterate()
	var keys []LPMKey
	var k LPMKey
	var v [64]byte
	for iter.Next(&k, &v) {
		keys = append(keys, k)
	}
	if err := iter.Err(); err != nil {
		// Fallback: NextKey loop (works for LPM trie)
		keys = keys[:0]
		var cur LPMKey
		for {
			if err := m.NextKey(nil, &cur); err != nil {
				break
			}
			keys = append(keys, cur)
			cur2 := cur
			_ = m.Delete(&cur2)
		}
		return nil
	}
	for _, k := range keys {
		k := k
		_ = m.Delete(&k)
	}
	return nil
}

func buildIPNets(prefixes []PrefixEntry) []net.IPNet {
	nets := make([]net.IPNet, len(prefixes))
	for i, p := range prefixes {
		nets[i] = p.Net
	}
	return nets
}

func lpmKeyToIP(k LPMKey) net.IP {
	if k.Prefixlen == 32 {
		return net.IP(k.Addr[:4])
	}
	return net.IP(k.Addr[:16])
}

func containedInAny(ip net.IP, nets []net.IPNet) bool {
	for _, n := range nets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}
