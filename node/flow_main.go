// flow_main.go — Flow mode entry point (v3.0)
// Runs when config mode=flow. Completely separate from XDP/BPF path.
package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/littlewolf9527/xsight/node/internal/config"
	"github.com/littlewolf9527/xsight/node/internal/flow"
	"github.com/littlewolf9527/xsight/node/internal/pb"
	"github.com/littlewolf9527/xsight/node/internal/reporter"
	"github.com/littlewolf9527/xsight/node/internal/watchdog"
)

func runFlowMode(cfg *config.Config) {
	log.Printf("xsight-node starting in FLOW mode: node_id=%s", cfg.NodeID)

	// Prefix trie for matching flow IPs against watch_prefixes
	trie := flow.NewPrefixTrie()

	// Aggregator produces *pb.StatsReport every second
	aggregator := flow.NewFlowAggregator(trie)

	// Channel for aggregator → reporter
	flowReports := make(chan *pb.StatsReport, 8)

	// Listener manager — tracks running listeners, handles dynamic start/stop
	var activeListeners []*flow.Listener

	// applyConfig callback — called by reporter on handshake + ConfigPush
	applyConfig := func(wc *pb.WatchConfig, deliveryVersion uint64) error {
		// Rebuild prefix trie from watch_prefixes
		var cidrs []string
		var snapPrefixes []config.SnapshotPrefix
		for _, wp := range wc.GetPrefixes() {
			cidr := fmt.Sprintf("%s/%d", prefixBytesToIP(wp.Prefix), wp.PrefixLen)
			cidrs = append(cidrs, cidr)
			snapPrefixes = append(snapPrefixes, config.SnapshotPrefix{
				Prefix: cidr,
				Name:   wp.Name,
			})
		}
		trie.Rebuild(cidrs)
		log.Printf("flow: prefix trie rebuilt with %d prefixes", trie.Count())

		// Apply flow listener/source config — only restart if flow config changed
		// (avoids destroying template cache on unrelated prefix/threshold changes)
		newFlowCfg := wc.GetFlowListeners()
		if flowConfigChanged(newFlowCfg, activeListeners) {
			applyFlowListeners(newFlowCfg, aggregator, &activeListeners)
		} else {
			// Only source tables may need refresh — update without restarting listeners
			updateSourceTables(newFlowCfg, activeListeners)
		}

		// Save snapshot (including flow listeners/sources for cold restart recovery)
		snap := &config.Snapshot{
			WatchPrefixes:          snapPrefixes,
			DeliveryVersionApplied: deliveryVersion,
		}
		if ht := wc.GetHardThresholds(); ht != nil {
			snap.HardThresholds = config.SnapshotThresholds{PPS: ht.Pps, BPS: ht.Bps}
		}
		for _, lc := range wc.GetFlowListeners() {
			if !lc.Enabled {
				continue
			}
			sl := config.SnapshotFlowListener{
				ListenAddress: lc.ListenAddress,
				ProtocolMode:  lc.ProtocolMode,
			}
			for _, sc := range lc.Sources {
				if !sc.Enabled {
					continue
				}
				sl.Sources = append(sl.Sources, config.SnapshotFlowSource{
					DeviceIP:   sc.DeviceIp,
					SampleMode: sc.SampleMode,
					SampleRate: int(sc.SampleRate),
					Name:       sc.Name,
				})
			}
			snap.FlowListeners = append(snap.FlowListeners, sl)
		}
		if err := config.SaveSnapshot(cfg.NodeID, snap); err != nil {
			log.Printf("flow: snapshot save error: %v", err)
		}
		return nil
	}

	// Load snapshot for initial prefix trie + flow listeners
	var initialDeliveryVersion uint64
	snap, err := config.LoadSnapshot(cfg.NodeID)
	if err != nil {
		log.Printf("flow: snapshot load error: %v (starting empty)", err)
	} else if snap != nil {
		var cidrs []string
		for _, sp := range snap.WatchPrefixes {
			cidrs = append(cidrs, sp.Prefix)
		}
		trie.Rebuild(cidrs)
		initialDeliveryVersion = snap.DeliveryVersionApplied
		log.Printf("flow: snapshot loaded: version=%d prefixes=%d listeners=%d",
			initialDeliveryVersion, trie.Count(), len(snap.FlowListeners))

		// Restore flow listeners from snapshot (cold start without Controller)
		if len(snap.FlowListeners) > 0 {
			var pbListeners []*pb.FlowListenerConfig
			for _, sl := range snap.FlowListeners {
				lc := &pb.FlowListenerConfig{
					ListenAddress: sl.ListenAddress,
					ProtocolMode:  sl.ProtocolMode,
					Enabled:       true,
				}
				for _, ss := range sl.Sources {
					lc.Sources = append(lc.Sources, &pb.FlowSourceConfig{
						DeviceIp:   ss.DeviceIP,
						SampleMode: ss.SampleMode,
						SampleRate: int32(ss.SampleRate),
						Name:       ss.Name,
						Enabled:    true,
					})
				}
				pbListeners = append(pbListeners, lc)
			}
			applyFlowListeners(pbListeners, aggregator, &activeListeners)
			log.Printf("flow: restored %d listeners from snapshot", len(activeListeners))
		}
	}

	// Reporter (flow mode — receives *pb.StatsReport directly)
	rpt := reporter.NewFlow(reporter.Config{
		ControllerAddr: cfg.Controller.Address,
		NodeID:         cfg.NodeID,
		APIKey:         cfg.Auth.NodeAPIKey,
		InterfaceName:  "flow",
		AgentVersion:   "3.0.0",
		UpstreamRate:   1,
		Mode:           "flow",
	}, flowReports, applyConfig)
	rpt.SetDeliveryVersion(initialDeliveryVersion)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go rpt.Run(ctx)

	// 1-second aggregation loop — flush aggregator → flowReports channel → reporter → gRPC
	go func() {
		ticker := time.NewTicker(1 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				msg := aggregator.Flush(cfg.NodeID, "flow", 1)
				if msg != nil {
					select {
					case flowReports <- msg:
					default:
						log.Println("flow: report channel full, dropping tick")
					}
				}
			}
		}
	}()

	// Health check
	go func() {
		ticker := time.NewTicker(10 * time.Second)
		defer ticker.Stop()
		for range ticker.C {
			log.Printf("flow-health: prefixes=%d grpc=%v", trie.Count(), rpt.Connected())
		}
	}()

	log.Println("xsight-node (flow mode) running, waiting for signals...")

	// Systemd watchdog
	watchdog.Ready()
	watchdogDone := make(chan struct{})
	go watchdog.RunHeartbeat(watchdogDone)

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)
	sig := <-sigCh
	log.Printf("%s received — graceful shutdown", sig)
	watchdog.Stopping()
	close(watchdogDone)
	cancel()
}

// flowConfigChanged checks if the listener structure (addresses/protocols) changed.
// Source-only changes return false (handled by updateSourceTables without restart).
func flowConfigChanged(newCfg []*pb.FlowListenerConfig, active []*flow.Listener) bool {
	// Build map of current active listeners: addr → protocol_mode
	activeMap := make(map[string]string, len(active))
	for _, l := range active {
		activeMap[l.ListenAddr] = l.ProtocolMode
	}
	// Count enabled new listeners
	enabledCount := 0
	for _, lc := range newCfg {
		if !lc.Enabled {
			continue
		}
		enabledCount++
		oldMode, exists := activeMap[lc.ListenAddress]
		if !exists {
			return true // new listener address
		}
		if oldMode != lc.ProtocolMode {
			return true // protocol_mode changed → must restart
		}
	}
	if enabledCount != len(active) {
		return true // listener count changed
	}
	return false
}

// updateSourceTables refreshes source filter tables on existing listeners without restarting them.
// Preserves template cache and UDP socket.
func updateSourceTables(newCfg []*pb.FlowListenerConfig, active []*flow.Listener) {
	addrToListener := make(map[string]*flow.Listener, len(active))
	for _, l := range active {
		addrToListener[l.ListenAddr] = l
	}
	for _, lc := range newCfg {
		if !lc.Enabled {
			continue
		}
		l, ok := addrToListener[lc.ListenAddress]
		if !ok {
			continue
		}
		var sources []flow.SourceConfig
		for _, sc := range lc.Sources {
			if !sc.Enabled {
				continue
			}
			sources = append(sources, flow.SourceConfig{
				Name:       sc.Name,
				DeviceIP:   sc.DeviceIp,
				SampleMode: sc.SampleMode,
				SampleRate: int(sc.SampleRate),
				Enabled:    sc.Enabled,
			})
		}
		l.UpdateSources(sources)
	}
}

// applyFlowListeners reconciles running listeners with the new config from Controller.
// Only called when listener structure actually changed (new/removed listeners).
func applyFlowListeners(listeners []*pb.FlowListenerConfig, aggregator *flow.FlowAggregator, active *[]*flow.Listener) {
	// Stop all existing listeners (simple reconciliation — full diff-based update in future)
	for _, l := range *active {
		l.Stop()
	}
	*active = nil

	var newActive []*flow.Listener
	for _, lc := range listeners {
		if !lc.Enabled {
			continue
		}
		var sources []flow.SourceConfig
		for _, sc := range lc.Sources {
			if !sc.Enabled {
				continue
			}
			sources = append(sources, flow.SourceConfig{
				Name:       sc.Name,
				DeviceIP:   sc.DeviceIp,
				SampleMode: sc.SampleMode,
				SampleRate: int(sc.SampleRate),
				Enabled:    sc.Enabled,
			})
		}
		l, err := flow.NewListener(flow.ListenerConfig{
			ListenAddr:   lc.ListenAddress,
			ProtocolMode: lc.ProtocolMode,
			Sources:      sources,
			Aggregator:   aggregator,
		})
		if err != nil {
			log.Printf("flow: failed to create listener %s: %v", lc.ListenAddress, err)
			continue
		}
		if err := l.Start(); err != nil {
			log.Printf("flow: failed to start listener %s: %v", lc.ListenAddress, err)
			continue
		}
		newActive = append(newActive, l)
		log.Printf("flow: started listener %s protocol=%s sources=%d", lc.ListenAddress, lc.ProtocolMode, len(sources))
	}
	*active = newActive
	aggregator.SetListeners(newActive)
}
