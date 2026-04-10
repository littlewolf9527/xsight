// xsight-node — XDP/eBPF traffic observation agent
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	_ "net/http/pprof"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/littlewolf9527/xsight/node/internal/bpf"
	"github.com/littlewolf9527/xsight/node/internal/collector"
	"github.com/littlewolf9527/xsight/node/internal/config"
	"github.com/littlewolf9527/xsight/node/internal/pb"
	"github.com/littlewolf9527/xsight/node/internal/reporter"
	"github.com/littlewolf9527/xsight/node/internal/sampler"
	"github.com/littlewolf9527/xsight/node/internal/watchdog"
)

var (
	configPath   = flag.String("config", "config.yaml", "path to config file")
	unload       = flag.Bool("unload", false, "detach XDP, remove pins, and exit")
	testPrefixes = flag.String("prefixes", "", "comma-separated CIDR prefixes for dev testing (bypasses Controller/snapshot)")
)

func main() {
	flag.Parse()

	// Load configuration
	cfg, err := config.Load(*configPath)
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	// pprof debug server (localhost only, opt-in via config)
	if cfg.Pprof {
		go func() {
			log.Println("pprof: listening on 127.0.0.1:6061")
			if err := http.ListenAndServe("127.0.0.1:6061", nil); err != nil {
				log.Printf("pprof: %v", err)
			}
		}()
	}

	// v3.0: dispatch by mode
	if cfg.IsFlowMode() {
		runFlowMode(cfg)
		return
	}

	primaryIface := cfg.Interfaces[0]

	// --unload: detach XDP + remove pins + exit (P7)
	if *unload {
		log.Printf("unloading xsight-node from %s", primaryIface.Name)
		mgr, err := bpf.Load(primaryIface.Name, cfg.BPF.MaxEntries)
		if err != nil {
			log.Fatalf("load for unload: %v", err)
		}
		_ = mgr.AttachXDP(primaryIface.Name) // recover link to unpin it
		mgr.Unload()
		log.Println("unload complete")
		os.Exit(0)
	}

	log.Printf("xsight-node starting: node_id=%s interfaces=%d", cfg.NodeID, len(cfg.Interfaces))

	// P1+P7: Load BPF objects with pin persistence
	mgr, err := bpf.Load(primaryIface.Name, cfg.BPF.MaxEntries)
	if err != nil {
		log.Fatalf("Failed to load BPF: %v", err)
	}
	defer mgr.Close()

	for _, iface := range cfg.Interfaces {
		log.Printf("attaching XDP to %s (mode=%s)", iface.Name, iface.Mode)
		if err := mgr.AttachXDP(iface.Name); err != nil {
			log.Fatalf("Failed to attach XDP to %s: %v", iface.Name, err)
		}
	}

	// Apply BPF config from first interface (single-NIC MVP; per-NIC isolation deferred)
	if err := mgr.ApplyInterfaceConfig(primaryIface.Mode, primaryIface.SampleBytes, primaryIface.UpstreamSampleRate); err != nil {
		log.Fatalf("Failed to apply BPF config: %v", err)
	}

	// P6: Load snapshot → init BPF maps (don't wait for Controller)
	// If -prefixes flag is set, use that instead (dev testing override)
	var initialDeliveryVersion uint64
	if *testPrefixes != "" {
		var entries []bpf.PrefixEntry
		for _, cidr := range strings.Split(*testPrefixes, ",") {
			cidr = strings.TrimSpace(cidr)
			if cidr == "" {
				continue
			}
			pe, err := bpf.ParsePrefix(cidr)
			if err != nil {
				log.Fatalf("bad prefix %q: %v", cidr, err)
			}
			entries = append(entries, pe)
		}
		if err := mgr.PopulateTrie(entries); err != nil {
			log.Fatalf("populate trie: %v", err)
		}
	} else {
		// Load last Controller snapshot
		snap, err := config.LoadSnapshot(cfg.NodeID)
		if err != nil {
			log.Printf("snapshot load error: %v (starting with empty watch set)", err)
		} else if snap != nil {
			log.Printf("snapshot loaded: version=%d prefixes=%d age=%v",
				snap.DeliveryVersionApplied, len(snap.WatchPrefixes),
				time.Since(snap.Timestamp).Round(time.Second))
			var entries []bpf.PrefixEntry
			for _, sp := range snap.WatchPrefixes {
				pe, err := bpf.ParsePrefix(sp.Prefix)
				if err != nil {
					log.Printf("snapshot: skip bad prefix %q: %v", sp.Prefix, err)
					continue
				}
				entries = append(entries, pe)
			}
			if len(entries) > 0 {
				if err := mgr.PopulateTrie(entries); err != nil {
					log.Printf("snapshot: populate trie failed: %v", err)
				}
			}
			initialDeliveryVersion = snap.DeliveryVersionApplied
		} else {
			log.Println("no snapshot found, starting with empty watch set")
		}
	}

	// Collector ref for HotSwap notification (set after collector is created)
	var collRef *collector.Collector

	// P6: applyConfig callback — called by reporter on handshake + ConfigPush
	applyConfig := func(wc *pb.WatchConfig, deliveryVersion uint64) error {
		var entries []bpf.PrefixEntry
		var snapPrefixes []config.SnapshotPrefix
		for _, wp := range wc.GetPrefixes() {
			cidr := fmt.Sprintf("%s/%d", prefixBytesToIP(wp.Prefix), wp.PrefixLen)
			pe, err := bpf.ParsePrefix(cidr)
			if err != nil {
				log.Printf("applyConfig: skip bad prefix %q: %v", cidr, err)
				continue
			}
			entries = append(entries, pe)
			snapPrefixes = append(snapPrefixes, config.SnapshotPrefix{
				Prefix: cidr,
				Name:   wp.Name,
			})
		}

		if err := mgr.HotSwap(entries); err != nil {
			return err
		}
		// Notify collector to skip next tick's deltas (avoid cumulative-as-delta spike)
		if collRef != nil {
			collRef.NotifyHotSwap()
		}

		// Save snapshot
		snap := &config.Snapshot{
			WatchPrefixes:          snapPrefixes,
			DeliveryVersionApplied: deliveryVersion,
		}
		if ht := wc.GetHardThresholds(); ht != nil {
			snap.HardThresholds = config.SnapshotThresholds{PPS: ht.Pps, BPS: ht.Bps}
		}
		if err := config.SaveSnapshot(cfg.NodeID, snap); err != nil {
			log.Printf("snapshot save error: %v", err)
		} else {
			log.Printf("snapshot saved: version=%d prefixes=%d", deliveryVersion, len(entries))
		}
		return nil
	}

	// Flow table: aggregates gopacket samples by 5-tuple, drained each tick
	flowTable := sampler.NewFlowTable()

	// P3: Collector (created before reporter so applyConfig can notify it)
	collectorCtx, collectorCancel := context.WithCancel(context.Background())
	defer collectorCancel()
	coll := collector.New(mgr, collector.DefaultTargetSPS)
	coll.SetFlowTable(flowTable)
	collRef = coll // wire to applyConfig closure
	go coll.Run(collectorCtx)

	// P5+P6: Start gRPC reporter with applyConfig callback
	rpt := reporter.New(reporter.Config{
		ControllerAddr: cfg.Controller.Address,
		NodeID:         cfg.NodeID,
		APIKey:         cfg.Auth.NodeAPIKey,
		InterfaceName:  primaryIface.Name,
		AgentVersion:   "0.7.0",
		UpstreamRate:   primaryIface.UpstreamSampleRate,
	}, coll.Reports, applyConfig)
	rpt.SetDeliveryVersion(initialDeliveryVersion)
	go rpt.Run(collectorCtx)

	// P2+P4: Start ring buffer sampler with gopacket parser + batcher
	s, err := sampler.New(mgr.Objs.Samples)
	if err != nil {
		log.Fatalf("Failed to start sampler: %v", err)
	}
	defer s.Close()

	batcher := sampler.NewBatcher(sampler.DefaultBatchConfig(), rpt.BatchHandler())
	defer batcher.Close()
	rpt.SetBatcher(batcher)

	// Parallel parse pipeline: reader → N workers → aggregator
	// workers=1 bypasses channels (identical to old single-threaded path)
	pool := sampler.NewWorkerPool(cfg.ParseWorkers, flowTable, batcher)
	log.Printf("sampler: starting with %d parse workers", pool.Workers())
	go pool.Start(s)

	// Signal handling
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGHUP, syscall.SIGTERM, syscall.SIGINT)

	// Health check: log global_stats + interface state every 10s (P7)
	go func() {
		ticker := time.NewTicker(10 * time.Second)
		defer ticker.Stop()
		for range ticker.C {
			gs, err := mgr.GlobalStats()
			if err != nil {
				log.Printf("health check: %v", err)
				continue
			}
			// Check interface UP state
			ifaceStatus := "UP"
			if iface, err := net.InterfaceByName(primaryIface.Name); err != nil {
				ifaceStatus = "ERROR"
			} else if iface.Flags&net.FlagUp == 0 {
				ifaceStatus = "DOWN"
			}
			log.Printf("health: total_pkts=%d total_bytes=%d matched_pkts=%d samples=%d batches=%d decode_err=%d unique_src=%d grpc=%v iface=%s pin=%v workers=%d parsed=%d dispatch_drop=%d",
				gs.TotalPkts, gs.TotalBytes, gs.MatchedPkts, s.TotalSamples.Load(),
				batcher.Metrics.BatchesSent.Load(), batcher.Metrics.DecodeErrors.Load(),
				batcher.UniqueSourceCount(), rpt.Connected(), ifaceStatus, mgr.PinPath != "",
				pool.Workers(), pool.ParsedTotal.Load(), pool.DispatchDropped.Load())
		}
	}()

	log.Println("xsight-node running, waiting for signals...")

	// Systemd watchdog
	watchdog.Ready()
	watchdogDone := make(chan struct{})
	go watchdog.RunHeartbeat(watchdogDone)

	for sig := range sigCh {
		switch sig {
		case syscall.SIGHUP:
			log.Println("SIGHUP received — reloading config")
			newCfg, err := config.Load(*configPath)
			if err != nil {
				log.Printf("Config reload failed: %v (keeping old config)", err)
				continue
			}
			cfg = newCfg
			pi := cfg.Interfaces[0]
			if err := mgr.ApplyInterfaceConfig(pi.Mode, pi.SampleBytes, pi.UpstreamSampleRate); err != nil {
				log.Printf("Failed to apply reloaded config: %v", err)
				continue
			}
			log.Println("Config reloaded and applied successfully")

		case syscall.SIGTERM, syscall.SIGINT:
			log.Printf("%s received — graceful shutdown (pins preserved)", sig)
			watchdog.Stopping()
			close(watchdogDone)
			os.Exit(0)
		}
	}
}

// prefixBytesToIP converts proto prefix bytes to IP string.
func prefixBytesToIP(b []byte) string {
	if len(b) == 4 {
		return fmt.Sprintf("%d.%d.%d.%d", b[0], b[1], b[2], b[3])
	}
	// IPv6
	ip := make([]byte, 16)
	copy(ip, b)
	return fmt.Sprintf("%x:%x:%x:%x:%x:%x:%x:%x",
		uint16(ip[0])<<8|uint16(ip[1]),
		uint16(ip[2])<<8|uint16(ip[3]),
		uint16(ip[4])<<8|uint16(ip[5]),
		uint16(ip[6])<<8|uint16(ip[7]),
		uint16(ip[8])<<8|uint16(ip[9]),
		uint16(ip[10])<<8|uint16(ip[11]),
		uint16(ip[12])<<8|uint16(ip[13]),
		uint16(ip[14])<<8|uint16(ip[15]))
}
