// xsight-controller — DDoS detection controller.
//
// Usage:
//
//	xsight-controller -config config.yaml
//	xsight-controller -config config.yaml -migrate  # run migrations only
package main

import (
	"context"
	"encoding/json"
	"flag"
	"io/fs"
	"log"
	"net"
	"net/http"
	_ "net/http/pprof" // registers /debug/pprof/* on default mux
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/littlewolf9527/xsight/controller/internal/config"
	"github.com/littlewolf9527/xsight/controller/internal/action"
	"github.com/littlewolf9527/xsight/controller/internal/api"
	"github.com/littlewolf9527/xsight/controller/internal/configpub"
	"github.com/littlewolf9527/xsight/controller/internal/engine"
	"github.com/littlewolf9527/xsight/controller/internal/engine/baseline"
	"github.com/littlewolf9527/xsight/controller/internal/engine/classifier"
	"github.com/littlewolf9527/xsight/controller/internal/engine/dedup"
	"github.com/littlewolf9527/xsight/controller/internal/engine/threshold"
	"github.com/littlewolf9527/xsight/controller/internal/ingestion"
	"github.com/littlewolf9527/xsight/controller/internal/retention"
	"github.com/littlewolf9527/xsight/controller/internal/tracker"
	"github.com/littlewolf9527/xsight/controller/internal/watchdog"
	"github.com/littlewolf9527/xsight/controller/internal/netutil"
	pb "github.com/littlewolf9527/xsight/controller/internal/pb"
	"github.com/littlewolf9527/xsight/controller/internal/store"
	"github.com/littlewolf9527/xsight/controller/internal/store/postgres"
	"github.com/littlewolf9527/xsight/controller/internal/store/ring"
	"github.com/littlewolf9527/xsight/shared/decoder"
	"golang.org/x/crypto/bcrypt"
)

var (
	configPath  = flag.String("config", "config.yaml", "path to config file")
	migrateOnly = flag.Bool("migrate", false, "run migrations and exit")
)

func main() {
	flag.Parse()

	cfg, err := config.Load(*configPath)
	if err != nil {
		log.Fatalf("config: %v", err)
	}
	log.Printf("config loaded: grpc=%s http=%s db=%s",
		cfg.Listen.GRPC, cfg.Listen.HTTP, cfg.Database.Driver)

	// pprof server on localhost only (not exposed externally)
	go func() {
		log.Println("pprof listening on 127.0.0.1:6060")
		if err := http.ListenAndServe("127.0.0.1:6060", nil); err != nil {
			log.Printf("pprof server: %v", err)
		}
	}()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Connect database
	var db *postgres.PGStore
	switch cfg.Database.Driver {
	case "postgres":
		db, err = postgres.New(ctx, cfg.Database.DSN)
		if err != nil {
			log.Fatalf("database: %v", err)
		}
		defer db.Close()
		log.Println("PostgreSQL connected")
	case "sqlite":
		log.Fatal("SQLite driver not yet implemented")
	}

	// Run migrations (retention policies from config)
	if err := db.AutoMigrate(ctx, postgres.RetentionConfig{
		TSStatsDays:          cfg.Retention.TSStatsDays,
		TSStatsCompressDays:  cfg.Retention.TSStatsCompressDays,
		TSStatsCaggDays:      cfg.Retention.TSStatsCaggDays,
		FlowLogsDays:         cfg.Retention.FlowLogsDays,
		FlowLogsCompressDays: cfg.Retention.FlowLogsCompressDays,
	}); err != nil {
		log.Fatalf("migrate: %v", err)
	}
	log.Println("database migrations complete")

	if *migrateOnly {
		log.Println("migrate-only mode, exiting")
		return
	}

	// Seed default admin user if no users exist
	{
		users, err := db.Users().List(ctx)
		if err != nil {
			log.Fatalf("list users for seed check: %v", err)
		}
		if len(users) == 0 {
			hash, err := bcrypt.GenerateFromPassword([]byte("admin"), bcrypt.DefaultCost)
			if err != nil {
				log.Fatalf("hash default password: %v", err)
			}
			_, err = db.Users().Create(ctx, &store.User{
				Username: "admin",
				Password: string(hash),
				Role:     "admin",
				Enabled:  true,
			})
			if err != nil {
				log.Fatalf("seed admin user: %v", err)
			}
			log.Println("created default admin user (username: admin, password: admin) — change this immediately!")
		}
	}

	// --- Phase 2: Ring Buffer + DB writer ---

	ringLimits := ring.Limits{
		MaxPointsPerIP:  cfg.Ring.MaxPointsPerIP,
		MaxIPsPerPrefix: cfg.Ring.MaxIPsPerPrefix,
		MaxGlobalKeys:   cfg.Ring.MaxGlobalKeys,
	}
	log.Printf("ring: limits points_per_ip=%d ips_per_prefix=%d global_keys=%d",
		ringLimits.MaxPointsPerIP, ringLimits.MaxIPsPerPrefix, ringLimits.MaxGlobalKeys)
	rings := ring.New(ringLimits)
	statsWriter := ingestion.NewStatsWriter(rings)
	dbWriter := ingestion.NewDBWriter(rings, db.Stats(), 5*time.Second)
	go dbWriter.Run(ctx)

	// --- Phase 3: Detection engine ---

	// 3.1 Threshold inheritance tree
	threshTree := threshold.NewTree()
	if err := threshTree.Rebuild(ctx, db); err != nil {
		log.Fatalf("threshold tree: %v", err)
	}
	statsWriter.SetGlobalChecker(threshTree)

	// 3.2 Hard threshold detector
	detector := threshold.NewDetector(threshTree, rings)

	// 3.3 Dynamic baseline (beta)
	baselineCfg := baseline.DefaultConfig()
	baselineCalc := baseline.NewCalculator(db.Stats(), baselineCfg)

	// 3.3b Dynamic detection profile engine
	profileEngine := baseline.NewProfileEngine(rings, db.DynDetect(), db.Stats())
	if err := profileEngine.LoadFromDB(ctx); err != nil {
		log.Printf("profile engine load: %v", err)
	}

	go func() {
		ticker := time.NewTicker(1 * time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				baselineCalc.Recompute()
				profileEngine.RefreshConfig(ctx)
			}
		}
	}()

	// Hourly profile updater
	go func() {
		// Wait until next hour boundary
		now := time.Now().UTC()
		nextHour := now.Truncate(time.Hour).Add(time.Hour)
		select {
		case <-ctx.Done():
			return
		case <-time.After(nextHour.Sub(now)):
		}
		profileEngine.UpdateHourly()
		ticker := time.NewTicker(1 * time.Hour)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				profileEngine.UpdateHourly()
			}
		}
	}()

	// 3.4 Attack classifier
	attackClassifier := classifier.New()

	// 3.5 Alert dedup
	alertDedup := dedup.New()

	// --- Phase 4: AttackTracker ---
	trackerCfg := tracker.Config{
		HardConfirmSeconds:     cfg.Detection.HardThresholdConfirmSeconds,
		DynamicConfirmSeconds:  cfg.Detection.DynamicThresholdConfirmSeconds,
		ExpiryIntervalSeconds:  cfg.Detection.ExpiryIntervalSeconds,
		ExpiryFunction:         cfg.Detection.ExpiryFunction,
		ExpiryScaleBaseSeconds: cfg.Detection.ExpiryScaleBaseSeconds,
		ExpiryMaxScale:         cfg.Detection.ExpiryMaxScale,
		MaxActiveAttacks:       cfg.Detection.MaxActiveAttacks,
	}
	// --- Phase 5: Action Engine ---
	actionEngine := action.NewEngine(db, cfg.Action.Mode)

	attackTracker := tracker.New(trackerCfg, db, rings, alertDedup, actionEngine.HandleEvent)
	attackTracker.SetRebreachCallback(actionEngine.CancelDelaysForAttack)

	// v1.2 PR-3/PR-4 crash recovery: run before serving traffic.
	// Three phases (executed in order by ReconcileOnStartup):
	//   1. Retry side effects for scheduled_actions stuck in 'executing'
	//      (PR-3 leftover: crashed between MarkExecuting and Complete)
	//   2. Retry DELETE for xdrop_active_rules stuck in 'withdrawing'
	//      (PR-4: crashed between MarkWithdrawing and MarkWithdrawn)
	//   3. Re-arm timers for pending scheduled_actions; overdue ones fire
	//      immediately (PR-3: timer lost during downtime).
	actionEngine.ReconcileOnStartup(ctx)

	// Crash recovery: rebuild active attacks from DB
	if err := attackTracker.RecoverFromDB(ctx); err != nil {
		log.Printf("tracker recovery: %v", err)
	}

	// BGP recovery: re-inject ephemeral routes for active attacks (FRR state lost on restart)
	action.RecoverBGPRoutes(ctx, db)

	// BGP bootstrap: scan FRR for routes not represented in bgp_announcements
	// and mark them as orphan / dismissed_on_upgrade. See bgp_bootstrap.go for
	// the first-boot vs. runtime semantics.
	action.BootstrapBGPOrphans(ctx, db)

	// --- Phase 1: gRPC ingestion layer ---
	nodeState := ingestion.NewNodeState()

	// Detection tick loop (1s interval) → feed to AttackTracker
	go func() {
		ticker := time.NewTicker(1 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				// Hard threshold detection — per-node
				connectedNodes := nodeState.ConnectedNodes()
				exceeded := detector.Tick(connectedNodes)

				// Dynamic baseline detection: check prefix-level per-node
				for _, nodeID := range connectedNodes {
					for _, prefix := range threshTree.AllPrefixes() {
						pr := rings.GetPrefixRing(nodeID, prefix)
						if pr == nil {
							continue
						}
						if dp, ok := pr.LatestOne(5 * time.Second); ok {
							if yes, reason := profileEngine.IsExceeded(nodeID, prefix, dp.PPS, dp.BPS); yes {
								exceeded = append(exceeded, engine.ThresholdExceeded{
									Prefix:    prefix,
									Direction: "receives",
									Decoder:   "ip",
									Unit:      "pps",
									Value:     0,
									Actual:    dp.PPS,
									Domain:    "subnet",
									NodeID:    nodeID,
									Source:    "dynamic",
								})
								_ = reason
							}
						}
					}
				}

				// Filter through dedup
				var filtered []engine.ThresholdExceeded
				for _, evt := range exceeded {
					if !alertDedup.ShouldSuppress(evt) {
						filtered = append(filtered, evt)
					}
				}
				// Feed to AttackTracker state machine (MUST call every tick,
				// even when empty, so expiry timers advance)
				if cfg.Detection.DryRun {
					// Dry-run: log detections but don't create attacks
					for _, evt := range filtered {
						log.Printf("DRY-RUN: would trigger %s decoder=%s %s=%d (threshold=%d) prefix=%s",
							evt.DstIP, evt.Decoder, evt.Unit, evt.Actual, evt.Value, evt.Prefix)
					}
					filtered = nil // don't feed tracker
				}
					attackTracker.Feed(filtered)

				// Classifier: try to upgrade active attacks with sample data
				for _, dstIP := range attackTracker.ActiveDstIPs() {
					ip := net.ParseIP(dstIP)
					if ip == nil {
						continue
					}
					result := attackClassifier.Classify(ip)
					if result != nil {
						attackTracker.UpgradeType(ip, result.AttackType, result.Confidence, result.Reasons)
					}
				}
			}
		}
	}()

	// Wire classifier to sample worker pool
	samplePool := ingestion.NewSampleWorkerPool(func(nodeID string, batch *pb.SampleBatch) {
		attackClassifier.Ingest(batch)
	})
	defer samplePool.Close()

	// Flow writer: top_flows → flow_logs table
	flowWriter := ingestion.NewFlowWriter(db.FlowLogs())

	// StatsStream → Ring Buffer + DB enqueue + detection + flow_logs
	onStats := func(nodeID string, report *pb.StatsReport) {
		statsWriter.HandleStats(nodeID, report)
		dbWriter.Enqueue(reportToStatPoints(nodeID, report))
		flowWriter.HandleFlows(nodeID, report)

		// Store flow metrics for API exposure
		// Proto field mapping for flow mode: dropped_user=unknown_exporter, dropped_kernel=template_misses
		if sm := report.GetSamplingMetrics(); sm != nil {
			nodeState.UpdateFlowMetrics(nodeID, sm.GetDecodeError(), sm.GetDroppedUser(), sm.GetDroppedKernel())
		}
		// Parse per-source and per-listener status from NodeHealth.Message (flow mode encodes JSON)
		if h := report.GetHealth(); h != nil && len(h.Message) > 1 && h.Message[0] == '{' {
			var parsed struct {
				Sources   []ingestion.SourceStatus   `json:"sources"`
				Listeners []ingestion.ListenerStatus  `json:"listeners"`
			}
			if json.Unmarshal([]byte(h.Message), &parsed) == nil {
				nodeState.UpdateSourceStatuses(nodeID, parsed.Sources)
				nodeState.UpdateListenerStatuses(nodeID, parsed.Listeners)
			}
		}

		gs := report.GetGlobalStats()
		pc, ic, _ := rings.Stats()
		log.Printf("stats: node=%s ts=%d ips=%d prefixes=%d global={pkts=%d matched=%d} ring={prefixes=%d ips=%d}",
			nodeID, report.Timestamp, len(report.IpStats), len(report.PrefixStats),
			gs.GetTotalPkts(), gs.GetMatchedPkts(), pc, ic)
	}

	onCritical := func(nodeID string, event *pb.CriticalEvent) {
		log.Printf("critical: node=%s type=%s dst=%v",
			nodeID, event.EventType, net.IP(event.DstIp))
	}

	handler := ingestion.NewGRPCHandler(ingestion.GRPCHandlerConfig{
		Store:      db,
		NodeState:  nodeState,
		SamplePool: samplePool,
		OnStats:    onStats,
		OnCritical: onCritical,
	})

	grpcSrv := ingestion.NewServer(handler)
	go func() {
		if err := grpcSrv.Serve(cfg.Listen.GRPC); err != nil {
			log.Fatalf("grpc server fatal: %v", err)
		}
	}()

	// --- Phase 6: Config Publisher ---
	configPub := configpub.New(db, handler, nodeState.ConnectedNodes)
	go configPub.RunDriftChecker(ctx)

	// --- Phase 7: REST API ---
	jwtSecret := cfg.Auth.APIKey + "-jwt" // derive JWT secret from API key
	router := api.NewRouter(api.Dependencies{
		Store:         db,
		ConfigPub:     configPub,
		NodeState:     nodeState,
		ThreshTree:    threshTree,
		Tracker:       attackTracker,
		ActionEngine:  actionEngine,
		BaselineCalc:  baselineCalc,
		ProfileEngine: profileEngine,
		APIKey:        cfg.Auth.APIKey,
		JWTSecret:     jwtSecret,
		FlowLogsDays:  cfg.Retention.FlowLogsDays,
	})
	// Serve embedded Vue SPA (Phase 8)
	webFS, _ := fs.Sub(webDist, "web/dist")
	api.ServeSPA(router, webFS)

	go func() {
		log.Printf("http: listening on %s", cfg.Listen.HTTP)
		if err := router.Run(cfg.Listen.HTTP); err != nil {
			log.Fatalf("http server fatal: %v", err)
		}
	}()

	// Wait briefly for listeners to bind, then signal ready
	time.Sleep(500 * time.Millisecond)
	log.Printf("xsight-controller running (mode=%s)", cfg.Action.Mode)

	// Data retention cleaner
	if cfg.Retention.TSStatsDays > 0 || cfg.Retention.AttacksDays > 0 || cfg.Retention.AuditLogDays > 0 {
		cleaner := retention.New(db.Pool(), retention.Config{
			TSStatsDays:   cfg.Retention.TSStatsDays,
			FlowLogsDays:  cfg.Retention.FlowLogsDays,
			AttacksDays:   cfg.Retention.AttacksDays,
			AuditLogDays:  cfg.Retention.AuditLogDays,
			IntervalHours: cfg.Retention.IntervalHours,
			HasTimescale:  db.HasTimescale(),
		})
		go cleaner.Run(ctx)
		log.Printf("retention: ts_stats=%dd attacks=%dd audit=%dd interval=%dh",
			cfg.Retention.TSStatsDays, cfg.Retention.AttacksDays, cfg.Retention.AuditLogDays, cfg.Retention.IntervalHours)
	}

	// Systemd watchdog: signal ready + start heartbeat
	watchdog.Ready()
	watchdogDone := make(chan struct{})
	go watchdog.RunHeartbeat(watchdogDone)

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)
	sig := <-sigCh
	log.Printf("received %v, shutting down", sig)
	watchdog.Stopping()
	close(watchdogDone)
	cancel()
	grpcSrv.GracefulStop()
}

func reportToStatPoints(nodeID string, report *pb.StatsReport) []store.StatPoint {
	ts := time.Unix(report.Timestamp, 0)
	// BPF counters are exact (every matched packet), only upstream sampling needs restoration.
	// local_sample_rate only affects ring buffer sampling, not ip_stats/prefix_stats counters.
	mul := uint64(1)
	if report.UpstreamSampleRate > 1 {
		mul = uint64(report.UpstreamSampleRate)
	}
	mul64 := int64(mul)

	var points []store.StatPoint

	// Inbound prefix stats (direction=receives)
	for _, ps := range report.PrefixStats {
		prefix := netutil.FormatPrefix(ps.Prefix, ps.PrefixLen)
		sp := store.StatPoint{
			Time:      ts,
			NodeID:    nodeID,
			Prefix:    &prefix,
			Direction: "receives",
			PPS:       int64(ps.PktCount) * mul64,
			BPS:       int64(ps.ByteCount) * 8 * mul64,
		}
		counts := ps.GetDecoderCounts()
		if len(counts) > 0 {
			for j := 0; j < len(counts) && j < decoder.MaxDecoders; j++ {
				sp.DecoderPPS[j] = int32(int64(counts[j]) * mul64)
			}
		} else {
			sp.DecoderPPS[decoder.TCP] = int32(int64(ps.GetTcpCount()) * mul64)
			sp.DecoderPPS[decoder.TCPSyn] = int32(int64(ps.GetTcpSynCount()) * mul64)
			sp.DecoderPPS[decoder.UDP] = int32(int64(ps.GetUdpCount()) * mul64)
			sp.DecoderPPS[decoder.ICMP] = int32(int64(ps.GetIcmpCount()) * mul64)
			sp.DecoderPPS[decoder.Frag] = int32(int64(ps.GetFragCount()) * mul64)
		}
		byteCounts := ps.GetDecoderByteCounts()
		for j := 0; j < len(byteCounts) && j < decoder.MaxDecoders; j++ {
			sp.DecoderBPS[j] = int64(byteCounts[j]) * 8 * mul64
		}
		points = append(points, sp)
	}
	// Inbound per-IP stats (direction=receives)
	for _, ip := range report.IpStats {
		dstIP := net.IP(ip.DstIp).String()
		sp := store.StatPoint{
			Time:      ts,
			NodeID:    nodeID,
			DstIP:     &dstIP,
			Direction: "receives",
			PPS:       int64(ip.PktCount) * mul64,
			BPS:       int64(ip.ByteCount) * 8 * mul64,
		}
		counts := ip.GetDecoderCounts()
		if len(counts) > 0 {
			for j := 0; j < len(counts) && j < decoder.MaxDecoders; j++ {
				sp.DecoderPPS[j] = int32(int64(counts[j]) * mul64)
			}
		} else {
			sp.DecoderPPS[0] = int32(int64(ip.GetTcpCount()) * mul64)
			sp.DecoderPPS[1] = int32(int64(ip.GetTcpSynCount()) * mul64)
			sp.DecoderPPS[2] = int32(int64(ip.GetUdpCount()) * mul64)
			sp.DecoderPPS[3] = int32(int64(ip.GetIcmpCount()) * mul64)
			sp.DecoderPPS[4] = int32(int64(ip.GetFragCount()) * mul64)
		}
		byteCounts := ip.GetDecoderByteCounts()
		for j := 0; j < len(byteCounts) && j < decoder.MaxDecoders; j++ {
			sp.DecoderBPS[j] = int64(byteCounts[j]) * 8 * mul64
		}
		points = append(points, sp)
	}

	// Outbound prefix stats (direction=sends)
	for _, sps := range report.GetSrcPrefixStats() {
		prefix := netutil.FormatPrefix(sps.Prefix, sps.PrefixLen)
		sp := store.StatPoint{
			Time:      ts,
			NodeID:    nodeID,
			Prefix:    &prefix,
			Direction: "sends",
			PPS:       int64(sps.PktCount) * mul64,
			BPS:       int64(sps.ByteCount) * 8 * mul64,
		}
		counts := sps.GetDecoderCounts()
		for j := 0; j < len(counts) && j < decoder.MaxDecoders; j++ {
			sp.DecoderPPS[j] = int32(int64(counts[j]) * mul64)
		}
		byteCounts := sps.GetDecoderByteCounts()
		for j := 0; j < len(byteCounts) && j < decoder.MaxDecoders; j++ {
			sp.DecoderBPS[j] = int64(byteCounts[j]) * 8 * mul64
		}
		points = append(points, sp)
	}

	// Outbound per-IP stats (direction=sends)
	for _, sip := range report.GetSrcIpStats() {
		srcIP := net.IP(sip.DstIp).String() // proto reuses dst_ip bytes for src_ip
		sp := store.StatPoint{
			Time:      ts,
			NodeID:    nodeID,
			DstIP:     &srcIP,
			Direction: "sends",
			PPS:       int64(sip.PktCount) * mul64,
			BPS:       int64(sip.ByteCount) * 8 * mul64,
		}
		counts := sip.GetDecoderCounts()
		for j := 0; j < len(counts) && j < decoder.MaxDecoders; j++ {
			sp.DecoderPPS[j] = int32(int64(counts[j]) * mul64)
		}
		byteCounts := sip.GetDecoderByteCounts()
		for j := 0; j < len(byteCounts) && j < decoder.MaxDecoders; j++ {
			sp.DecoderBPS[j] = int64(byteCounts[j]) * 8 * mul64
		}
		points = append(points, sp)
	}

	return points
}
