package api

import (
	"net/http"
	"sort"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/littlewolf9527/xsight/controller/internal/store"
	"github.com/littlewolf9527/xsight/controller/internal/store/ring"
	"github.com/littlewolf9527/xsight/shared/decoder"
)

type nodeInfo struct {
	ID   string `json:"id"`
	Mode string `json:"mode"`
}

type prefixTraffic struct {
	Prefix  string     `json:"prefix"`
	PPS     int64      `json:"pps"`
	BPS     int64      `json:"bps"`
	TCPPPS  int32      `json:"tcp_pps"`
	UDPPPS  int32      `json:"udp_pps"`
	ICMPPPS int32      `json:"icmp_pps"`
	TCPBPS  int64      `json:"tcp_bps"`
	UDPBPS  int64      `json:"udp_bps"`
	ICMPBPS int64      `json:"icmp_bps"`
	Nodes   []nodeInfo `json:"nodes"`
	nodeSet map[string]bool `json:"-"`
}

func trafficOverview(deps Dependencies) gin.HandlerFunc {
	return func(c *gin.Context) {
		rings := deps.ProfileEngine.Rings()
		if rings == nil {
			ok(c, gin.H{
				"total_pps":       0,
				"total_bps":       0,
				"node_count":      0,
				"active_prefixes": 0,
				"top_prefixes":    []any{},
			})
			return
		}

		// Direction: receives (default), sends, both
		direction := c.DefaultQuery("direction", "receives")
		if direction != "receives" && direction != "sends" && direction != "both" {
			errResponse(c, http.StatusBadRequest, "direction must be 'receives', 'sends', or 'both'")
			return
		}

		// Optional node_id filter: only include data from this node
		filterNodeID := c.Query("node_id")

		// Collect prefix traffic from the appropriate ring(s)
		type ringSource struct {
			nps    []ring.NodePrefix
			getRing func(nodeID, prefix string) *ring.PrefixRing
		}
		var sources []ringSource
		if direction == "receives" || direction == "both" {
			sources = append(sources, ringSource{
				nps:    rings.AllNodePrefixes(),
				getRing: rings.GetPrefixRing,
			})
		}
		if direction == "sends" || direction == "both" {
			sources = append(sources, ringSource{
				nps:    rings.AllOutboundNodePrefixes(),
				getRing: rings.GetSrcPrefixRing,
			})
		}

		prefixMap := make(map[string]*prefixTraffic)
		nodeSet := make(map[string]bool)
		var totalPPS, totalBPS int64

		for _, src := range sources {
			for _, np := range src.nps {
				// Skip virtual global prefix — its data is already included in specific prefixes
				if np.Prefix == "0.0.0.0/0" {
					continue
				}
				pr := src.getRing(np.NodeID, np.Prefix)
				if pr == nil {
					continue
				}
				dp, found := pr.LatestOne(10 * time.Second)
				if !found {
					continue
				}

				// node_id filter
				if filterNodeID != "" && np.NodeID != filterNodeID {
					continue
				}

				nodeSet[np.NodeID] = true
				totalPPS += dp.PPS
				totalBPS += dp.BPS

				pt, exists := prefixMap[np.Prefix]
				if !exists {
					pt = &prefixTraffic{Prefix: np.Prefix, nodeSet: make(map[string]bool)}
					prefixMap[np.Prefix] = pt
				}
				pt.PPS += dp.PPS
				pt.BPS += dp.BPS
				pt.TCPPPS += dp.DecoderPPS[decoder.TCP]
				pt.UDPPPS += dp.DecoderPPS[decoder.UDP]
				pt.ICMPPPS += dp.DecoderPPS[decoder.ICMP]
				pt.TCPBPS += dp.DecoderBPS[decoder.TCP]
				pt.UDPBPS += dp.DecoderBPS[decoder.UDP]
				pt.ICMPBPS += dp.DecoderBPS[decoder.ICMP]
				pt.nodeSet[np.NodeID] = true
			}
		}

		// Sort by PPS desc, take top N (default 20, max 200)
		topN := 20
		if n, err := strconv.Atoi(c.DefaultQuery("limit", "20")); err == nil && n > 0 {
			topN = n
		}
		if topN > 200 {
			topN = 200
		}
		// Build node mode lookup
		allNodes, _ := deps.Store.Nodes().List(c)
		nodeModeMap := make(map[string]string, len(allNodes))
		for _, n := range allNodes {
			nodeModeMap[n.ID] = n.Mode
		}

		topPrefixes := make([]prefixTraffic, 0, len(prefixMap))
		for _, pt := range prefixMap {
			pt.Nodes = make([]nodeInfo, 0, len(pt.nodeSet))
			for nid := range pt.nodeSet {
				mode := nodeModeMap[nid]
				if mode == "" {
					mode = "xdp"
				}
				pt.Nodes = append(pt.Nodes, nodeInfo{ID: nid, Mode: mode})
			}
			topPrefixes = append(topPrefixes, *pt)
		}
		sort.Slice(topPrefixes, func(i, j int) bool {
			return topPrefixes[i].PPS > topPrefixes[j].PPS
		})
		if len(topPrefixes) > topN {
			topPrefixes = topPrefixes[:topN]
		}

		ok(c, gin.H{
			"total_pps":       totalPPS,
			"total_bps":       totalBPS,
			"node_count":      len(nodeSet),
			"active_prefixes": len(prefixMap),
			"top_prefixes":    topPrefixes,
		})
	}
}

func totalTimeseries(deps Dependencies) gin.HandlerFunc {
	return func(c *gin.Context) {
		resolution := c.DefaultQuery("resolution", "5min")
		limit := 1000
		switch resolution {
		case "5s":
			limit = 7200
		case "5min":
			limit = 2000
		case "1h":
			limit = 1000
		}
		dir := c.Query("direction")
		if dir != "" && dir != "receives" && dir != "sends" && dir != "both" {
			errResponse(c, http.StatusBadRequest, "direction must be 'receives', 'sends', or 'both'")
			return
		}
		filter := store.TimeseriesFilter{
			Resolution: resolution,
			Direction:  dir,
			Limit:      limit,
		}
		if from := c.Query("from"); from != "" {
			if t, err := time.Parse(time.RFC3339, from); err == nil {
				filter.From = t
			}
		}
		if to := c.Query("to"); to != "" {
			if t, err := time.Parse(time.RFC3339, to); err == nil {
				filter.To = t
			}
		}
		if filter.From.IsZero() {
			filter.From = time.Now().Add(-1 * time.Hour)
		}

		points, err := deps.Store.Stats().QueryTotalTimeseries(c, filter)
		if err != nil {
			errResponse(c, http.StatusInternalServerError, err.Error())
			return
		}
		ok(c, points)
	}
}
