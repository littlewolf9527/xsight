package postgres

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/littlewolf9527/xsight/controller/internal/store"
	"github.com/littlewolf9527/xsight/shared/decoder"
)

type statsRepo struct{ pool *pgxpool.Pool }

// buildExtraDecoderPPS collects decoder PPS values with index >= StandardCount into a
// name-keyed map. Returns nil when all extra indices are zero — stored as SQL NULL to
// save space on rows without v1.3+ decoders.
func buildExtraDecoderPPS(decoderPPS [decoder.MaxDecoders]int32) map[string]int32 {
	var out map[string]int32
	for i := decoder.StandardCount; i < decoder.MaxDecoders; i++ {
		v := decoderPPS[i]
		if v == 0 {
			continue
		}
		name := decoder.Names[i]
		if name == "" {
			continue
		}
		if out == nil {
			out = make(map[string]int32)
		}
		out[name] = v
	}
	return out
}

// buildExtraDecoderBPS is the BPS variant of buildExtraDecoderPPS.
func buildExtraDecoderBPS(decoderBPS [decoder.MaxDecoders]int64) map[string]int64 {
	var out map[string]int64
	for i := decoder.StandardCount; i < decoder.MaxDecoders; i++ {
		v := decoderBPS[i]
		if v == 0 {
			continue
		}
		name := decoder.Names[i]
		if name == "" {
			continue
		}
		if out == nil {
			out = make(map[string]int64)
		}
		out[name] = v
	}
	return out
}

// encodeJSONB marshals a map into []byte for pgx; nil map → SQL NULL.
func encodeJSONB(m any) any {
	// Handle both int32 and int64 maps by checking reflectively via type switch.
	switch v := m.(type) {
	case map[string]int32:
		if len(v) == 0 {
			return nil
		}
		b, err := json.Marshal(v)
		if err != nil {
			return nil
		}
		return b
	case map[string]int64:
		if len(v) == 0 {
			return nil
		}
		b, err := json.Marshal(v)
		if err != nil {
			return nil
		}
		return b
	}
	return nil
}

// BulkInsert writes stat points into ts_stats using pgx.CopyFrom for maximum throughput.
func (r *statsRepo) BulkInsert(ctx context.Context, points []store.StatPoint) error {
	if len(points) == 0 {
		return nil
	}

	columns := []string{
		"time", "node_id", "dst_ip", "prefix", "direction",
		"pps", "bps", "tcp_pps", "tcp_syn_pps", "udp_pps", "icmp_pps", "frag_pps",
		"tcp_bps", "udp_bps", "icmp_bps", "frag_bps",
		"extra_decoder_pps", "extra_decoder_bps",
	}

	rows := make([][]any, len(points))
	for i, p := range points {
		dir := p.Direction
		if dir == "" {
			dir = "receives"
		}
		extraPPS := encodeJSONB(buildExtraDecoderPPS(p.DecoderPPS))
		extraBPS := encodeJSONB(buildExtraDecoderBPS(p.DecoderBPS))
		rows[i] = []any{
			p.Time, p.NodeID, p.DstIP, p.Prefix, dir,
			p.PPS, p.BPS,
			p.DecoderPPS[decoder.TCP], p.DecoderPPS[decoder.TCPSyn], p.DecoderPPS[decoder.UDP], p.DecoderPPS[decoder.ICMP], p.DecoderPPS[decoder.Frag],
			p.DecoderBPS[decoder.TCP], p.DecoderBPS[decoder.UDP], p.DecoderBPS[decoder.ICMP], p.DecoderBPS[decoder.Frag],
			extraPPS, extraBPS,
		}
	}

	_, err := r.pool.CopyFrom(ctx,
		pgx.Identifier{"ts_stats"},
		columns,
		pgx.CopyFromRows(rows),
	)
	return err
}

// QueryTimeseries returns aggregated time-series data for charting.
// Routing: 5s → raw, 5min (≤1H range) → raw (realtime), 5min/1h (>1H range) → cagg.
func (r *statsRepo) QueryTimeseries(ctx context.Context, filter store.TimeseriesFilter) ([]store.TimeseriesPoint, error) {
	limit := clampLimit(filter.Limit)

	// 1H view (5min resolution, ≤1H range): use raw for realtime data (no cagg delay).
	// 6H/24H view (5min/1h resolution, >1H range): use cagg for performance.
	useCagg := false
	if filter.Resolution != "5s" {
		timeRange := time.Since(filter.From)
		if timeRange > 90*time.Minute { // >1.5H → use cagg (covers 6H and 24H views)
			useCagg = true
		}
	}

	if useCagg {
		points, err := r.queryTimeseriesFromCagg(ctx, filter, limit)
		if err == nil {
			return points, nil
		}
		// Fallback to raw table if cagg doesn't exist or query failed
		log.Printf("WARNING: cagg query failed, falling back to raw ts_stats: %v", err)
	}

	return r.queryTimeseriesFromRaw(ctx, filter, limit)
}

// queryTimeseriesFromCagg queries the ts_stats_5min continuous aggregate.
func (r *statsRepo) queryTimeseriesFromCagg(ctx context.Context, filter store.TimeseriesFilter, limit int) ([]store.TimeseriesPoint, error) {
	var conds []string
	var args []any
	argN := 1

	if !filter.From.IsZero() {
		conds = append(conds, fmt.Sprintf("bucket >= $%d", argN))
		args = append(args, filter.From)
		argN++
	}
	if !filter.To.IsZero() {
		conds = append(conds, fmt.Sprintf("bucket <= $%d", argN))
		args = append(args, filter.To)
		argN++
	}
	if filter.Prefix != "" {
		conds = append(conds, fmt.Sprintf("prefix <<= $%d::CIDR", argN))
		args = append(args, filter.Prefix)
		argN++
	}
	if filter.NodeID != "" {
		conds = append(conds, fmt.Sprintf("node_id = $%d", argN))
		args = append(args, filter.NodeID)
		argN++
	}

	// Direction filter (v2.11 Phase 3)
	dir := filter.Direction
	if dir == "" {
		dir = "receives"
	}
	if dir != "both" {
		conds = append(conds, fmt.Sprintf("direction = $%d", argN))
		args = append(args, dir)
		argN++
	}

	where := ""
	if len(conds) > 0 {
		where = " WHERE " + strings.Join(conds, " AND ")
	}

	// For 5min resolution: cagg rows are already at 5min granularity, just sum across prefixes.
	// For 1h resolution: two-phase — first sum across prefixes per 5min bucket,
	// then avg those totals across the hour (otherwise we'd sum 12 buckets instead of averaging).
	// CAGG v5 includes frag_pps/bps. Extra decoders (v1.3) are NOT in CAGG — raw-only.
	var q string
	if filter.Resolution == "1h" {
		q = fmt.Sprintf(`
			SELECT time_bucket('1 hour', bucket) AS ts,
				   avg(total_pps)::BIGINT AS pps,
				   avg(total_bps)::BIGINT AS bps,
				   avg(total_tcp)::INT AS tcp_pps,
				   avg(total_syn)::INT AS tcp_syn_pps,
				   avg(total_udp)::INT AS udp_pps,
				   avg(total_icmp)::INT AS icmp_pps,
				   avg(total_frag)::INT AS frag_pps,
				   avg(total_tcp_bps)::BIGINT AS tcp_bps,
				   avg(total_udp_bps)::BIGINT AS udp_bps,
				   avg(total_icmp_bps)::BIGINT AS icmp_bps,
				   avg(total_frag_bps)::BIGINT AS frag_bps
			FROM (
				SELECT bucket,
					   sum(avg_pps) AS total_pps,
					   sum(avg_bps) AS total_bps,
					   sum(avg_tcp_pps) AS total_tcp,
					   sum(avg_tcp_syn_pps) AS total_syn,
					   sum(avg_udp_pps) AS total_udp,
					   sum(avg_icmp_pps) AS total_icmp,
					   sum(avg_frag_pps) AS total_frag,
					   sum(avg_tcp_bps) AS total_tcp_bps,
					   sum(avg_udp_bps) AS total_udp_bps,
					   sum(avg_icmp_bps) AS total_icmp_bps,
					   sum(avg_frag_bps) AS total_frag_bps
				FROM ts_stats_5min%s
				GROUP BY bucket
			) sub
			GROUP BY ts
			ORDER BY ts
			LIMIT %d`, where, limit)
	} else {
		// 5min — direct read, sum across child prefixes
		q = fmt.Sprintf(`
			SELECT bucket AS ts,
				   sum(avg_pps)::BIGINT AS pps,
				   sum(avg_bps)::BIGINT AS bps,
				   sum(avg_tcp_pps)::INT AS tcp_pps,
				   sum(avg_tcp_syn_pps)::INT AS tcp_syn_pps,
				   sum(avg_udp_pps)::INT AS udp_pps,
				   sum(avg_icmp_pps)::INT AS icmp_pps,
				   sum(avg_frag_pps)::INT AS frag_pps,
				   sum(avg_tcp_bps)::BIGINT AS tcp_bps,
				   sum(avg_udp_bps)::BIGINT AS udp_bps,
				   sum(avg_icmp_bps)::BIGINT AS icmp_bps,
				   sum(avg_frag_bps)::BIGINT AS frag_bps
			FROM ts_stats_5min%s
			GROUP BY bucket
			ORDER BY bucket
			LIMIT %d`, where, limit)
	}

	// CAGG path: no extra_decoder aggregates by design.
	return r.scanTimeseries(ctx, q, args, false)
}

// queryTimeseriesFromRaw queries the raw ts_stats table (used for 5s resolution or cagg fallback).
// For 5s resolution, each bucket has ~1 timestamp so simple GROUP BY is correct.
// For 5min/1h fallback, uses two-phase aggregation: inner sums per timestamp, outer averages per bucket.
func (r *statsRepo) queryTimeseriesFromRaw(ctx context.Context, filter store.TimeseriesFilter, limit int) ([]store.TimeseriesPoint, error) {
	bucket := "5 seconds"
	switch filter.Resolution {
	case "5min":
		bucket = "5 minutes"
	case "1h":
		bucket = "1 hour"
	}

	var conds []string
	var args []any
	argN := 1

	if !filter.From.IsZero() {
		conds = append(conds, fmt.Sprintf("time >= $%d", argN))
		args = append(args, filter.From)
		argN++
	}
	if !filter.To.IsZero() {
		conds = append(conds, fmt.Sprintf("time <= $%d", argN))
		args = append(args, filter.To)
		argN++
	}
	if filter.Prefix != "" {
		conds = append(conds, fmt.Sprintf("prefix <<= $%d::CIDR", argN))
		args = append(args, filter.Prefix)
		argN++
	}
	if filter.NodeID != "" {
		conds = append(conds, fmt.Sprintf("node_id = $%d", argN))
		args = append(args, filter.NodeID)
		argN++
	}
	conds = append(conds, "dst_ip IS NULL")

	// Direction filter: receives (default), sends, or both (no filter)
	dir := filter.Direction
	if dir == "" {
		dir = "receives"
	}
	if dir != "both" {
		conds = append(conds, fmt.Sprintf("direction = $%d", argN))
		args = append(args, dir)
		argN++
	}

	where := " WHERE " + strings.Join(conds, " AND ")

	var q string
	if filter.Resolution == "5s" {
		// 5s: one timestamp per bucket, simple GROUP BY is correct
		q = fmt.Sprintf(`
			SELECT time_bucket('5 seconds', time) AS bucket,
				   sum(pps)::BIGINT AS pps,
				   sum(bps)::BIGINT AS bps,
				   sum(tcp_pps)::INT AS tcp_pps,
				   sum(tcp_syn_pps)::INT AS tcp_syn_pps,
				   sum(udp_pps)::INT AS udp_pps,
				   sum(icmp_pps)::INT AS icmp_pps,
				   sum(frag_pps)::INT AS frag_pps,
				   sum(tcp_bps)::BIGINT AS tcp_bps,
				   sum(udp_bps)::BIGINT AS udp_bps,
				   sum(icmp_bps)::BIGINT AS icmp_bps,
				   sum(frag_bps)::BIGINT AS frag_bps
			FROM ts_stats%s
			GROUP BY bucket
			ORDER BY bucket
			LIMIT %d`, where, limit)
	} else {
		// 5min/1h fallback: two-phase aggregation
		q = fmt.Sprintf(`
			SELECT bucket,
				   avg(s_pps)::BIGINT AS pps,
				   avg(s_bps)::BIGINT AS bps,
				   avg(s_tcp)::INT AS tcp_pps,
				   avg(s_syn)::INT AS tcp_syn_pps,
				   avg(s_udp)::INT AS udp_pps,
				   avg(s_icmp)::INT AS icmp_pps,
				   avg(s_frag)::INT AS frag_pps,
				   avg(s_tcp_bps)::BIGINT AS tcp_bps,
				   avg(s_udp_bps)::BIGINT AS udp_bps,
				   avg(s_icmp_bps)::BIGINT AS icmp_bps,
				   avg(s_frag_bps)::BIGINT AS frag_bps
			FROM (
				SELECT time_bucket('%s', time) AS bucket,
					   time,
					   sum(pps) AS s_pps,
					   sum(bps) AS s_bps,
					   sum(tcp_pps) AS s_tcp,
					   sum(tcp_syn_pps) AS s_syn,
					   sum(udp_pps) AS s_udp,
					   sum(icmp_pps) AS s_icmp,
					   sum(frag_pps) AS s_frag,
					   sum(tcp_bps) AS s_tcp_bps,
					   sum(udp_bps) AS s_udp_bps,
					   sum(icmp_bps) AS s_icmp_bps,
					   sum(frag_bps) AS s_frag_bps
				FROM ts_stats%s
				GROUP BY bucket, time
			) sub
			GROUP BY bucket
			ORDER BY bucket
			LIMIT %d`, bucket, where, limit)
	}

	// Raw path: extra decoder JSONB not aggregated in chart queries.
	// Access to extras goes through dedicated single-row queries (QueryExtras*).
	return r.scanTimeseries(ctx, q, args, false)
}

// QueryTotalTimeseries returns aggregated time-series data across ALL prefixes.
// Uses the same cagg optimization as QueryTimeseries.
func (r *statsRepo) QueryTotalTimeseries(ctx context.Context, filter store.TimeseriesFilter) ([]store.TimeseriesPoint, error) {
	// Total = same as per-prefix but without prefix filter
	return r.QueryTimeseries(ctx, filter)
}

// clampLimit normalises the LIMIT value.
func clampLimit(v int) int {
	if v <= 0 {
		return 1000
	}
	if v > 10000 {
		return 10000
	}
	return v
}

// scanTimeseries executes the query and scans into TimeseriesPoint slice.
// withExtras controls whether the query returns extra_decoder_pps/bps JSONB columns
// at the end of SELECT; when false (current chart queries), only the 12 standard fields
// are scanned. JSONB scanning path reserved for future dedicated extras-access API.
func (r *statsRepo) scanTimeseries(ctx context.Context, q string, args []any, withExtras bool) ([]store.TimeseriesPoint, error) {
	rows, err := r.pool.Query(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var points []store.TimeseriesPoint
	for rows.Next() {
		var p store.TimeseriesPoint
		if withExtras {
			var extraPPSRaw, extraBPSRaw []byte
			if err := rows.Scan(
				&p.Time, &p.PPS, &p.BPS,
				&p.TCPPPS, &p.TCPSynPPS, &p.UDPPPS, &p.ICMPPPS, &p.FragPPS,
				&p.TCPBPS, &p.UDPBPS, &p.ICMPBPS, &p.FragBPS,
				&extraPPSRaw, &extraBPSRaw,
			); err != nil {
				return nil, err
			}
			if len(extraPPSRaw) > 0 {
				_ = json.Unmarshal(extraPPSRaw, &p.ExtraDecoderPPS)
			}
			if len(extraBPSRaw) > 0 {
				_ = json.Unmarshal(extraBPSRaw, &p.ExtraDecoderBPS)
			}
		} else {
			if err := rows.Scan(
				&p.Time, &p.PPS, &p.BPS,
				&p.TCPPPS, &p.TCPSynPPS, &p.UDPPPS, &p.ICMPPPS, &p.FragPPS,
				&p.TCPBPS, &p.UDPBPS, &p.ICMPBPS, &p.FragBPS,
			); err != nil {
				return nil, err
			}
		}
		points = append(points, p)
	}
	return points, rows.Err()
}

// QueryHourP95 computes P95 for a closed hour window [start, end).
// Returns per-(node_id, prefix) results. Used by dynamic detection profile engine.
func (r *statsRepo) QueryHourP95(ctx context.Context, start, end time.Time, minPoints int) ([]store.P95Result, error) {
	rows, err := r.pool.Query(ctx,
		`SELECT node_id, prefix::TEXT,
				percentile_disc(0.95) WITHIN GROUP (ORDER BY pps)::BIGINT AS p95_pps,
				percentile_disc(0.95) WITHIN GROUP (ORDER BY bps)::BIGINT AS p95_bps,
				count(*) AS data_points
		 FROM ts_stats
		 WHERE dst_ip IS NULL AND time >= $1 AND time < $2
		 GROUP BY node_id, prefix
		 HAVING count(*) >= $3`, start, end, minPoints)
	if err != nil {
		return nil, fmt.Errorf("query hour p95: %w", err)
	}
	defer rows.Close()
	return scanP95Results(rows)
}

// QueryWindowP95 computes P95 for a rolling window [end-duration, end).
// Returns per-(node_id, prefix) results. Used by baseline recommendation calculator.
func (r *statsRepo) QueryWindowP95(ctx context.Context, end time.Time, duration time.Duration, minPoints int) ([]store.P95Result, error) {
	start := end.Add(-duration)
	rows, err := r.pool.Query(ctx,
		`SELECT node_id, prefix::TEXT,
				percentile_disc(0.95) WITHIN GROUP (ORDER BY pps)::BIGINT AS p95_pps,
				percentile_disc(0.95) WITHIN GROUP (ORDER BY bps)::BIGINT AS p95_bps,
				count(*) AS data_points
		 FROM ts_stats
		 WHERE dst_ip IS NULL AND time >= $1 AND time < $2
		 GROUP BY node_id, prefix
		 HAVING count(*) >= $3`, start, end, minPoints)
	if err != nil {
		return nil, fmt.Errorf("query window p95: %w", err)
	}
	defer rows.Close()
	return scanP95Results(rows)
}

func scanP95Results(rows pgx.Rows) ([]store.P95Result, error) {
	var results []store.P95Result
	for rows.Next() {
		var r store.P95Result
		if err := rows.Scan(&r.NodeID, &r.Prefix, &r.P95PPS, &r.P95BPS, &r.DataPoints); err != nil {
			return nil, err
		}
		results = append(results, r)
	}
	return results, rows.Err()
}
