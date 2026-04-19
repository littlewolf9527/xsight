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
	// CAGG v6 (v1.3.2) includes frag_pps/bps + 9 extra decoder aggregates (tcp_ack/rst/fin,
	// gre/esp/igmp/ip_other, bad_fragment/invalid). When filter.IncludeExtras is true the
	// query pack those into a JSONB output column matching the raw path's shape.
	//
	// Extras pack as JSONB at SELECT time so scanTimeseries can use one scan path regardless
	// of whether data came from raw ts_stats or CAGG.
	extraPPSSQL := `'{}'::jsonb`
	extraBPSSQL := `'{}'::jsonb`
	if filter.IncludeExtras {
		if filter.Resolution == "1h" {
			extraPPSSQL = `jsonb_strip_nulls(jsonb_build_object(
				'tcp_ack',      NULLIF(avg(total_tcp_ack_pps)::INT,      0),
				'tcp_rst',      NULLIF(avg(total_tcp_rst_pps)::INT,      0),
				'tcp_fin',      NULLIF(avg(total_tcp_fin_pps)::INT,      0),
				'gre',          NULLIF(avg(total_gre_pps)::INT,          0),
				'esp',          NULLIF(avg(total_esp_pps)::INT,          0),
				'igmp',         NULLIF(avg(total_igmp_pps)::INT,         0),
				'ip_other',     NULLIF(avg(total_ip_other_pps)::INT,     0),
				'bad_fragment', NULLIF(avg(total_bad_fragment_pps)::INT, 0),
				'invalid',      NULLIF(avg(total_invalid_pps)::INT,      0)
			))`
			extraBPSSQL = `jsonb_strip_nulls(jsonb_build_object(
				'tcp_ack',      NULLIF(avg(total_tcp_ack_bps)::BIGINT,      0),
				'tcp_rst',      NULLIF(avg(total_tcp_rst_bps)::BIGINT,      0),
				'tcp_fin',      NULLIF(avg(total_tcp_fin_bps)::BIGINT,      0),
				'gre',          NULLIF(avg(total_gre_bps)::BIGINT,          0),
				'esp',          NULLIF(avg(total_esp_bps)::BIGINT,          0),
				'igmp',         NULLIF(avg(total_igmp_bps)::BIGINT,         0),
				'ip_other',     NULLIF(avg(total_ip_other_bps)::BIGINT,     0),
				'bad_fragment', NULLIF(avg(total_bad_fragment_bps)::BIGINT, 0),
				'invalid',      NULLIF(avg(total_invalid_bps)::BIGINT,      0)
			))`
		} else {
			extraPPSSQL = `jsonb_strip_nulls(jsonb_build_object(
				'tcp_ack',      NULLIF(sum(avg_tcp_ack_pps)::INT,      0),
				'tcp_rst',      NULLIF(sum(avg_tcp_rst_pps)::INT,      0),
				'tcp_fin',      NULLIF(sum(avg_tcp_fin_pps)::INT,      0),
				'gre',          NULLIF(sum(avg_gre_pps)::INT,          0),
				'esp',          NULLIF(sum(avg_esp_pps)::INT,          0),
				'igmp',         NULLIF(sum(avg_igmp_pps)::INT,         0),
				'ip_other',     NULLIF(sum(avg_ip_other_pps)::INT,     0),
				'bad_fragment', NULLIF(sum(avg_bad_fragment_pps)::INT, 0),
				'invalid',      NULLIF(sum(avg_invalid_pps)::INT,      0)
			))`
			extraBPSSQL = `jsonb_strip_nulls(jsonb_build_object(
				'tcp_ack',      NULLIF(sum(avg_tcp_ack_bps)::BIGINT,      0),
				'tcp_rst',      NULLIF(sum(avg_tcp_rst_bps)::BIGINT,      0),
				'tcp_fin',      NULLIF(sum(avg_tcp_fin_bps)::BIGINT,      0),
				'gre',          NULLIF(sum(avg_gre_bps)::BIGINT,          0),
				'esp',          NULLIF(sum(avg_esp_bps)::BIGINT,          0),
				'igmp',         NULLIF(sum(avg_igmp_bps)::BIGINT,         0),
				'ip_other',     NULLIF(sum(avg_ip_other_bps)::BIGINT,     0),
				'bad_fragment', NULLIF(sum(avg_bad_fragment_bps)::BIGINT, 0),
				'invalid',      NULLIF(sum(avg_invalid_bps)::BIGINT,      0)
			))`
		}
	}

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
				   avg(total_frag_bps)::BIGINT AS frag_bps,
				   %s AS extra_decoder_pps,
				   %s AS extra_decoder_bps
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
					   sum(avg_frag_bps) AS total_frag_bps,
					   sum(avg_tcp_ack_pps)      AS total_tcp_ack_pps,
					   sum(avg_tcp_rst_pps)      AS total_tcp_rst_pps,
					   sum(avg_tcp_fin_pps)      AS total_tcp_fin_pps,
					   sum(avg_gre_pps)          AS total_gre_pps,
					   sum(avg_esp_pps)          AS total_esp_pps,
					   sum(avg_igmp_pps)         AS total_igmp_pps,
					   sum(avg_ip_other_pps)     AS total_ip_other_pps,
					   sum(avg_bad_fragment_pps) AS total_bad_fragment_pps,
					   sum(avg_invalid_pps)      AS total_invalid_pps,
					   sum(avg_tcp_ack_bps)      AS total_tcp_ack_bps,
					   sum(avg_tcp_rst_bps)      AS total_tcp_rst_bps,
					   sum(avg_tcp_fin_bps)      AS total_tcp_fin_bps,
					   sum(avg_gre_bps)          AS total_gre_bps,
					   sum(avg_esp_bps)          AS total_esp_bps,
					   sum(avg_igmp_bps)         AS total_igmp_bps,
					   sum(avg_ip_other_bps)     AS total_ip_other_bps,
					   sum(avg_bad_fragment_bps) AS total_bad_fragment_bps,
					   sum(avg_invalid_bps)      AS total_invalid_bps
				FROM ts_stats_5min%s
				GROUP BY bucket
			) sub
			GROUP BY ts
			ORDER BY ts
			LIMIT %d`, extraPPSSQL, extraBPSSQL, where, limit)
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
				   sum(avg_frag_bps)::BIGINT AS frag_bps,
				   %s AS extra_decoder_pps,
				   %s AS extra_decoder_bps
			FROM ts_stats_5min%s
			GROUP BY bucket
			ORDER BY bucket
			LIMIT %d`, extraPPSSQL, extraBPSSQL, where, limit)
	}

	return r.scanTimeseries(ctx, q, args, filter.IncludeExtras)
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

	// Extras: merge per-row JSONB maps across all source rows in a bucket.
	// Uses `jsonb_object_agg` over (key, sum-or-avg) pairs derived from the JSONB columns.
	// For 5s: each bucket is ~1 row already; for 5min/1h we inner-sum per timestamp then
	// outer-aggregate per bucket. Keeping the math simple: we just pick the max value per
	// (bucket, decoder_name) across the small number of rows in that bucket — good enough
	// for chart visualization and correctly handles the "some rows have the key, some don't"
	// mixed-source case without introducing NULL biases into avg.
	extrasSelectCols := ""
	if filter.IncludeExtras {
		extrasSelectCols = `, merge_extras(extra_decoder_pps) AS extra_decoder_pps,
		       merge_extras(extra_decoder_bps) AS extra_decoder_bps`
		_ = extrasSelectCols // placeholder; implemented below per-resolution
	}

	var q string
	if filter.Resolution == "5s" {
		// 5s: one timestamp per bucket, simple GROUP BY is correct
		extras := ""
		if filter.IncludeExtras {
			// Single row per bucket in typical case, but across prefix children use
			// `jsonb_object_agg` on each key's SUM.
			extras = `,
				   (SELECT jsonb_object_agg(k, v) FROM (
				       SELECT k, sum((val)::int)::int AS v
				       FROM jsonb_each_text(coalesce(jsonb_agg_extras_pps.obj,'{}'::jsonb)) AS kv(k, val)
				       GROUP BY k
				   ) t) AS extra_decoder_pps`
			_ = extras // inline impl too complex; switch to a simpler approach below
		}
		if filter.IncludeExtras {
			// Simpler: use jsonb_object_agg over (k, sum(v)) via LATERAL unnest.
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
					   sum(frag_bps)::BIGINT AS frag_bps,
					   jsonb_strip_nulls(jsonb_build_object(
					       'tcp_ack',      NULLIF(sum((extra_decoder_pps->>'tcp_ack')::int),      0),
					       'tcp_rst',      NULLIF(sum((extra_decoder_pps->>'tcp_rst')::int),      0),
					       'tcp_fin',      NULLIF(sum((extra_decoder_pps->>'tcp_fin')::int),      0),
					       'gre',          NULLIF(sum((extra_decoder_pps->>'gre')::int),          0),
					       'esp',          NULLIF(sum((extra_decoder_pps->>'esp')::int),          0),
					       'igmp',         NULLIF(sum((extra_decoder_pps->>'igmp')::int),         0),
					       'ip_other',     NULLIF(sum((extra_decoder_pps->>'ip_other')::int),     0),
					       'bad_fragment', NULLIF(sum((extra_decoder_pps->>'bad_fragment')::int), 0),
					       'invalid',      NULLIF(sum((extra_decoder_pps->>'invalid')::int),      0)
					   )) AS extra_decoder_pps,
					   jsonb_strip_nulls(jsonb_build_object(
					       'tcp_ack',      NULLIF(sum((extra_decoder_bps->>'tcp_ack')::bigint),      0),
					       'tcp_rst',      NULLIF(sum((extra_decoder_bps->>'tcp_rst')::bigint),      0),
					       'tcp_fin',      NULLIF(sum((extra_decoder_bps->>'tcp_fin')::bigint),      0),
					       'gre',          NULLIF(sum((extra_decoder_bps->>'gre')::bigint),          0),
					       'esp',          NULLIF(sum((extra_decoder_bps->>'esp')::bigint),          0),
					       'igmp',         NULLIF(sum((extra_decoder_bps->>'igmp')::bigint),         0),
					       'ip_other',     NULLIF(sum((extra_decoder_bps->>'ip_other')::bigint),     0),
					       'bad_fragment', NULLIF(sum((extra_decoder_bps->>'bad_fragment')::bigint), 0),
					       'invalid',      NULLIF(sum((extra_decoder_bps->>'invalid')::bigint),      0)
					   )) AS extra_decoder_bps
				FROM ts_stats%s
				GROUP BY bucket
				ORDER BY bucket
				LIMIT %d`, where, limit)
		} else {
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
		}
	} else {
		// 5min/1h fallback: two-phase aggregation. Extras follow the same pattern.
		if filter.IncludeExtras {
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
					   avg(s_frag_bps)::BIGINT AS frag_bps,
					   jsonb_strip_nulls(jsonb_build_object(
					       'tcp_ack',      NULLIF(avg(s_tcp_ack)::INT,      0),
					       'tcp_rst',      NULLIF(avg(s_tcp_rst)::INT,      0),
					       'tcp_fin',      NULLIF(avg(s_tcp_fin)::INT,      0),
					       'gre',          NULLIF(avg(s_gre)::INT,          0),
					       'esp',          NULLIF(avg(s_esp)::INT,          0),
					       'igmp',         NULLIF(avg(s_igmp)::INT,         0),
					       'ip_other',     NULLIF(avg(s_ip_other)::INT,     0),
					       'bad_fragment', NULLIF(avg(s_bad_fragment)::INT, 0),
					       'invalid',      NULLIF(avg(s_invalid)::INT,      0)
					   )) AS extra_decoder_pps,
					   jsonb_strip_nulls(jsonb_build_object(
					       'tcp_ack',      NULLIF(avg(s_tcp_ack_b)::BIGINT,      0),
					       'tcp_rst',      NULLIF(avg(s_tcp_rst_b)::BIGINT,      0),
					       'tcp_fin',      NULLIF(avg(s_tcp_fin_b)::BIGINT,      0),
					       'gre',          NULLIF(avg(s_gre_b)::BIGINT,          0),
					       'esp',          NULLIF(avg(s_esp_b)::BIGINT,          0),
					       'igmp',         NULLIF(avg(s_igmp_b)::BIGINT,         0),
					       'ip_other',     NULLIF(avg(s_ip_other_b)::BIGINT,     0),
					       'bad_fragment', NULLIF(avg(s_bad_fragment_b)::BIGINT, 0),
					       'invalid',      NULLIF(avg(s_invalid_b)::BIGINT,      0)
					   )) AS extra_decoder_bps
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
						   sum(frag_bps) AS s_frag_bps,
						   sum(COALESCE((extra_decoder_pps->>'tcp_ack')::int, 0))      AS s_tcp_ack,
						   sum(COALESCE((extra_decoder_pps->>'tcp_rst')::int, 0))      AS s_tcp_rst,
						   sum(COALESCE((extra_decoder_pps->>'tcp_fin')::int, 0))      AS s_tcp_fin,
						   sum(COALESCE((extra_decoder_pps->>'gre')::int, 0))          AS s_gre,
						   sum(COALESCE((extra_decoder_pps->>'esp')::int, 0))          AS s_esp,
						   sum(COALESCE((extra_decoder_pps->>'igmp')::int, 0))         AS s_igmp,
						   sum(COALESCE((extra_decoder_pps->>'ip_other')::int, 0))     AS s_ip_other,
						   sum(COALESCE((extra_decoder_pps->>'bad_fragment')::int, 0)) AS s_bad_fragment,
						   sum(COALESCE((extra_decoder_pps->>'invalid')::int, 0))      AS s_invalid,
						   sum(COALESCE((extra_decoder_bps->>'tcp_ack')::bigint, 0))      AS s_tcp_ack_b,
						   sum(COALESCE((extra_decoder_bps->>'tcp_rst')::bigint, 0))      AS s_tcp_rst_b,
						   sum(COALESCE((extra_decoder_bps->>'tcp_fin')::bigint, 0))      AS s_tcp_fin_b,
						   sum(COALESCE((extra_decoder_bps->>'gre')::bigint, 0))          AS s_gre_b,
						   sum(COALESCE((extra_decoder_bps->>'esp')::bigint, 0))          AS s_esp_b,
						   sum(COALESCE((extra_decoder_bps->>'igmp')::bigint, 0))         AS s_igmp_b,
						   sum(COALESCE((extra_decoder_bps->>'ip_other')::bigint, 0))     AS s_ip_other_b,
						   sum(COALESCE((extra_decoder_bps->>'bad_fragment')::bigint, 0)) AS s_bad_fragment_b,
						   sum(COALESCE((extra_decoder_bps->>'invalid')::bigint, 0))      AS s_invalid_b
					FROM ts_stats%s
					GROUP BY bucket, time
				) sub
				GROUP BY bucket
				ORDER BY bucket
				LIMIT %d`, bucket, where, limit)
		} else {
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
	}

	return r.scanTimeseries(ctx, q, args, filter.IncludeExtras)
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
