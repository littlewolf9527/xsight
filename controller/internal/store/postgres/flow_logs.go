package postgres

import (
	"context"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/littlewolf9527/xsight/controller/internal/store"
)

type flowLogRepo struct{ pool *pgxpool.Pool }

// BulkInsert writes flow log entries using pgx.CopyFrom for maximum throughput.
func (r *flowLogRepo) BulkInsert(ctx context.Context, flows []store.FlowLog) error {
	if len(flows) == 0 {
		return nil
	}

	columns := []string{
		"time", "node_id", "prefix", "src_ip", "dst_ip",
		"src_port", "dst_port", "protocol", "tcp_flags",
		"packets", "bytes",
	}

	rows := make([][]any, len(flows))
	for i, f := range flows {
		rows[i] = []any{
			f.Time, f.NodeID, f.Prefix, f.SrcIP, f.DstIP,
			f.SrcPort, f.DstPort, f.Protocol, f.TCPFlags,
			f.Packets, f.Bytes,
		}
	}

	_, err := r.pool.CopyFrom(ctx,
		pgx.Identifier{"flow_logs"},
		columns,
		pgx.CopyFromRows(rows),
	)
	return err
}

// QueryByDstIP returns flow logs matching a destination IP within a time window,
// sorted by packets descending.
func (r *flowLogRepo) QueryByDstIP(ctx context.Context, filter store.FlowLogFilter) ([]store.FlowLog, error) {
	var conds []string
	var args []any
	argN := 1

	if filter.DstIP != "" {
		// Support both exact IP and subnet match:
		// attack dst_ip can be "1.2.3.0/24" (subnet) or "1.2.3.4" (single IP)
		if strings.Contains(filter.DstIP, "/") {
			conds = append(conds, fmt.Sprintf("dst_ip <<= $%d::CIDR", argN))
		} else {
			conds = append(conds, fmt.Sprintf("dst_ip = $%d::INET", argN))
		}
		args = append(args, filter.DstIP)
		argN++
	}

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

	where := ""
	if len(conds) > 0 {
		where = " WHERE " + strings.Join(conds, " AND ")
	}

	limit := 1000
	if filter.Limit > 0 {
		limit = filter.Limit
	}
	if limit > 10000 {
		limit = 10000
	}

	q := fmt.Sprintf(`SELECT time, node_id, prefix::TEXT, src_ip::TEXT, dst_ip::TEXT,
		src_port, dst_port, protocol, tcp_flags, packets, bytes
		FROM flow_logs%s
		ORDER BY packets DESC
		LIMIT %d`, where, limit)

	rows, err := r.pool.Query(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var result []store.FlowLog
	for rows.Next() {
		var f store.FlowLog
		if err := rows.Scan(
			&f.Time, &f.NodeID, &f.Prefix, &f.SrcIP, &f.DstIP,
			&f.SrcPort, &f.DstPort, &f.Protocol, &f.TCPFlags,
			&f.Packets, &f.Bytes,
		); err != nil {
			return nil, err
		}
		result = append(result, f)
	}
	return result, rows.Err()
}

// QueryBySrcIP queries flow_logs by source IP for outbound attack sensor logs.
func (r *flowLogRepo) QueryBySrcIP(ctx context.Context, filter store.FlowLogFilter) ([]store.FlowLog, error) {
	var conds []string
	var args []any
	argN := 1

	if filter.DstIP != "" {
		// For outbound attacks, DstIP in the attack record is actually the internal src IP
		if strings.Contains(filter.DstIP, "/") {
			conds = append(conds, fmt.Sprintf("src_ip <<= $%d::CIDR", argN))
		} else {
			conds = append(conds, fmt.Sprintf("src_ip = $%d::INET", argN))
		}
		args = append(args, filter.DstIP)
		argN++
	}

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

	where := ""
	if len(conds) > 0 {
		where = " WHERE " + strings.Join(conds, " AND ")
	}

	limit := 1000
	if filter.Limit > 0 {
		limit = filter.Limit
	}
	if limit > 10000 {
		limit = 10000
	}

	q := fmt.Sprintf(`SELECT time, node_id, prefix::TEXT, src_ip::TEXT, dst_ip::TEXT,
		src_port, dst_port, protocol, tcp_flags, packets, bytes
		FROM flow_logs%s
		ORDER BY packets DESC
		LIMIT %d`, where, limit)

	rows, err := r.pool.Query(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var result []store.FlowLog
	for rows.Next() {
		var f store.FlowLog
		if err := rows.Scan(
			&f.Time, &f.NodeID, &f.Prefix, &f.SrcIP, &f.DstIP,
			&f.SrcPort, &f.DstPort, &f.Protocol, &f.TCPFlags,
			&f.Packets, &f.Bytes,
		); err != nil {
			return nil, err
		}
		result = append(result, f)
	}
	return result, rows.Err()
}
