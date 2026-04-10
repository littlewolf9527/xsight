#!/usr/bin/env bash
# xSight Node — Service Manager
# Usage: sudo ./scripts/node.sh {start|stop|restart|status|logs}
#
# Expects node/config.yaml to exist. Copy node/config.example.yaml to get started.
# Must be run as root (XDP requires CAP_NET_ADMIN + CAP_BPF).

set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BOLD='\033[1m'; NC='\033[0m'
info()  { echo -e "${GREEN}[node]${NC} $*"; }
warn()  { echo -e "${YELLOW}[node]${NC} $*"; }
die()   { echo -e "${RED}[node] ERROR:${NC} $*" >&2; exit 1; }

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
NODE_DIR="${NODE_DIR:-$ROOT/node}"
NODE_BIN="$NODE_DIR/bin/xsight-node"
CONFIG="$NODE_DIR/config.yaml"
LOG_FILE="/tmp/xsight-node.log"

check_root() {
    [[ $EUID -eq 0 ]] || die "Must be run as root (XDP requires CAP_NET_ADMIN + CAP_BPF)"
}

is_running() {
    pgrep -f "xsight-node" &>/dev/null
}

do_start() {
    check_root
    [[ -f "$NODE_BIN" ]] || die "Binary not found: $NODE_BIN — run ./scripts/build-node.sh first"
    [[ -f "$CONFIG"   ]] || die "Config not found: $CONFIG — copy config.example.yaml and edit it"

    if is_running; then
        warn "Node already running (PID $(pgrep -f xsight-node))"
        return 0
    fi

    info "Starting xSight node..."
    # Start from NODE_DIR so relative paths resolve correctly
    cd "$NODE_DIR"
    nohup "$NODE_BIN" -config "$CONFIG" >"$LOG_FILE" 2>&1 &
    sleep 2

    if is_running; then
        info "Node started (PID $(pgrep -f xsight-node))"
        info "Logs: $LOG_FILE"
    else
        die "Node failed to start — check $LOG_FILE\n$(tail -20 "$LOG_FILE" 2>/dev/null)"
    fi
}

do_stop() {
    check_root
    if is_running; then
        info "Stopping node (PID $(pgrep -f xsight-node))..."
        pkill -f "xsight-node" || true
        sleep 1
        is_running && pkill -9 -f "xsight-node" || true
        info "Stopped"
    else
        warn "Node is not running"
    fi
}

do_status() {
    echo ""
    echo -e "${BOLD}=== xSight Node Status ===${NC}"
    echo ""

    if is_running; then
        echo -e "  Process : ${GREEN}running${NC} (PID $(pgrep -f xsight-node))"
    else
        echo -e "  Process : ${RED}stopped${NC}"
        echo ""
        return 0
    fi

    # Show node_id and mode from config
    NODE_ID=$(grep 'node_id' "$CONFIG" 2>/dev/null | head -1 | awk '{print $2}' | tr -d '"' || echo "-")
    MODE=$(grep 'mode' "$CONFIG" 2>/dev/null | head -1 | awk '{print $2}' | tr -d '"' || echo "-")
    echo -e "  Node ID : $NODE_ID"
    echo -e "  Mode    : $MODE"

    echo ""
}

do_logs() {
    [[ -f "$LOG_FILE" ]] || die "Log file not found: $LOG_FILE"
    tail -f "$LOG_FILE"
}

CMD="${1:-}"
case "$CMD" in
    start)   do_start ;;
    stop)    do_stop ;;
    restart) do_stop; sleep 1; do_start ;;
    status)  do_status ;;
    logs)    do_logs ;;
    *)
        echo "Usage: sudo $0 {start|stop|restart|status|logs}"
        echo ""
        echo "  start    Start node agent (requires root)"
        echo "  stop     Stop node agent (requires root)"
        echo "  restart  Stop then start"
        echo "  status   Show process and node info"
        echo "  logs     Tail live log output"
        echo ""
        echo "Environment:"
        echo "  NODE_DIR  Node directory (default: ./node)"
        exit 1
        ;;
esac
