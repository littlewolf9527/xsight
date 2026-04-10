#!/usr/bin/env bash
# xSight Node — Build Script
# Usage: ./scripts/build-node.sh [bpf|agent|all]
#
#   bpf    Generate BPF objects via go generate (requires clang, Linux)
#   agent  Build Go node binary
#   all    Build BPF then agent (default)
#
# Must be run on a Linux host with clang and Go installed.

set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BOLD='\033[1m'; NC='\033[0m'
info()  { echo -e "${GREEN}[build-node]${NC} $*"; }
warn()  { echo -e "${YELLOW}[build-node]${NC} $*"; }
die()   { echo -e "${RED}[build-node] ERROR:${NC} $*" >&2; exit 1; }

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
NODE_DIR="$ROOT/node"
BPF_DIR="$NODE_DIR/internal/bpf"
BIN_DIR="$NODE_DIR/bin"
NODE_BIN="$BIN_DIR/xsight-node"
BPF_OBJ="$BPF_DIR/xsight_x86_bpfel.o"

build_bpf() {
    info "Generating BPF objects via go generate..."
    command -v clang &>/dev/null || die "clang not found. Install with: apt install clang"
    [[ "$(uname)" == "Linux" ]] || die "BPF generation requires Linux (detected: $(uname))"
    (cd "$NODE_DIR" && go generate ./internal/bpf/)
    [[ -f "$BPF_OBJ" ]] || die "BPF generation failed — $BPF_OBJ not found"
    info "BPF generate OK -> $BPF_OBJ"
}

build_agent() {
    info "Compiling Go node agent..."
    command -v go &>/dev/null || die "go not found. Install from https://go.dev/dl/"
    mkdir -p "$BIN_DIR"
    (cd "$NODE_DIR" && go build -buildvcs=false -trimpath -o "$NODE_BIN" .)
    [[ -f "$NODE_BIN" ]] || die "Node compile failed"
    info "Node build OK -> $NODE_BIN"
}

CMD="${1:-all}"
case "$CMD" in
    bpf)   build_bpf ;;
    agent) build_agent ;;
    all)   build_bpf; build_agent ;;
    *) die "Unknown command '$CMD'. Usage: $0 [bpf|agent|all]" ;;
esac

echo -e "\n${BOLD}${GREEN}=== Node build complete ===${NC}"
