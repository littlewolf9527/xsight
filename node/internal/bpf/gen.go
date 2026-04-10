// Package bpf contains generated BPF bindings via bpf2go.
//
// Run `go generate ./internal/bpf/` to regenerate after modifying bpf/xsight.c.
// Requires: Linux + clang + llvm-strip + bpftool (run on build server, not Mac).
//
// Generated files (xsight_bpfel.go, xsight_bpfel.o, etc.) are NOT checked into
// the repository. They must be generated on the Linux build server before
// `go build` will succeed. See Makefile targets: `make generate build`.
package bpf

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall -Werror" -target amd64 xsight ../../bpf/xsight.c
