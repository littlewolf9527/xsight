//go:build !linux

// This file provides stub types so that `go build` on non-Linux platforms
// produces a clear runtime error instead of cryptic "undefined: xsightObjects".
//
// xsight-node requires Linux with BPF support. The bpf2go generated bindings
// (xsight_bpfel.go, xsight_bpfel.o) are only produced on Linux via:
//
//	cd xsight/node && make generate build
//
// See internal/bpf/gen.go for the go:generate directive.
package bpf

import "github.com/cilium/ebpf"

// stubObjects mirrors the bpf2go-generated xsightObjects so that callers
// (e.g. main.go accessing mgr.Objs.Samples) compile on non-Linux.
type stubObjects struct {
	Samples            *ebpf.Map
	XsightMain         *ebpf.Program
	GlobalStats        *ebpf.Map
	WatchTrieA         *ebpf.Map
	WatchTrieB         *ebpf.Map
	IpStatsA           *ebpf.Map
	IpStatsB           *ebpf.Map
	SrcStatsA          *ebpf.Map
	SrcStatsB          *ebpf.Map
	ActiveSlot         *ebpf.Map
	PrefixStatsMap     *ebpf.Map
	SrcPrefixStatsMap  *ebpf.Map
	XsightConfig       *ebpf.Map
}

func (s *stubObjects) Close() error { return nil }

// Manager holds the loaded BPF collection and all XDP attachments.
// On non-Linux platforms, Load() returns ErrNotLinux.
type Manager struct {
	Objs        *stubObjects
	Attachments []XDPAttachment
	PinPath     string
	Recovered   bool
}

// XDPAttachment is a stub on non-Linux.
type XDPAttachment struct {
	Iface   string
	PinPath string
}

const errMsg = "xsight-node requires Linux with BPF support; build with: make generate build (on Linux)"

type notLinuxError struct{}

func (notLinuxError) Error() string { return errMsg }

// ErrNotLinux is returned by all BPF operations on non-Linux platforms.
var ErrNotLinux error = notLinuxError{}

func Load(ifaceName string, maxEntries uint32) (*Manager, error)          { return nil, ErrNotLinux }
func (m *Manager) AttachXDP(ifaceName string) error                       { return ErrNotLinux }
func (m *Manager) PopulateTrie(prefixes []PrefixEntry) error              { return ErrNotLinux }
func (m *Manager) Close()                                                 {}
func (m *Manager) Unload()                                                {}
func (m *Manager) SetConfig(index uint32, value uint64) error             { return ErrNotLinux }
func (m *Manager) ApplyInterfaceConfig(mode string, sb, ur uint32) error  { return ErrNotLinux }
func (m *Manager) GlobalStats() (*GlobalStats, error)                     { return nil, ErrNotLinux }
func (m *Manager) ReadActiveSlot() (uint32, error)                        { return 0, ErrNotLinux }
func (m *Manager) IterIPStats() (*ebpf.MapIterator, error)                { return nil, ErrNotLinux }
func (m *Manager) BatchReadIPStats() (map[LPMKey]DstIPStats, error)       { return nil, ErrNotLinux }
func (m *Manager) IterPrefixStats() *ebpf.MapIterator                     { return nil }
func (m *Manager) IterSrcPrefixStats() *ebpf.MapIterator                  { return nil }
func (m *Manager) BatchReadSrcIPStats() (map[LPMKey]DstIPStats, error)    { return nil, ErrNotLinux }
func (m *Manager) SetSampleRate(rate uint32) error                        { return ErrNotLinux }
func (m *Manager) HotSwap(prefixes []PrefixEntry) error                   { return ErrNotLinux }
