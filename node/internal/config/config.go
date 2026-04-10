// Package config defines the Node configuration structure.
package config

import (
	"fmt"
	"log"
	"net"
	"os"
	"runtime"

	"gopkg.in/yaml.v3"
)

// Config is the top-level Node configuration.
type Config struct {
	Mode         string      `yaml:"mode"`    // "xdp" (default) | "flow" — v3.0
	NodeID       string      `yaml:"node_id"`
	Interfaces   []Interface `yaml:"interfaces"`
	BPF          BPFConfig   `yaml:"bpf"`
	Controller   CtrlConfig  `yaml:"controller"`
	Auth         AuthConfig  `yaml:"auth"`
	ParseWorkers int         `yaml:"parse_workers"` // parallel parse workers, default = NumCPU/2, min 1, max 16
	Pprof        bool        `yaml:"pprof"`         // enable pprof debug server on 127.0.0.1:6061 (default false)
}

// Interface defines a single mirror/ERSPAN interface to monitor.
type Interface struct {
	Name               string `yaml:"name"`
	Mode               string `yaml:"mode"`                 // "mirror" | "erspan"
	UpstreamSampleRate uint32 `yaml:"upstream_sample_rate"`  // 1=passthrough, 300=upstream 1:300
	SampleBytes        uint32 `yaml:"sample_bytes"`          // 128-512, default 256
}

// BPFConfig holds BPF-related settings.
type BPFConfig struct {
	Path       string `yaml:"path"`        // path to BPF ELF (only used with manual load)
	MaxEntries uint32 `yaml:"max_entries"` // ip_stats map size, default 1000000
}

// CtrlConfig holds Controller connection settings.
type CtrlConfig struct {
	Address string `yaml:"address"` // "controller:50051"
}

// AuthConfig holds authentication settings.
type AuthConfig struct {
	NodeAPIKey string `yaml:"node_api_key"` // API key for gRPC handshake
}

// Load reads and parses a config.yaml file.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}

	cfg := &Config{}
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}

	if err := cfg.validate(); err != nil {
		return nil, fmt.Errorf("validate config: %w", err)
	}

	return cfg, nil
}

func (c *Config) validate() error {
	if c.NodeID == "" {
		return fmt.Errorf("node_id is required")
	}

	// Default mode to xdp for backward compatibility
	if c.Mode == "" {
		c.Mode = "xdp"
	}
	if c.Mode != "xdp" && c.Mode != "flow" {
		return fmt.Errorf("mode must be 'xdp' or 'flow', got %q", c.Mode)
	}

	// Mode-specific validation
	if c.Mode == "xdp" {
		if len(c.Interfaces) == 0 {
			return fmt.Errorf("at least one interface is required in xdp mode")
		}
		for i, iface := range c.Interfaces {
			if iface.Name == "" {
				return fmt.Errorf("interfaces[%d].name is required", i)
			}
			if iface.Mode != "mirror" && iface.Mode != "erspan" {
				return fmt.Errorf("interfaces[%d].mode must be 'mirror' or 'erspan', got %q", i, iface.Mode)
			}
			if iface.UpstreamSampleRate == 0 {
				c.Interfaces[i].UpstreamSampleRate = 1
			}
			if iface.SampleBytes == 0 {
				c.Interfaces[i].SampleBytes = 256
			}
			if iface.SampleBytes < 128 || iface.SampleBytes > 512 {
				return fmt.Errorf("interfaces[%d].sample_bytes must be 128-512, got %d", i, iface.SampleBytes)
			}
		}
		if c.BPF.MaxEntries == 0 {
			c.BPF.MaxEntries = 1000000
		}
		if c.ParseWorkers == 0 {
			c.ParseWorkers = runtime.NumCPU() / 2
			if c.ParseWorkers < 1 {
				c.ParseWorkers = 1
			}
		}
		if c.ParseWorkers < 1 || c.ParseWorkers > 16 {
			return fmt.Errorf("parse_workers must be 1-16, got %d", c.ParseWorkers)
		}
		// Warn if a configured mirror/ERSPAN interface shares a subnet with
		// a management IP (SSH/gRPC traffic would be XDP_DROP'd).
		warnManagementConflict(c.Interfaces)
	}
	// flow mode: interfaces/BPF/parse_workers not required (config comes from Controller)

	if c.Controller.Address == "" {
		return fmt.Errorf("controller.address is required")
	}
	if c.Auth.NodeAPIKey == "" {
		return fmt.Errorf("auth.node_api_key is required")
	}

	return nil
}

// IsFlowMode returns true if this node is configured for flow collection mode.
func (c *Config) IsFlowMode() bool {
	return c.Mode == "flow"
}

// warnManagementConflict checks if any configured mirror interface has an IP
// in the same subnet as another interface on the machine (likely management).
func warnManagementConflict(ifaces []Interface) {
	// Collect all local IPs with their subnets
	type localAddr struct {
		iface string
		net   *net.IPNet
	}
	var mgmtAddrs []localAddr

	netIfaces, err := net.Interfaces()
	if err != nil {
		return
	}
	for _, ni := range netIfaces {
		if ni.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, _ := ni.Addrs()
		for _, a := range addrs {
			if ipnet, ok := a.(*net.IPNet); ok {
				// Skip IPv6 link-local (fe80::/10) — all interfaces share this
				// prefix, generating false positive warnings.
				if ipnet.IP.IsLinkLocalUnicast() {
					continue
				}
				mgmtAddrs = append(mgmtAddrs, localAddr{iface: ni.Name, net: ipnet})
			}
		}
	}

	// For each configured mirror interface, check if it has an IP that
	// overlaps with another interface's subnet
	for _, mi := range ifaces {
		for _, ma := range mgmtAddrs {
			if ma.iface == mi.Name {
				continue // same interface, skip
			}
			// Check if the mirror interface has an IP in the mgmt subnet
			mirrorIface, err := net.InterfaceByName(mi.Name)
			if err != nil {
				continue
			}
			mirrorAddrs, _ := mirrorIface.Addrs()
			for _, a := range mirrorAddrs {
				if ipnet, ok := a.(*net.IPNet); ok {
					if ma.net.Contains(ipnet.IP) || ipnet.Contains(ma.net.IP) {
						log.Printf("WARNING: mirror interface %s (%s) shares subnet with management interface %s (%s) — XDP will DROP management traffic on %s!",
							mi.Name, ipnet.IP, ma.iface, ma.net.IP, mi.Name)
					}
				}
			}
		}
	}
}
