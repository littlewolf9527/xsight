package flow

import (
	"testing"
)

func TestSourceResolveSampleRateForce(t *testing.T) {
	s := &Source{SampleMode: "force", SampleRate: 2000}
	if r := s.ResolveSampleRate(500); r != 2000 {
		t.Errorf("force mode: expected 2000, got %d", r)
	}
}

func TestSourceResolveSampleRateAuto(t *testing.T) {
	s := &Source{SampleMode: "auto"}
	if r := s.ResolveSampleRate(500); r != 500 {
		t.Errorf("auto mode with record rate: expected 500, got %d", r)
	}
	if r := s.ResolveSampleRate(0); r != 1 {
		t.Errorf("auto mode without record rate: expected 1, got %d", r)
	}
}

func TestSourceResolveSampleRateNone(t *testing.T) {
	s := &Source{SampleMode: "none"}
	if r := s.ResolveSampleRate(9999); r != 1 {
		t.Errorf("none mode: expected 1, got %d", r)
	}
}

func TestListenerUpdateSourcesWithSlash32(t *testing.T) {
	l := &Listener{
		sources: make(map[string]*Source),
	}
	l.UpdateSources([]SourceConfig{
		{Name: "test", DeviceIP: "10.0.0.1/32", SampleMode: "auto", Enabled: true},
	})

	if len(l.sources) != 1 {
		t.Fatalf("expected 1 source, got %d", len(l.sources))
	}
	if _, ok := l.sources["10.0.0.1"]; !ok {
		t.Error("expected source key '10.0.0.1'")
		for k := range l.sources {
			t.Logf("  actual key: %q", k)
		}
	}
}

func TestListenerUpdateSourcesWithoutSlash(t *testing.T) {
	l := &Listener{
		sources: make(map[string]*Source),
	}
	l.UpdateSources([]SourceConfig{
		{Name: "test", DeviceIP: "192.168.1.1", SampleMode: "force", SampleRate: 500, Enabled: true},
	})

	if len(l.sources) != 1 {
		t.Fatalf("expected 1 source, got %d", len(l.sources))
	}
	s := l.sources["192.168.1.1"]
	if s == nil {
		t.Fatal("expected source '192.168.1.1'")
	}
	if s.SampleMode != "force" || s.SampleRate != 500 {
		t.Errorf("unexpected source config: mode=%s rate=%d", s.SampleMode, s.SampleRate)
	}
}

func TestListenerUpdateSourcesIPv6WithSlash128(t *testing.T) {
	l := &Listener{
		sources: make(map[string]*Source),
	}
	l.UpdateSources([]SourceConfig{
		{Name: "v6", DeviceIP: "2001:db8::1/128", SampleMode: "auto", Enabled: true},
	})

	if len(l.sources) != 1 {
		t.Fatalf("expected 1 source, got %d", len(l.sources))
	}
	if _, ok := l.sources["2001:db8::1"]; !ok {
		t.Error("expected source key '2001:db8::1'")
	}
}

func TestListenerUpdateSourcesDisabledSkipped(t *testing.T) {
	l := &Listener{
		sources: make(map[string]*Source),
	}
	l.UpdateSources([]SourceConfig{
		{Name: "enabled", DeviceIP: "10.0.0.1", SampleMode: "auto", Enabled: true},
		{Name: "disabled", DeviceIP: "10.0.0.2", SampleMode: "auto", Enabled: false},
	})

	// Disabled source should still be in the map (Enabled flag checked at runtime in transport)
	// UpdateSources stores all, transport checks Enabled
	if len(l.sources) != 2 {
		t.Fatalf("expected 2 sources (enabled check is at transport), got %d", len(l.sources))
	}
}

func TestListenerMatchesProtocolModeSFlow(t *testing.T) {
	l := &Listener{ProtocolMode: "sflow"}

	// sFlow: first 4 bytes as uint32 = 5
	sflowPayload := []byte{0, 0, 0, 5, 0, 0, 0, 1} // version=5, agent_type=1
	if !l.matchesProtocolMode(sflowPayload) {
		t.Error("sflow mode should match sFlow packet")
	}

	// NetFlow v9: first 2 bytes = 0x0009
	nfv9Payload := []byte{0, 9, 0, 1, 0, 0, 0, 0}
	if l.matchesProtocolMode(nfv9Payload) {
		t.Error("sflow mode should reject NetFlow v9")
	}
}

func TestListenerMatchesProtocolModeNetflow(t *testing.T) {
	l := &Listener{ProtocolMode: "netflow"}

	// NetFlow v5
	nfv5Payload := []byte{0, 5, 0, 1, 0, 0, 0, 0}
	if !l.matchesProtocolMode(nfv5Payload) {
		t.Error("netflow mode should match NetFlow v5")
	}

	// NetFlow v9
	nfv9Payload := []byte{0, 9, 0, 1, 0, 0, 0, 0}
	if !l.matchesProtocolMode(nfv9Payload) {
		t.Error("netflow mode should match NetFlow v9")
	}

	// IPFIX (v10) — netflow mode should NOT match IPFIX
	ipfixPayload := []byte{0, 10, 0, 1, 0, 0, 0, 0}
	if l.matchesProtocolMode(ipfixPayload) {
		t.Error("netflow mode should reject IPFIX")
	}
}

func TestListenerMatchesProtocolModeIPFIX(t *testing.T) {
	l := &Listener{ProtocolMode: "ipfix"}

	ipfixPayload := []byte{0, 10, 0, 1, 0, 0, 0, 0}
	if !l.matchesProtocolMode(ipfixPayload) {
		t.Error("ipfix mode should match IPFIX")
	}

	nfv9Payload := []byte{0, 9, 0, 1, 0, 0, 0, 0}
	if l.matchesProtocolMode(nfv9Payload) {
		t.Error("ipfix mode should reject NetFlow v9")
	}
}

func TestListenerMatchesProtocolModeAuto(t *testing.T) {
	l := &Listener{ProtocolMode: "auto"}

	// Auto should match everything
	for _, payload := range [][]byte{
		{0, 0, 0, 5, 0, 0, 0, 1}, // sFlow
		{0, 5, 0, 1, 0, 0, 0, 0}, // NFv5
		{0, 9, 0, 1, 0, 0, 0, 0}, // NFv9
		{0, 10, 0, 1, 0, 0, 0, 0}, // IPFIX
	} {
		if !l.matchesProtocolMode(payload) {
			t.Errorf("auto mode should match all, rejected payload %v", payload)
		}
	}
}
