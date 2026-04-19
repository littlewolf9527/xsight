package postgres

// Unit tests for v1.3 Phase 1a (JSONB persistence tech debt) that don't need
// a live Postgres. Real DB roundtrip tests live elsewhere (integration-level).

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/littlewolf9527/xsight/shared/decoder"
)

// TestMigrations_FragBPSColumn asserts that the v1.3 Phase 1a migration adds
// the frag_bps column to ts_stats. Catches accidental drops during rebases.
func TestMigrations_FragBPSColumn(t *testing.T) {
	var found bool
	for _, m := range migrations {
		if strings.Contains(m, "ADD COLUMN frag_bps BIGINT") {
			found = true
			break
		}
	}
	if !found {
		t.Error("migrations missing ADD COLUMN frag_bps — v2.10.x added tcp/udp/icmp BPS but this Phase 1a step fixes the frag omission")
	}
}

// TestMigrations_ExtraDecoderJSONBColumns asserts Phase 1a JSONB columns are added.
func TestMigrations_ExtraDecoderJSONBColumns(t *testing.T) {
	wantPPS := "ADD COLUMN extra_decoder_pps JSONB"
	wantBPS := "ADD COLUMN extra_decoder_bps JSONB"
	var hasPPS, hasBPS bool
	for _, m := range migrations {
		if strings.Contains(m, wantPPS) {
			hasPPS = true
		}
		if strings.Contains(m, wantBPS) {
			hasBPS = true
		}
	}
	if !hasPPS {
		t.Errorf("migrations missing %q — extra decoders (index ≥ %d) need a JSONB column to persist", wantPPS, decoder.StandardCount)
	}
	if !hasBPS {
		t.Errorf("migrations missing %q — extra decoder BPS needs a JSONB column too", wantBPS)
	}
}

// TestCaggV5_IncludesFragAggregates asserts that ensureCagg creates a v5 cagg
// with frag_pps and frag_bps aggregates. The source file is string-grepped
// because CREATE MATERIALIZED VIEW lives in Go code, not the migrations slice.
func TestCaggV5_IncludesFragAggregates(t *testing.T) {
	_, thisFile, _, _ := runtime.Caller(0)
	srcPath := filepath.Join(filepath.Dir(thisFile), "postgres.go")
	src, err := os.ReadFile(srcPath)
	if err != nil {
		t.Fatalf("read postgres.go: %v", err)
	}
	content := string(src)
	for _, want := range []string{
		"avg(frag_pps)::INT AS avg_frag_pps",
		"avg(frag_bps)::BIGINT AS avg_frag_bps",
	} {
		if !strings.Contains(content, want) {
			t.Errorf("ensureCagg v5 missing %q — frag aggregates were the reason v4→v5 was done", want)
		}
	}
	if !strings.Contains(content, "avg_frag_bps") {
		t.Error("ensureCagg version probe should use avg_frag_bps (the v5 marker column)")
	}
}

// TestBuildExtraDecoderPPS_OnlyExtras asserts that only indices >= StandardCount
// are collected into the map, keyed by decoder name.
func TestBuildExtraDecoderPPS_OnlyExtras(t *testing.T) {
	var input [decoder.MaxDecoders]int32
	input[decoder.TCP] = 100     // index 0 — standard, must NOT appear
	input[decoder.UDP] = 200     // index 2 — standard, must NOT appear
	input[decoder.Frag] = 300    // index 4 — standard, must NOT appear
	// Fill extras (this test is robust against new decoder additions as long as
	// their indices are >= StandardCount and they register a name).
	// Use raw indices directly to avoid coupling to specific v1.3 decoder identities.
	input[decoder.StandardCount] = 7
	input[decoder.MaxDecoders-1] = 9

	got := buildExtraDecoderPPS(input)
	if got == nil {
		t.Fatal("expected non-nil map when any extra decoder has a non-zero value")
	}

	// Standard decoders must not appear.
	for _, std := range []string{"tcp", "tcp_syn", "udp", "icmp", "fragment"} {
		if _, exists := got[std]; exists {
			t.Errorf("standard decoder %q leaked into extra_decoder_pps map", std)
		}
	}

	// The values at index StandardCount and MaxDecoders-1 should appear keyed by their names.
	firstName := decoder.Names[decoder.StandardCount]
	lastName := decoder.Names[decoder.MaxDecoders-1]
	if firstName != "" {
		if v, ok := got[firstName]; !ok || v != 7 {
			t.Errorf("expected got[%q]=7, got %v (exists=%v)", firstName, v, ok)
		}
	}
	if lastName != "" {
		if v, ok := got[lastName]; !ok || v != 9 {
			t.Errorf("expected got[%q]=9, got %v (exists=%v)", lastName, v, ok)
		}
	}
}

// TestBuildExtraDecoderPPS_AllZero returns nil (not empty map) so the DB writes SQL NULL.
// Saves JSONB storage on the (common) row with no v1.3 decoders.
func TestBuildExtraDecoderPPS_AllZero(t *testing.T) {
	var input [decoder.MaxDecoders]int32
	input[decoder.TCP] = 1000 // standard decoder, still all-zero on extras
	got := buildExtraDecoderPPS(input)
	if got != nil {
		t.Errorf("expected nil map when all extra indices are zero, got %v", got)
	}
}

// TestBuildExtraDecoderPPS_SkipEmptyNames makes sure unused slots (Names[i] == "")
// don't pollute the map even if they have a non-zero value (shouldn't happen in
// normal flow but defensive behaviour is important for the JSONB format).
func TestBuildExtraDecoderPPS_SkipEmptyNames(t *testing.T) {
	var input [decoder.MaxDecoders]int32
	// Find an unused slot and write into it.
	unusedIdx := -1
	for i := decoder.StandardCount; i < decoder.MaxDecoders; i++ {
		if decoder.Names[i] == "" {
			unusedIdx = i
			break
		}
	}
	if unusedIdx == -1 {
		t.Skip("no unused decoder slot available — decoder registry is full, test inapplicable")
	}
	input[unusedIdx] = 42
	got := buildExtraDecoderPPS(input)
	if got != nil {
		t.Errorf("unused slot (Names[%d]=\"\") should not produce a map entry; got %v", unusedIdx, got)
	}
}

// TestBuildExtraDecoderBPS_Mirror asserts BPS helper parallels PPS helper.
func TestBuildExtraDecoderBPS_Mirror(t *testing.T) {
	var input [decoder.MaxDecoders]int64
	input[decoder.TCP] = 10_000_000 // standard, ignored
	input[decoder.StandardCount] = 50_000

	got := buildExtraDecoderBPS(input)
	firstName := decoder.Names[decoder.StandardCount]
	if firstName == "" {
		t.Skip("decoder at StandardCount has no name — test inapplicable")
	}
	if got == nil || got[firstName] != 50_000 {
		t.Errorf("expected got[%q]=50000, got %v", firstName, got)
	}
}

// TestEncodeJSONB_NilFromEmpty asserts that empty maps encode to SQL NULL (nil any).
func TestEncodeJSONB_NilFromEmpty(t *testing.T) {
	if got := encodeJSONB(map[string]int32(nil)); got != nil {
		t.Errorf("nil map should encode to nil any (SQL NULL), got %v", got)
	}
	if got := encodeJSONB(map[string]int64{}); got != nil {
		t.Errorf("empty map should encode to nil any (SQL NULL), got %v", got)
	}
}

// TestEncodeJSONB_Roundtrip asserts that a non-empty map encodes to valid JSON
// that can be decoded back to the same values. Catches marshalling regressions.
func TestEncodeJSONB_Roundtrip(t *testing.T) {
	in := map[string]int32{"tcp_ack": 10, "gre": 20}
	raw := encodeJSONB(in)
	b, ok := raw.([]byte)
	if !ok {
		t.Fatalf("expected []byte from encodeJSONB, got %T", raw)
	}
	var out map[string]int32
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatalf("encoded bytes must be valid JSON: %v", err)
	}
	if out["tcp_ack"] != 10 || out["gre"] != 20 {
		t.Errorf("roundtrip mismatch: in=%v out=%v", in, out)
	}
}

// TestEncodeJSONB_UnsupportedType returns nil (SQL NULL) rather than panicking.
// Keeps BulkInsert robust if a future caller passes something unexpected.
func TestEncodeJSONB_UnsupportedType(t *testing.T) {
	if got := encodeJSONB("not a map"); got != nil {
		t.Errorf("unsupported type should encode to nil any, got %v", got)
	}
	if got := encodeJSONB(42); got != nil {
		t.Errorf("unsupported type should encode to nil any, got %v", got)
	}
}
