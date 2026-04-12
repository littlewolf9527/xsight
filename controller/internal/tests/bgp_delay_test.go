package tests

import (
	"testing"

	"github.com/littlewolf9527/xsight/controller/internal/action"
)

// U14: Verifies that CompleteDelay removes the entry without cancelling the context.
// This tests the ScheduleDelay/CompleteDelay helper mechanics, NOT the full
// delayed-withdraw execution path (which requires a real BGP connector).
func TestDelayHelper_CompleteDoesNotCancel(t *testing.T) {
	ms := NewMockStore()
	eng := action.NewEngine(ms, "auto")

	// CancelDelaysForAttack on empty map should be a no-op.
	eng.CancelDelaysForAttack(1)

	ctx := eng.ScheduleDelay(1, 2, 3, "10.0.0.1/32|RTBH")
	eng.CompleteDelay(1, 2, 3, "10.0.0.1/32|RTBH")
	eng.CancelDelaysForAttack(1) // nothing to cancel after Complete

	select {
	case <-ctx.Done():
		t.Error("context should not be cancelled after CompleteDelay")
	default:
		// Expected: CompleteDelay removes entry, does not call cancel.
	}
}

// U15: Verifies that ScheduleDelay returns a live (non-cancelled) context.
func TestDelayHelper_ScheduleReturnsLiveContext(t *testing.T) {
	ms := NewMockStore()
	eng := action.NewEngine(ms, "auto")

	ctx := eng.ScheduleDelay(1, 2, 3, "10.0.0.1/32|RTBH")
	if ctx == nil {
		t.Fatal("ScheduleDelay returned nil context")
	}

	select {
	case <-ctx.Done():
		t.Error("context should not be cancelled immediately after ScheduleDelay")
	default:
		// Expected.
	}
}

// U16: Verifies that CancelDelaysForAttack cancels all pending delays for a given attackID.
func TestDelayHelper_CancelDelaysForAttack(t *testing.T) {
	ms := NewMockStore()
	eng := action.NewEngine(ms, "auto")

	ctx := eng.ScheduleDelay(1, 2, 3, "10.0.0.1/32|RTBH")

	eng.CancelDelaysForAttack(1)

	select {
	case <-ctx.Done():
		// Expected.
	default:
		t.Error("context should be cancelled after CancelDelaysForAttack")
	}
}

// U17: Same as U16 but for xDrop-flavored keys — verifies no key-format bias.
func TestDelayHelper_CancelDelaysForAttack_XDrop(t *testing.T) {
	ms := NewMockStore()
	eng := action.NewEngine(ms, "auto")

	ctx := eng.ScheduleDelay(1, 5, 10, "rule-abc")

	eng.CancelDelaysForAttack(1)

	select {
	case <-ctx.Done():
		// Expected.
	default:
		t.Error("xdrop delay context should be cancelled after CancelDelaysForAttack")
	}
}
