package baseline

import (
	"testing"
	"time"
)

func TestSlotIndex(t *testing.T) {
	tests := []struct {
		name string
		time time.Time
		want int
	}{
		{
			"Monday 00:00 UTC",
			time.Date(2026, 3, 16, 0, 0, 0, 0, time.UTC), // Monday
			0,
		},
		{
			"Monday 01:00 UTC",
			time.Date(2026, 3, 16, 1, 0, 0, 0, time.UTC),
			1,
		},
		{
			"Tuesday 14:00 UTC",
			time.Date(2026, 3, 17, 14, 0, 0, 0, time.UTC), // Tuesday
			38,
		},
		{
			"Sunday 23:00 UTC",
			time.Date(2026, 3, 22, 23, 0, 0, 0, time.UTC), // Sunday
			167,
		},
		{
			"Sunday 00:00 UTC",
			time.Date(2026, 3, 22, 0, 0, 0, 0, time.UTC), // Sunday
			144,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := SlotIndex(tt.time)
			if got != tt.want {
				t.Errorf("SlotIndex(%v) = %d, want %d (weekday=%s)", tt.time, got, tt.want, tt.time.Weekday())
			}
		})
	}
}

func TestSlotLabel(t *testing.T) {
	tests := []struct {
		slot int
		want string
	}{
		{0, "Monday 00:00 UTC"},
		{167, "Sunday 23:00 UTC"},
		{38, "Tuesday 14:00 UTC"},
		{144, "Sunday 00:00 UTC"},
	}
	for _, tt := range tests {
		got := SlotLabel(tt.slot)
		if got != tt.want {
			t.Errorf("SlotLabel(%d) = %q, want %q", tt.slot, got, tt.want)
		}
	}
}
