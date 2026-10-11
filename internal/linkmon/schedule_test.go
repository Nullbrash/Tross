package linkmon

import (
	"testing"
	"time"
)

func TestNightlyDue(t *testing.T) {
	loc := time.FixedZone("MSK", 3*3600)
	day := func(h, m int) time.Time { return time.Date(2026, 10, 12, h, m, 0, 0, loc) }
	never := time.Time{}
	cases := []struct {
		name      string
		now, last time.Time
		want      bool
	}{
		{"before window", day(3, 59), never, false},
		{"window start", day(4, 0), never, true},
		{"inside window", day(4, 30), never, true},
		{"after window", day(5, 0), never, false},
		{"already done today", day(4, 30), day(4, 1), false},
		{"done yesterday", day(4, 30), day(4, 1).Add(-24 * time.Hour), true},
	}
	for _, c := range cases {
		if got := nightlyDue(c.now, c.last, 4, 0); got != c.want {
			t.Errorf("%s: got %v, want %v", c.name, got, c.want)
		}
	}
}
