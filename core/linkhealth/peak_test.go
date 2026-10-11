package linkhealth

import (
	"testing"
	"time"
)

func TestPeakTracker(t *testing.T) {
	var p PeakTracker
	base := time.Date(2026, 10, 11, 10, 15, 0, 0, time.UTC)
	p.Add(base, 100, 10)
	p.Add(base.Add(time.Minute), 300, 5)
	p.Add(base.Add(2*time.Hour), 200, 50)
	if d, u := p.Peak(base.Add(2 * time.Hour)); d != 300 || u != 50 {
		t.Fatalf("peak = %d/%d, want 300/50", d, u)
	}
	// Через сутки корзина 10:00 устаревает, остаётся 12:00.
	if d, u := p.Peak(base.Add(24*time.Hour + time.Minute)); d != 200 || u != 50 {
		t.Fatalf("after 24h peak = %d/%d, want 200/50", d, u)
	}
	// Та же корзина через сутки перезаписывается, а не накапливается.
	p.Add(base.Add(24*time.Hour), 50, 1)
	if d, _ := p.Peak(base.Add(24*time.Hour + time.Minute)); d != 200 {
		t.Fatalf("stale bucket leaked: %d", d)
	}
}
