package resolver

import (
	"net/netip"
	"testing"
)

func TestFromHome(t *testing.T) {
	r := &Resolver{cfg: Config{Home: []netip.Prefix{netip.MustParsePrefix("192.168.10.0/24")}}}
	for a, want := range map[string]bool{"192.168.10.5": true, "127.0.0.1": true, "203.0.113.5": false, "192.168.11.5": false} {
		if got := r.fromHome(netip.MustParseAddr(a)); got != want {
			t.Errorf("%s: %v", a, got)
		}
	}
	if !(&Resolver{}).fromHome(netip.MustParseAddr("203.0.113.5")) {
		t.Error("no home networks: answer everyone")
	}
}
