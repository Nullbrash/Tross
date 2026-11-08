package dataplane

import (
	"net/netip"
	"strings"
	"testing"
)

func TestRenderAccessApproval(t *testing.T) {
	s := Spec{LANInterface: "lan", RequireDeviceApproval: true}
	got := renderAccess(s, []netip.Addr{netip.MustParseAddr("192.168.10.20")})
	for _, want := range []string{"approved4", "192.168.10.20", "udp dport { 53, 67, 68 }", "counter drop"} {
		if !strings.Contains(got, want) {
			t.Errorf("access missing %q:\n%s", want, got)
		}
	}
}

func TestRenderAccessOff(t *testing.T) {
	if got := renderAccess(Spec{}, nil); strings.Contains(got, "chain input") {
		t.Fatalf("disabled access has chain: %s", got)
	}
}
