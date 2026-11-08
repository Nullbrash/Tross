package dataplane

import (
	"fmt"
	"net/netip"
	"strings"
)

const nftAccessTable = "tross_access"

// renderAccess молча отсеивает новые устройства до обычного маршрута: им
// оставлены только DHCP/DNS самого шлюза, поэтому UI и интернет недоступны.
func renderAccess(spec Spec, approved []netip.Addr) string {
	var b strings.Builder
	fmt.Fprintf(&b, "add table inet %s\ndelete table inet %s\n", nftAccessTable, nftAccessTable)
	if !spec.RequireDeviceApproval {
		return b.String()
	}
	fmt.Fprintf(&b, "table inet %s {\n\tset approved4 { type ipv4_addr", nftAccessTable)
	if len(approved) != 0 {
		b.WriteString("; elements = {")
	}
	for i, a := range approved {
		if i > 0 {
			b.WriteString(", ")
		}
		b.WriteString(a.String())
	}
	if len(approved) != 0 {
		b.WriteString(" }")
	}
	b.WriteString(" }\n")
	lan := quote(spec.LANInterface)
	fmt.Fprintf(&b, "\tchain input { type filter hook input priority filter - 10; policy accept; iifname %s ip saddr @approved4 accept; iifname %s udp dport { 53, 67, 68 } accept; iifname %s tcp dport 53 accept; iifname %s counter drop; }\n", lan, lan, lan, lan)
	fmt.Fprintf(&b, "\tchain forward { type filter hook forward priority filter - 10; policy accept; iifname %s ip saddr @approved4 accept; iifname %s counter drop; }\n}\n", lan, lan)
	return b.String()
}
