package devices

import (
	"slices"
	"strings"

	"tross/core/model"
)

// Веса признаков «то же устройство». Имя mDNS и DHCP задаёт владелец или
// ОС из имени устройства; client-id у разных MAC совпадает, только если он
// не выведен из MAC (DUID). Отпечаток DHCP одинаков у всех телефонов одной
// модели — слабый признак.
const (
	strong    = 2.0
	weak      = 0.5
	threshold = strong
)

// sameAs — на какую пропавшую запись похожа новая d; nil — ни на одну
// уверенно или на две одинаково (два одинаковых телефона в доме). Вызов —
// под r.mu.
func (r *Registry) sameAs(d *model.Device) *model.SameAs {
	var best *model.SameAs
	bestScore, tie := 0.0, false
	for _, c := range r.devs {
		if c.ID == d.ID || c.LastSeen.After(d.FirstSeen) || d.FirstSeen.Sub(c.LastSeen) > SameWindow || slices.Contains(d.NotSame, c.ID) {
			continue
		}
		score, reasons := similarity(d.Hints, c.Hints)
		if score < threshold {
			continue
		}
		switch {
		case score > bestScore:
			best, bestScore, tie = &model.SameAs{ID: c.ID, Reasons: reasons}, score, false
		case score == bestScore:
			tie = true
		}
	}
	if tie {
		return nil
	}
	return best
}

// similarity — оценка и причины; противоречие в имени исключает пару.
func similarity(a, b model.DeviceHints) (float64, []string) {
	var score float64
	var reasons []string
	name := func(x, y, why string) bool {
		x, y = normName(x), normName(y)
		if x == "" || y == "" {
			return true
		}
		if x != y {
			// Оба назвались по-разному — разные устройства.
			return generic[x] || generic[y]
		}
		if generic[x] {
			score += weak
		} else {
			score += strong
			reasons = append(reasons, why)
		}
		return true
	}
	if !name(a.MDNSName, b.MDNSName, "mdns_name") || !name(a.DHCPHostname, b.DHCPHostname, "dhcp_hostname") {
		return 0, nil
	}
	if a.DHCPClientID != "" && strings.EqualFold(a.DHCPClientID, b.DHCPClientID) {
		score += strong
		reasons = append(reasons, "dhcp_client_id")
	}
	if a.DHCPParams != "" && a.DHCPParams == b.DHCPParams && a.DHCPVendorClass == b.DHCPVendorClass {
		score += weak
		reasons = append(reasons, "dhcp_fingerprint")
	}
	if a.MDNSModel != "" && a.MDNSModel == b.MDNSModel {
		score += weak
		reasons = append(reasons, "mdns_model")
	}
	return score, reasons
}

func normName(n string) string {
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(n), ".local"))
}
