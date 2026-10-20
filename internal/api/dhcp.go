package api

import (
	"net/http"
	"net/netip"
	"time"

	"tross/internal/dhcp"
)

// DHCPStatus — раздача адресов в LAN.
type DHCPStatus struct {
	Enabled      bool         `json:"enabled"`
	Range        string       `json:"range"`
	Gateway      netip.Addr   `json:"gateway"`
	LeaseSeconds int          `json:"lease_seconds"`
	Running      bool         `json:"running"` // dnsmasq жив
	Reservations int          `json:"reservations"`
	Leases       []dhcp.Lease `json:"leases"`
	// Foreign — другие DHCP-серверы в LAN (роутер с включённой раздачей).
	Foreign []DHCPForeign `json:"foreign"`
}

type DHCPForeign struct {
	Server   netip.Addr `json:"server"`
	MAC      string     `json:"mac"`
	LastSeen time.Time  `json:"last_seen"`
	Reported time.Time  `json:"-"`
}

func (s *Server) handleDHCP(w http.ResponseWriter, r *http.Request) {
	if s.opts.DHCP == nil {
		writeJSON(w, http.StatusOK, DHCPStatus{})
		return
	}
	writeJSON(w, http.StatusOK, s.opts.DHCP(r.Context()))
}
