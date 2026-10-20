package devices

import (
	"log/slog"
	"net/netip"
)

// SourceOptions — где и что слушать.
type SourceOptions struct {
	// Interface — интерфейс LAN; на каналах не слушаем никогда.
	Interface string
	// Networks — адреса LAN: пакеты с других источников отбрасываются.
	Networks []netip.Prefix
	Observe  func(Observation)
	Log      *slog.Logger
}
