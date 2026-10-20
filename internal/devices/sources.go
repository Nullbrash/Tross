package devices

import (
	"log/slog"
	"net/netip"

	"tross/core/model"
)

// SourceOptions — где и что слушать.
type SourceOptions struct {
	// Interface — интерфейс LAN; на каналах не слушаем никогда.
	Interface string
	// Networks — адреса LAN: пакеты с других источников отбрасываются.
	Networks []netip.Prefix
	Observe  func(Observation)
	// OnServer — ответ DHCP-сервера в LAN (идентификатор сервера, MAC
	// отправителя): так замечается второй раздающий; nil — не нужно.
	OnServer func(server netip.Addr, mac model.MAC)
	Log      *slog.Logger
}
