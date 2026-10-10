// Package devices — реестр клиентов сети по MAC (этап 7).
package devices

import (
	"context"
	"net/netip"
	"time"

	"tross/core/model"
)

// Observation — факт появления устройства в сети (DHCP, ARP, mDNS, SSDP).
type Observation struct {
	MAC   model.MAC
	IP    netip.Addr
	Hints model.DeviceHints
	At    time.Time
}

// DeviceRegistry ведёт реестр устройств и публикует event.TopicDeviceNew.
type DeviceRegistry interface {
	// Observe учитывает наблюдение; isNew — устройство увидено впервые.
	Observe(ctx context.Context, o Observation) (d model.Device, isNew bool, err error)
	List() []model.Device
	Get(id string) (model.Device, bool)
	ByMAC(mac model.MAC) (model.Device, bool)
	ByIP(ip netip.Addr) (model.Device, bool)
	// Update сохраняет правки пользователя (имя, тип, заметка, режим DNS).
	Update(ctx context.Context, d model.Device) error
	// Merge переносит MAC и настройки записи src в dst и удаляет src.
	Merge(ctx context.Context, dstID, srcID string) error
}
