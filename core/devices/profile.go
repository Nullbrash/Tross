package devices

import "tross/core/model"

// DefaultUPnP — уровень UPnP по профилю типа. Ослабление — только для типа,
// подтверждённого пользователем: назваться приставкой может кто угодно.
func DefaultUPnP(t model.DeviceType, confirmed bool) model.UPnPLevel {
	if !confirmed {
		return model.UPnPDeny
	}
	switch t {
	case model.DeviceTypeConsole:
		return model.UPnPAllow
	case model.DeviceTypePC:
		return model.UPnPAsk
	}
	return model.UPnPDeny
}

// EffectiveUPnP — уровень, заданный пользователем, иначе по профилю.
func EffectiveUPnP(d model.Device) model.UPnPLevel {
	if d.UPnP != "" {
		return d.UPnP
	}
	return DefaultUPnP(d.Type, d.TypeConfirmed)
}
