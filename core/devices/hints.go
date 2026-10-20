package devices

import (
	"regexp"
	"strings"

	"tross/core/model"
)

// MergeHints — подсказки a, дополненные свежими из b (непустое поле b
// заменяет поле a).
func MergeHints(a, b model.DeviceHints) model.DeviceHints {
	set := func(dst *string, v string) {
		if v != "" {
			*dst = v
		}
	}
	set(&a.DHCPHostname, b.DHCPHostname)
	set(&a.DHCPClientID, b.DHCPClientID)
	set(&a.DHCPVendorClass, b.DHCPVendorClass)
	set(&a.DHCPParams, b.DHCPParams)
	set(&a.Vendor, b.Vendor)
	set(&a.MDNSName, b.MDNSName)
	set(&a.MDNSModel, b.MDNSModel)
	set(&a.SSDPServer, b.SSDPServer)
	return a
}

// SuggestName — имя записи по подсказкам: mDNS (его задал владелец,
// «Kitchen-TV»), затем имя DHCP; пусто — интерфейс показывает
// производителя.
func SuggestName(h model.DeviceHints) string {
	for _, n := range []string{h.MDNSName, h.DHCPHostname} {
		n = strings.TrimSuffix(strings.TrimSpace(n), ".local")
		if n != "" && !genericName(n) {
			return n
		}
	}
	return ""
}

type typeRule struct {
	re *regexp.Regexp
	t  model.DeviceType
}

func rules(t model.DeviceType, patterns ...string) []typeRule {
	out := make([]typeRule, len(patterns))
	for i, p := range patterns {
		out[i] = typeRule{regexp.MustCompile(`(?i)` + p), t}
	}
	return out
}

// Порядок важен: ТВ на Android присылает класс android-dhcp, как телефон,
// поэтому ТВ, приставки и умный дом проверяются раньше телефонов.
var nameRules = concat(
	rules(model.DeviceTypeConsole, `^ps[345]\b`, `playstation`, `xbox`, `nintendo`, `^switch\b`, `steamdeck|steam-deck`),
	rules(model.DeviceTypeTV, `\btv\b|-tv\b|tv-|smarttv|smart-tv`, `bravia`, `webos`, `tizen`, `chromecast`, `apple-?tv|appletv`, `\bmibox|mitv`, `roku`, `fire-?tv|^aft[a-z]`, `shield`, `androidtv|android-tv`),
	rules(model.DeviceTypeSmartHome, `^esp[_-]|esp32|esp8266`, `tasmota`, `shelly`, `yeelink|yeelight`, `^zhimi|^lumi|^chuangmi|^roborock|^dreame`, `tuya|smartlife`, `philips-hue|^hue\b`, `sonoff`, `wled`, `\bnest\b|google-home|\becho\b|alexa`, `camera|ipcam|^cam[-_]`, `printer|^hp[0-9a-f]{6}|^epson|^brn[0-9a-f]`),
	rules(model.DeviceTypeServer, `raspberrypi|^rpi`, `\bnas\b|synology|^ds[0-9]{3}|diskstation|qnap|truenas|unraid|openmediavault`, `proxmox|homeassistant|home-assistant`),
	rules(model.DeviceTypePhone, `iphone`, `ipad`, `galaxy|^sm-[a-z][0-9]`, `\bpixel\b`, `redmi|poco|^mi-?[0-9]|xiaomi`, `huawei|honor`, `oneplus`, `\brealme\b|\boppo\b|\bvivo\b`, `^android[-_]`, `nokia|motorola|moto-`),
	rules(model.DeviceTypePC, `^desktop-`, `^laptop-`, `macbook|imac|mac-?mini|mac-?pro|mac-?studio`, `-pc\b|^pc-`, `thinkpad|surface`),
)

// Модели из mDNS _device-info.
var modelRules = concat(
	rules(model.DeviceTypePC, `^mac`, `^imac`),
	rules(model.DeviceTypePhone, `^iphone`, `^ipad`),
	rules(model.DeviceTypeTV, `^appletv`, `^j[0-9]+ap`),
)

var ssdpRules = concat(
	rules(model.DeviceTypeConsole, `xbox`, `playstation`),
	rules(model.DeviceTypeTV, `webos`, `tizen|samsung`, `bravia|sony`, `roku`, `dlnadoc.*tv|tv.*dlnadoc`),
)

var vendorRules = concat(
	rules(model.DeviceTypeConsole, `sony interactive`, `nintendo`),
	rules(model.DeviceTypeTV, `roku`, `tcl king`, `vizio`),
	rules(model.DeviceTypeSmartHome, `espressif`, `tuya`, `shelly|allterco`, `signify|philips lighting`, `ring llc|^ring$`, `sonoff|itead`),
	rules(model.DeviceTypeServer, `raspberry pi`, `synology`, `qnap`),
	// Производители материнских плат — ПК (их сетевая карта на плате).
	rules(model.DeviceTypePC, `micro-star|\bmsi\b`, `asrock`, `giga-byte|gigabyte`),
)

func concat(rs ...[]typeRule) []typeRule {
	var out []typeRule
	for _, r := range rs {
		out = append(out, r...)
	}
	return out
}

func match(rs []typeRule, s string) model.DeviceType {
	if s == "" {
		return ""
	}
	for _, r := range rs {
		if r.re.MatchString(s) {
			return r.t
		}
	}
	return ""
}

// GuessType — тип по подсказкам; не угадан — other. Самое конкретное —
// модель mDNS, затем SSDP и имена, затем класс DHCP и производитель.
func GuessType(h model.DeviceHints) model.DeviceType {
	if t := match(modelRules, h.MDNSModel); t != "" {
		return t
	}
	if t := match(ssdpRules, h.SSDPServer); t != "" {
		return t
	}
	for _, n := range []string{h.MDNSName, h.DHCPHostname} {
		if t := match(nameRules, n); t != "" {
			return t
		}
	}
	vc := strings.ToLower(h.DHCPVendorClass)
	switch {
	case strings.HasPrefix(vc, "android-dhcp"):
		return model.DeviceTypePhone
	case strings.HasPrefix(vc, "msft"):
		return model.DeviceTypePC
	}
	if t := match(vendorRules, h.Vendor); t != "" {
		return t
	}
	return model.DeviceTypeOther
}

// Имена, которые ставятся по умолчанию на тысячах устройств: по ним нельзя
// ни назвать запись, ни узнать устройство после смены MAC.
var generic = map[string]bool{
	"": true, "localhost": true, "unknown": true, "android": true, "iphone": true, "ipad": true,
	"macbook": true, "macbook-pro": true, "macbook-air": true, "imac": true, "galaxy": true,
	"espressif": true, "esp": true, "pc": true, "desktop": true, "laptop": true, "phone": true, "tv": true,
	"android-tv": true, "chromecast": true, "raspberrypi": true, "linux": true, "debian": true, "ubuntu": true,
}

func genericName(n string) bool {
	return generic[strings.ToLower(strings.TrimSuffix(strings.TrimSpace(n), ".local"))]
}
