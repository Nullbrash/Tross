package model

import (
	"fmt"
	"net"
	"net/netip"
	"time"
)

// MAC — аппаратный адрес Ethernet (EUI-48).
type MAC [6]byte

func ParseMAC(s string) (MAC, error) {
	hw, err := net.ParseMAC(s)
	if err != nil {
		return MAC{}, err
	}
	if len(hw) != 6 {
		return MAC{}, fmt.Errorf("mac %q: want 6 bytes, got %d", s, len(hw))
	}
	var m MAC
	copy(m[:], hw)
	return m, nil
}

func (m MAC) String() string { return net.HardwareAddr(m[:]).String() }

func (m MAC) IsZero() bool { return m == MAC{} }

// IsLocallyAdministered — бит 0x02 первого октета: второй символ записи 2, 6, A или E.
func (m MAC) IsLocallyAdministered() bool { return m[0]&0x02 != 0 }

func (m MAC) IsMulticast() bool { return m[0]&0x01 != 0 }

// IsRandomized — признак случайного («частного») MAC телефона или ноутбука:
// при нём устройство может сменить адрес и «потерять» свои настройки.
func (m MAC) IsRandomized() bool { return m.IsLocallyAdministered() && !m.IsMulticast() }

// OUI — префикс производителя; у случайных MAC он ничего не значит.
func (m MAC) OUI() [3]byte { return [3]byte{m[0], m[1], m[2]} }

func (m MAC) MarshalText() ([]byte, error) { return []byte(m.String()), nil }

func (m *MAC) UnmarshalText(b []byte) error {
	v, err := ParseMAC(string(b))
	if err != nil {
		return err
	}
	*m = v
	return nil
}

// DeviceType — тип устройства; задаёт профиль политик по умолчанию.
type DeviceType string

const (
	DeviceTypePhone     DeviceType = "phone"
	DeviceTypePC        DeviceType = "pc"
	DeviceTypeTV        DeviceType = "tv"
	DeviceTypeConsole   DeviceType = "console"
	DeviceTypeServer    DeviceType = "server"
	DeviceTypeSmartHome DeviceType = "smart_home"
	DeviceTypeOther     DeviceType = "other"
)

func (t DeviceType) Valid() bool {
	switch t {
	case DeviceTypePhone, DeviceTypePC, DeviceTypeTV, DeviceTypeConsole,
		DeviceTypeServer, DeviceTypeSmartHome, DeviceTypeOther:
		return true
	}
	return false
}

// DNSMode — что делать с запросами устройства к внешним DNS/DoH/DoT.
type DNSMode string

const (
	DNSObserve  DNSMode = "observe"
	DNSRedirect DNSMode = "redirect"
	DNSBlock    DNSMode = "block"
	DNSExempt   DNSMode = "exempt"
)

func (m DNSMode) Valid() bool {
	return m == DNSObserve || m == DNSRedirect || m == DNSBlock || m == DNSExempt
}

// UPnPLevel — может ли устройство само открывать порты (UPnP IGD,
// NAT-PMP, PCP). Пустое — по профилю типа.
type UPnPLevel string

const (
	UPnPDeny  UPnPLevel = "deny"
	UPnPAsk   UPnPLevel = "ask"
	UPnPAllow UPnPLevel = "allow"
)

func (l UPnPLevel) Valid() bool { return l == UPnPDeny || l == UPnPAsk || l == UPnPAllow }

// DeviceHints — подсказки для автоматического определения имени и типа.
type DeviceHints struct {
	DHCPHostname string `json:"dhcp_hostname,omitempty"`
	// DHCPClientID — опция 61 в hex; DHCPVendorClass — опция 60;
	// DHCPParams — список запрошенных опций (55) через запятую: отпечаток ОС.
	DHCPClientID    string `json:"dhcp_client_id,omitempty"`
	DHCPVendorClass string `json:"dhcp_vendor_class,omitempty"`
	DHCPParams      string `json:"dhcp_params,omitempty"`
	Vendor          string `json:"vendor,omitempty"`
	MDNSName        string `json:"mdns_name,omitempty"`
	// MDNSModel — модель из записи _device-info (например, MacBookPro18,3).
	MDNSModel  string `json:"mdns_model,omitempty"`
	SSDPServer string `json:"ssdp_server,omitempty"`
}

// SameAs — предположение «эта запись — то же устройство, что ID» (смена
// случайного MAC). Объединяет только пользователь.
type SameAs struct {
	ID      string   `json:"id"`
	Reasons []string `json:"reasons"`
}

// Device — запись реестра клиентов. Несколько MAC — результат объединения записей
// (например, после смены случайного адреса).
type Device struct {
	ID   string     `json:"id"`
	MACs []MAC      `json:"macs"`
	Name string     `json:"name"`
	Type DeviceType `json:"type"`
	// TypeConfirmed — тип задал пользователь; угаданный тип не ослабляет
	// ограничений профиля.
	TypeConfirmed bool        `json:"type_confirmed,omitempty"`
	Note          string      `json:"note,omitempty"`
	Hints         DeviceHints `json:"hints"`
	DNSMode       DNSMode     `json:"dns_mode,omitempty"`
	UPnP          UPnPLevel   `json:"upnp,omitempty"`
	// UPnPPrograms — программы (по описанию из запроса), которым при
	// уровне «спрашивать» разрешено «всегда»: любой порт ≥ 1024.
	UPnPPrograms []string `json:"upnp_programs,omitempty"`
	// Addr — последний известный IPv4 в LAN.
	Addr netip.Addr `json:"addr,omitzero"`
	// Aliases — id записей, влитых в эту: ссылки на них в конфиге остаются
	// в силе.
	Aliases   []string  `json:"aliases,omitempty"`
	MaybeSame *SameAs   `json:"maybe_same,omitempty"`
	NotSame   []string  `json:"not_same,omitempty"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
}

// HasRandomMAC — есть ли у устройства хотя бы один случайный MAC.
func (d Device) HasRandomMAC() bool {
	for _, m := range d.MACs {
		if m.IsRandomized() {
			return true
		}
	}
	return false
}
