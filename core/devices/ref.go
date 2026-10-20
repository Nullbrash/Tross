package devices

import (
	"fmt"
	"net/netip"
	"regexp"
	"strings"

	"tross/core/model"
)

// Ref — ссылка на устройство в конфиге: IPv4-адрес, MAC или id записи
// реестра («dev-…»). По MAC и id правило следует за устройством при смене
// адреса; по IP — за адресом, кто бы его ни занял.
type Ref struct {
	Addr netip.Addr
	MAC  model.MAC
	ID   string
}

var idRe = regexp.MustCompile(`^dev-[0-9a-f]{12}$`)

func ParseRef(s string) (Ref, error) {
	s = strings.TrimSpace(s)
	if a, err := netip.ParseAddr(s); err == nil {
		if !a.Is4() {
			return Ref{}, fmt.Errorf("device %q: only IPv4 is supported", s)
		}
		return Ref{Addr: a}, nil
	}
	if m, err := model.ParseMAC(s); err == nil {
		if m.IsZero() || m.IsMulticast() {
			return Ref{}, fmt.Errorf("device %q: not a client MAC", s)
		}
		return Ref{MAC: m}, nil
	}
	if idRe.MatchString(s) {
		return Ref{ID: s}, nil
	}
	return Ref{}, fmt.Errorf("device %q: want an IPv4 address, a MAC or a device id (dev-…)", s)
}

func (r Ref) IsZero() bool { return r == Ref{} }

// String — каноническая запись (MAC — строчными, через двоеточие): по ней
// ссылки сравниваются.
func (r Ref) String() string {
	switch {
	case r.Addr.IsValid():
		return r.Addr.String()
	case !r.MAC.IsZero():
		return r.MAC.String()
	}
	return r.ID
}

func (r Ref) MarshalText() ([]byte, error) { return []byte(r.String()), nil }

func (r *Ref) UnmarshalText(b []byte) error {
	v, err := ParseRef(string(b))
	if err != nil {
		return err
	}
	*r = v
	return nil
}

// AddrOf — текущий адрес устройства по ссылке: у ссылки по IP — сам
// адрес; неизвестное устройство или без адреса — false.
func (r *Registry) AddrOf(ref Ref) (netip.Addr, bool) {
	if ref.Addr.IsValid() {
		return ref.Addr, true
	}
	d, ok := r.Resolve(ref.String())
	if !ok || !d.Addr.IsValid() {
		return netip.Addr{}, false
	}
	return d.Addr, true
}

// RefsOf — все ссылки, которыми можно назвать устройство с этим адресом:
// адрес, id, псевдонимы, MAC. Неизвестный адрес — только он сам.
func (r *Registry) RefsOf(a netip.Addr) []string {
	out := []string{a.String()}
	d, ok := r.ByIP(a)
	if !ok {
		return out
	}
	out = append(out, d.ID)
	out = append(out, d.Aliases...)
	for _, m := range d.MACs {
		out = append(out, m.String())
	}
	return out
}
