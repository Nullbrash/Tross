// Package devices — реестр клиентов сети по MAC: записи из наблюдений
// (DHCP, ARP, mDNS, SSDP), производитель по OUI, догадка о типе, профили по
// типу, предположение «то же устройство после смены случайного MAC».
// Без ввода-вывода: наблюдения приносит и записи сохраняет демон.
package devices

import (
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"time"

	"tross/core/model"
)

// Observation — признак того, что устройство сейчас в сети. Только
// свидетельства активности (запрос DHCP, ответ ARP, анонс): запись соседа,
// оставшаяся в ядре после ухода, — не наблюдение, иначе «оба устройства в
// сети» снимет верное предположение о смене MAC.
type Observation struct {
	MAC   model.MAC
	IP    netip.Addr
	Hints model.DeviceHints
	At    time.Time
}

// Change — итог наблюдения.
type Change struct {
	Device model.Device
	// New — запись создана; Changed — изменилось что-то кроме LastSeen
	// (сохранить сразу; LastSeen сохраняется пачкой).
	New, Changed bool
	// Others — другие записи, изменённые попутно (адрес перешёл, снято
	// предположение): их тоже сохранить.
	Others []model.Device
}

var (
	ErrNotFound = errors.New("devices: no such device")
	ErrSame     = errors.New("devices: cannot merge a device into itself")
	ErrInvalid  = errors.New("devices: invalid value")
	// ErrPlaceholder — MAC-заглушка (02:00:00:00:00:00: так Android скрывает
	// адрес): не адрес устройства — под ним бывают разные устройства.
	ErrPlaceholder = errors.New("devices: placeholder MAC")
)

// IsPlaceholder — MAC, который не опознаёт устройство.
func IsPlaceholder(m model.MAC) bool { return m == model.MAC{0x02} }

// SameWindow — как давно должна была пропасть запись, чтобы новая могла
// быть ею после смены MAC.
const SameWindow = 30 * 24 * time.Hour

// Registry — реестр в памяти; безопасен для параллельного использования.
type Registry struct {
	mu    sync.Mutex
	devs  map[string]*model.Device
	byMAC map[model.MAC]string
	byIP  map[netip.Addr]string
}

func NewRegistry() *Registry {
	return &Registry{devs: map[string]*model.Device{}, byMAC: map[model.MAC]string{}, byIP: map[netip.Addr]string{}}
}

// Load заменяет содержимое реестра сохранёнными записями.
func (r *Registry) Load(ds []model.Device) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.devs, r.byMAC, r.byIP = map[string]*model.Device{}, map[model.MAC]string{}, map[netip.Addr]string{}
	for _, d := range ds {
		r.devs[d.ID] = &d
		for _, m := range d.MACs {
			r.byMAC[m] = d.ID
		}
		if d.Addr.IsValid() {
			r.byIP[d.Addr] = d.ID
		}
	}
}

// ID записи — по первому MAC: стабилен и читаем; MAC в реестре один раз,
// поэтому id не повторяется.
func idOf(m model.MAC) string { return "dev-" + strings.ReplaceAll(m.String(), ":", "") }

func (r *Registry) Observe(o Observation) (Change, error) {
	if o.MAC.IsZero() || o.MAC.IsMulticast() {
		return Change{}, fmt.Errorf("devices: not a client MAC: %s", o.MAC)
	}
	if IsPlaceholder(o.MAC) {
		return Change{}, ErrPlaceholder
	}
	if o.At.IsZero() {
		return Change{}, errors.New("devices: observation without time")
	}
	r.mu.Lock()
	defer r.mu.Unlock()

	var ch Change
	others := map[string]bool{}
	id, known := r.byMAC[o.MAC]
	if !known {
		h := o.Hints
		if v := Vendor(o.MAC); v != "" {
			h.Vendor = v
		}
		d := &model.Device{ID: idOf(o.MAC), MACs: []model.MAC{o.MAC}, Hints: h, Type: GuessType(h), FirstSeen: o.At, LastSeen: o.At}
		r.devs[d.ID], r.byMAC[o.MAC] = d, d.ID
		id, ch.New, ch.Changed = d.ID, true, true
	}
	d := r.devs[id]
	if known {
		if o.At.After(d.LastSeen) {
			d.LastSeen = o.At
		}
		if h := MergeHints(d.Hints, o.Hints); h != d.Hints {
			d.Hints, ch.Changed = h, true
			if !d.TypeConfirmed {
				d.Type = GuessType(h)
			}
		}
	}
	if o.IP.IsValid() && d.Addr != o.IP {
		if prev, ok := r.byIP[o.IP]; ok && prev != id {
			r.devs[prev].Addr = netip.Addr{}
			others[prev] = true
		}
		if d.Addr.IsValid() && r.byIP[d.Addr] == id {
			delete(r.byIP, d.Addr)
		}
		d.Addr, r.byIP[o.IP], ch.Changed = o.IP, id, true
	}
	// Подсказки приходят не сразу (ARP раньше имени mDNS) — пока запись
	// молода, предположение пересчитывается с каждой новой подсказкой.
	if ch.Changed && d.MaybeSame == nil && o.At.Sub(d.FirstSeen) <= OnlineWindow {
		d.MaybeSame = r.sameAs(d)
	}
	// Записи, которые считали эту своим прежним «я», пока она ушла: обе в
	// сети — значит, это два устройства.
	for _, x := range r.devs {
		if x.MaybeSame != nil && x.MaybeSame.ID == id && o.At.After(x.FirstSeen) && !x.LastSeen.Before(o.At.Add(-OnlineWindow)) {
			x.MaybeSame = nil
			others[x.ID] = true
		}
	}
	ch.Device = clone(d)
	for oid := range others {
		ch.Others = append(ch.Others, clone(r.devs[oid]))
	}
	slices.SortFunc(ch.Others, func(a, b model.Device) int { return strings.Compare(a.ID, b.ID) })
	return ch, nil
}

// OnlineWindow — запись видели не раньше этого — она «в сети».
const OnlineWindow = 10 * time.Minute

// Edit — правки пользователя; nil — поле не меняется.
type Edit struct {
	Name    *string
	Type    *model.DeviceType
	Note    *string
	DNSMode *model.DNSMode
	UPnP    *model.UPnPLevel
}

// Update применяет правки. Тип, заданный пользователем, — подтверждённый;
// пустой тип возвращает догадку.
func (r *Registry) Update(id string, e Edit) (model.Device, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	d, ok := r.devs[id]
	if !ok {
		return model.Device{}, ErrNotFound
	}
	if e.Type != nil && *e.Type != "" && !e.Type.Valid() {
		return model.Device{}, fmt.Errorf("%w: type %q", ErrInvalid, *e.Type)
	}
	if e.DNSMode != nil && *e.DNSMode != "" && !e.DNSMode.Valid() {
		return model.Device{}, fmt.Errorf("%w: dns mode %q", ErrInvalid, *e.DNSMode)
	}
	if e.UPnP != nil && *e.UPnP != "" && !e.UPnP.Valid() {
		return model.Device{}, fmt.Errorf("%w: upnp level %q", ErrInvalid, *e.UPnP)
	}
	if e.Name != nil {
		d.Name = strings.TrimSpace(*e.Name)
	}
	if e.Note != nil {
		d.Note = strings.TrimSpace(*e.Note)
	}
	if e.Type != nil {
		if *e.Type == "" {
			d.Type, d.TypeConfirmed = GuessType(d.Hints), false
		} else {
			d.Type, d.TypeConfirmed = *e.Type, true
		}
	}
	if e.DNSMode != nil {
		d.DNSMode = *e.DNSMode
	}
	if e.UPnP != nil {
		d.UPnP = *e.UPnP
	}
	return clone(d), nil
}

// Merge вливает запись src в dst: MAC, адрес и свежие подсказки src
// переходят к dst, настройки dst остаются (пустые — берутся у src), id src
// становится псевдонимом dst. Возвращает dst и записи, изменённые попутно.
func (r *Registry) Merge(dstID, srcID string) (model.Device, []model.Device, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if dstID == srcID {
		return model.Device{}, nil, ErrSame
	}
	dst, ok1 := r.devs[dstID]
	src, ok2 := r.devs[srcID]
	if !ok1 || !ok2 {
		return model.Device{}, nil, ErrNotFound
	}
	for _, m := range src.MACs {
		if !slices.Contains(dst.MACs, m) {
			dst.MACs = append(dst.MACs, m)
		}
		r.byMAC[m] = dstID
	}
	newer := src.LastSeen.After(dst.LastSeen)
	if newer {
		dst.Hints = MergeHints(dst.Hints, src.Hints)
		dst.LastSeen = src.LastSeen
	} else {
		dst.Hints = MergeHints(src.Hints, dst.Hints)
	}
	if src.FirstSeen.Before(dst.FirstSeen) {
		dst.FirstSeen = src.FirstSeen
	}
	if src.Addr.IsValid() && (newer || !dst.Addr.IsValid()) {
		if dst.Addr.IsValid() && r.byIP[dst.Addr] == dstID {
			delete(r.byIP, dst.Addr)
		}
		dst.Addr = src.Addr
		r.byIP[src.Addr] = dstID
	} else if src.Addr.IsValid() && r.byIP[src.Addr] == srcID {
		delete(r.byIP, src.Addr)
	}
	fill := func(d *string, v string) {
		if *d == "" {
			*d = v
		}
	}
	fill(&dst.Name, src.Name)
	fill(&dst.Note, src.Note)
	if dst.DNSMode == "" {
		dst.DNSMode = src.DNSMode
	}
	if dst.UPnP == "" {
		dst.UPnP = src.UPnP
	}
	switch {
	case dst.TypeConfirmed:
	case src.TypeConfirmed:
		dst.Type, dst.TypeConfirmed = src.Type, true
	default:
		dst.Type = GuessType(dst.Hints)
	}
	for _, p := range src.UPnPPrograms {
		if !slices.Contains(dst.UPnPPrograms, p) {
			dst.UPnPPrograms = append(dst.UPnPPrograms, p)
		}
	}
	dst.Aliases = append(append(dst.Aliases, src.ID), src.Aliases...)
	dst.NotSame = slices.DeleteFunc(append(dst.NotSame, src.NotSame...), func(s string) bool { return s == srcID || s == dstID })
	dst.NotSame = slices.Compact(sortedCopy(dst.NotSame))
	dst.MaybeSame = nil
	delete(r.devs, srcID)

	var others []model.Device
	for _, x := range r.devs {
		changed := false
		if x.MaybeSame != nil && x.MaybeSame.ID == srcID {
			x.MaybeSame.ID, changed = dstID, true
		}
		if i := slices.Index(x.NotSame, srcID); i >= 0 {
			x.NotSame[i], changed = dstID, true
			x.NotSame = slices.Compact(sortedCopy(x.NotSame))
		}
		if changed {
			others = append(others, clone(x))
		}
	}
	slices.SortFunc(others, func(a, b model.Device) int { return strings.Compare(a.ID, b.ID) })
	return clone(dst), others, nil
}

// MaxPrograms — предел программ «всегда» на устройство.
const MaxPrograms = 32

// AllowProgram — программа устройства открывает порты без вопроса.
func (r *Registry) AllowProgram(id, desc string) (model.Device, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	d, ok := r.devs[id]
	if !ok {
		return model.Device{}, ErrNotFound
	}
	desc = strings.TrimSpace(desc)
	switch {
	case desc == "":
		return model.Device{}, fmt.Errorf("%w: empty program description", ErrInvalid)
	case slices.ContainsFunc(d.UPnPPrograms, func(p string) bool { return strings.EqualFold(p, desc) }):
	case len(d.UPnPPrograms) >= MaxPrograms:
		return model.Device{}, fmt.Errorf("%w: too many programs", ErrInvalid)
	default:
		d.UPnPPrograms = append(d.UPnPPrograms, desc)
	}
	return clone(d), nil
}

// Dismiss — «это другое устройство»: предположение снимается и больше для
// этой пары не делается.
func (r *Registry) Dismiss(id string) (model.Device, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	d, ok := r.devs[id]
	if !ok {
		return model.Device{}, ErrNotFound
	}
	if d.MaybeSame != nil {
		d.NotSame = slices.Compact(sortedCopy(append(d.NotSame, d.MaybeSame.ID)))
		d.MaybeSame = nil
	}
	return clone(d), nil
}

// Forget удаляет запись (устройство появится снова как новое).
func (r *Registry) Forget(id string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	d, ok := r.devs[id]
	if !ok {
		return ErrNotFound
	}
	for _, m := range d.MACs {
		delete(r.byMAC, m)
	}
	if d.Addr.IsValid() && r.byIP[d.Addr] == id {
		delete(r.byIP, d.Addr)
	}
	delete(r.devs, id)
	return nil
}

func (r *Registry) Len() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.devs)
}

func (r *Registry) List() []model.Device {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]model.Device, 0, len(r.devs))
	for _, d := range r.devs {
		out = append(out, clone(d))
	}
	slices.SortFunc(out, func(a, b model.Device) int { return strings.Compare(a.ID, b.ID) })
	return out
}

func (r *Registry) Get(id string) (model.Device, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	d, ok := r.devs[id]
	if !ok {
		return model.Device{}, false
	}
	return clone(d), true
}

func (r *Registry) ByMAC(m model.MAC) (model.Device, bool) {
	r.mu.Lock()
	id, ok := r.byMAC[m]
	r.mu.Unlock()
	if !ok {
		return model.Device{}, false
	}
	return r.Get(id)
}

func (r *Registry) ByIP(ip netip.Addr) (model.Device, bool) {
	r.mu.Lock()
	id, ok := r.byIP[ip]
	r.mu.Unlock()
	if !ok {
		return model.Device{}, false
	}
	return r.Get(id)
}

// Resolve — запись по ссылке из конфига: id, псевдоним (id влитой записи)
// или MAC.
func (r *Registry) Resolve(ref string) (model.Device, bool) {
	if m, err := model.ParseMAC(ref); err == nil {
		return r.ByMAC(m)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if d, ok := r.devs[ref]; ok {
		return clone(d), true
	}
	for _, d := range r.devs {
		if slices.Contains(d.Aliases, ref) {
			return clone(d), true
		}
	}
	return model.Device{}, false
}

func sortedCopy(s []string) []string {
	out := slices.Clone(s)
	slices.Sort(out)
	return out
}

func clone(d *model.Device) model.Device {
	c := *d
	c.MACs = slices.Clone(d.MACs)
	c.Aliases = slices.Clone(d.Aliases)
	c.NotSame = slices.Clone(d.NotSame)
	c.UPnPPrograms = slices.Clone(d.UPnPPrograms)
	if d.MaybeSame != nil {
		s := *d.MaybeSame
		s.Reasons = slices.Clone(s.Reasons)
		c.MaybeSame = &s
	}
	return c
}
