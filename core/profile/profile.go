// Package profile — профили сервисов: из каких частей состоит сервис, как
// распознать каждую часть и к какому классу трафика она относится. Каталог —
// данные (встроенный catalog.yaml), а не код: обновляется с проектом, а
// пользователь переопределяет его своими профилями.
package profile

import (
	_ "embed"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strconv"
	"strings"

	"go.yaml.in/yaml/v3"

	"tross/core/model"
)

// Признаки протокола по первому пакету с данными (Flow.Signature).
const (
	SigSTUN         = "stun"
	SigDiscordVoice = "discord_voice"
	SigBitTorrent   = "bittorrent"
	SigUTP          = "utp"
	SigDHT          = "dht"
)

// PortRange — диапазон портов назначения; в YAML — «443» или «27000-27250».
type PortRange struct{ From, To uint16 }

func (r PortRange) Contains(p uint16) bool { return p >= r.From && p <= r.To }

func (r *PortRange) UnmarshalYAML(n *yaml.Node) error {
	var s string
	if err := n.Decode(&s); err != nil {
		return err
	}
	v, err := ParsePortRange(s)
	if err != nil {
		return fmt.Errorf("line %d: %w", n.Line, err)
	}
	*r = v
	return nil
}

func ParsePortRange(s string) (PortRange, error) {
	from, to, found := strings.Cut(strings.TrimSpace(s), "-")
	if !found {
		to = from
	}
	a, err1 := strconv.ParseUint(from, 10, 16)
	b, err2 := strconv.ParseUint(to, 10, 16)
	if err1 != nil || err2 != nil || a == 0 || a > b {
		return PortRange{}, fmt.Errorf("bad port range %q", s)
	}
	return PortRange{uint16(a), uint16(b)}, nil
}

// Match — условие распознавания: все заданные поля должны совпасть (И).
// Domains — суффиксы (сам домен и поддомены).
type Match struct {
	Proto     model.Protocol `yaml:"proto"`
	Ports     []PortRange    `yaml:"ports"`
	Domains   []string       `yaml:"domains"`
	Networks  []netip.Prefix `yaml:"networks"`
	Signature string         `yaml:"signature"`
}

// Part — часть сервиса; Match — варианты (ИЛИ).
type Part struct {
	ID    string             `yaml:"id"`
	Name  string             `yaml:"name"`
	Class model.TrafficClass `yaml:"class"`
	// PinService — все соединения устройства к сервису держать одним каналом.
	PinService bool    `yaml:"pin_service"`
	Match      []Match `yaml:"match"`
}

type Service struct {
	ID       string `yaml:"id"`
	Name     string `yaml:"name"`
	Disabled bool   `yaml:"disabled"`
	Parts    []Part `yaml:"parts"`
}

type Catalog struct {
	Services []Service `yaml:"services"`
}

//go:embed catalog.yaml
var builtin []byte

// Builtin — каталог, поставляемый с проектом.
func Builtin() (Catalog, error) { return Parse(builtin) }

func Parse(b []byte) (Catalog, error) {
	var c Catalog
	dec := yaml.NewDecoder(strings.NewReader(string(b)))
	dec.KnownFields(true)
	if err := dec.Decode(&c); err != nil {
		return Catalog{}, err
	}
	return c, c.Validate()
}

// Domains — домены сервиса ("steam") или его части ("steam/store"); false —
// такого нет. Выключенный сервис доменов не даёт, но существует.
func (c Catalog) Domains(ref string) ([]string, bool) {
	svc, part, _ := strings.Cut(ref, "/")
	for _, s := range c.Services {
		if s.ID != svc {
			continue
		}
		// Выключенный сервис (в том числе заменённый пользователем без
		// частей) существует, но доменов не даёт — и у частей тоже.
		if s.Disabled {
			return nil, true
		}
		var out []string
		found := part == ""
		for _, p := range s.Parts {
			if part != "" && p.ID != part {
				continue
			}
			found = true
			for _, m := range p.Match {
				out = append(out, m.Domains...)
			}
		}
		return out, found
	}
	return nil, false
}

func (c Catalog) Validate() error {
	var errs []error
	seen := map[string]bool{}
	for _, s := range c.Services {
		if s.ID == "" || seen[s.ID] {
			errs = append(errs, fmt.Errorf("service %q: empty or duplicate id", s.ID))
		}
		seen[s.ID] = true
		parts := map[string]bool{}
		for _, p := range s.Parts {
			where := s.ID + "/" + p.ID
			if p.ID == "" || parts[p.ID] {
				errs = append(errs, fmt.Errorf("%s: empty or duplicate part id", where))
			}
			parts[p.ID] = true
			if p.Class == "" {
				errs = append(errs, fmt.Errorf("%s: no class", where))
			}
			if len(p.Match) == 0 {
				errs = append(errs, fmt.Errorf("%s: no match", where))
			}
			for _, m := range p.Match {
				if err := m.Validate(); err != nil {
					errs = append(errs, fmt.Errorf("%s: %w", where, err))
				}
			}
		}
	}
	return errors.Join(errs...)
}

func (m Match) Validate() error {
	if m.Proto != "" && m.Proto != model.ProtoTCP && m.Proto != model.ProtoUDP {
		return fmt.Errorf("bad proto %q", m.Proto)
	}
	if len(m.Ports) == 0 && len(m.Domains) == 0 && len(m.Networks) == 0 && m.Signature == "" {
		// Одно лишь «tcp» совпало бы с половиной трафика.
		return errors.New("match needs ports, domains, networks or signature")
	}
	for _, d := range m.Domains {
		if n, err := model.NormalizeDomain(d); err != nil || n != d {
			return fmt.Errorf("domain %q is not normalized", d)
		}
	}
	for _, p := range m.Networks {
		if !p.Addr().Is4() || p != p.Masked() {
			return fmt.Errorf("network %s: want masked IPv4 prefix", p)
		}
	}
	return nil
}

// WithUser — каталог с профилями пользователя поверх: профиль с тем же ID
// заменяет встроенный целиком (Disabled — выключает), новые — добавляются.
// Обновление каталога проекта не трогает пользовательские профили.
func (c Catalog) WithUser(user []Service) Catalog {
	out := Catalog{}
	for _, s := range c.Services {
		if i := slices.IndexFunc(user, func(u Service) bool { return u.ID == s.ID }); i >= 0 {
			s = user[i]
		}
		out.Services = append(out.Services, s)
	}
	for _, u := range user {
		if !slices.ContainsFunc(c.Services, func(s Service) bool { return s.ID == u.ID }) {
			out.Services = append(out.Services, u)
		}
	}
	return out
}

// Hit — совпавшая часть сервиса.
type Hit struct {
	Service string
	Part    Part
	score   int
}

// Basis — по какому признаку узнана часть: signature, domain, network, port.
func (h Hit) Basis() string {
	switch {
	case h.score >= 1000:
		return "signature"
	case h.score >= 100:
		return "domain"
	case h.score >= 10:
		return "network"
	}
	return "port"
}

// Matches — подходит ли соединение под условие (для правил пользователя).
func (m Match) Matches(f model.Flow) bool {
	_, ok := m.score(f)
	return ok
}

// Lookup — самая конкретная часть, подходящая к соединению. Конкретность:
// признак протокола > домен (длиннее — конкретнее) > сеть > порт; при
// равенстве — порядок каталога.
func (c Catalog) Lookup(f model.Flow) (Hit, bool) {
	var best Hit
	found := false
	for _, s := range c.Services {
		if s.Disabled {
			continue
		}
		for _, p := range s.Parts {
			for _, m := range p.Match {
				if sc, ok := m.score(f); ok && (!found || sc > best.score) {
					best, found = Hit{Service: s.ID, Part: p, score: sc}, true
				}
			}
		}
	}
	return best, found
}

func (m Match) score(f model.Flow) (int, bool) {
	sc := 0
	if m.Proto != "" && m.Proto != f.Proto {
		return 0, false
	}
	if len(m.Ports) > 0 {
		if !slices.ContainsFunc(m.Ports, func(r PortRange) bool { return r.Contains(f.Dst.Port()) }) {
			return 0, false
		}
		sc += 1
	}
	if len(m.Networks) > 0 {
		if !slices.ContainsFunc(m.Networks, func(p netip.Prefix) bool { return p.Contains(f.Dst.Addr()) }) {
			return 0, false
		}
		sc += 10
	}
	if len(m.Domains) > 0 {
		d, err := model.NormalizeDomain(f.Domain)
		if err != nil {
			return 0, false
		}
		longest := -1
		for _, s := range m.Domains {
			if (d == s || strings.HasSuffix(d, "."+s)) && len(s) > longest {
				longest = len(s)
			}
		}
		if longest < 0 {
			return 0, false
		}
		sc += 100 + longest
	}
	if m.Signature != "" {
		if m.Signature != f.Signature {
			return 0, false
		}
		sc += 1000
	}
	return sc, true
}
