package proxypolicy

import (
	"fmt"
	"net/netip"
	"strings"

	"tross/core/model"
)

// KaringGroup — нормализованное представление включённой группы Karing.
// Адаптер формата резервной копии строится отдельно: после импорта секретный
// архив больше не нужен ни политике, ни тестам.
type KaringGroup struct {
	ID        string
	Action    Action
	Domains   []string
	IPs       []string
	GeoIP     []string
	GeoSite   []string
	ACL       []string
	Ports     []uint16
	Protocols []model.Protocol
	Processes []string
	Paths     []string
}

// Unsupported сообщает ровно о том, что шлюз не может применить без агента
// на устройстве. Оно не переводится молча в сетевое условие.
type Unsupported struct{ GroupID, Field, Reason string }

// ImportResult отделяет правила от ссылок на списки и неподдержанных условий.
// Категории списков являются данными сопоставления, но сами ничего не включают.
type ImportResult struct {
	Rules       []Rule
	GeoIP       map[string]struct{}
	GeoSite     map[string]struct{}
	ACL         map[string]struct{}
	Unsupported []Unsupported
}

func actionStage(a Action, geoipRU, geositeRU, acl bool) Stage {
	if geoipRU {
		return StageGeoIPRU
	}
	if geositeRU {
		return StageGeoSiteRU
	}
	if acl {
		return StageACL
	}
	if a == ActionBlock {
		return StageBlock
	}
	if a == ActionProxy {
		return StageProxy
	}
	return StageDirect
}

// ImportKaringGroups импортирует только включённые группы. Гео-категории с
// именем ru получают их фиксированную стадию direct; прочие категории ACL
// сохраняют действие самой включённой группы.
func ImportKaringGroups(groups []KaringGroup) (ImportResult, error) {
	out := ImportResult{GeoIP: map[string]struct{}{}, GeoSite: map[string]struct{}{}, ACL: map[string]struct{}{}}
	seen := map[string]struct{}{}
	for _, g := range groups {
		if strings.TrimSpace(g.ID) == "" || !g.Action.Valid() {
			return out, fmt.Errorf("karing group: invalid id or action")
		}
		if _, ok := seen[g.ID]; ok {
			return out, fmt.Errorf("karing group %q repeated", g.ID)
		}
		seen[g.ID] = struct{}{}
		for _, p := range g.Processes {
			if p != "" {
				out.Unsupported = append(out.Unsupported, Unsupported{g.ID, "process", "requires_device_agent"})
			}
		}
		for _, p := range g.Paths {
			if p != "" {
				out.Unsupported = append(out.Unsupported, Unsupported{g.ID, "path", "requires_device_agent"})
			}
		}
		for _, c := range g.GeoIP {
			out.GeoIP[c] = struct{}{}
			a, s := g.Action, actionStage(g.Action, c == "ru", false, false)
			if c == "ru" {
				a = ActionDirect
			}
			out.Rules = append(out.Rules, Rule{ID: g.ID + ":geoip:" + c, Stage: s, Action: a, Match: Match{GeoIP: c}})
		}
		for _, c := range g.GeoSite {
			out.GeoSite[c] = struct{}{}
			a, s := g.Action, actionStage(g.Action, false, c == "ru", false)
			if c == "ru" {
				a = ActionDirect
			}
			out.Rules = append(out.Rules, Rule{ID: g.ID + ":geosite:" + c, Stage: s, Action: a, Match: Match{GeoSite: c}})
		}
		for _, c := range g.ACL {
			out.ACL[c] = struct{}{}
			out.Rules = append(out.Rules, Rule{ID: g.ID + ":acl:" + c, Stage: StageACL, Action: g.Action, Match: Match{ACL: c}})
		}
		for _, d := range g.Domains {
			d, err := model.NormalizeDomain(d)
			if err != nil {
				return out, fmt.Errorf("karing group %q: %w", g.ID, err)
			}
			out.Rules = append(out.Rules, Rule{ID: g.ID + ":domain:" + d, Stage: actionStage(g.Action, false, false, false), Action: g.Action, Match: Match{Domain: d}})
		}
		for _, s := range g.IPs {
			ip, err := netip.ParseAddr(s)
			if err != nil {
				return out, fmt.Errorf("karing group %q: invalid IP %q", g.ID, s)
			}
			out.Rules = append(out.Rules, Rule{ID: g.ID + ":ip:" + s, Stage: actionStage(g.Action, false, false, false), Action: g.Action, Match: Match{IP: ip}})
		}
	}
	return out, nil
}
