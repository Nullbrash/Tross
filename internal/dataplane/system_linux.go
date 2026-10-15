//go:build linux

package dataplane

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/ti-mo/conntrack"
	"github.com/ti-mo/netfilter"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"tross/core/decision"
	"tross/core/model"
)

// System — dataplane на ядре Linux: ip rule + таблицы маршрутизации каналов
// (netlink), таблица inet tross (nft), conntrack (netlink).
type System struct {
	log *slog.Logger

	mu      sync.Mutex
	spec    Spec
	up      bool
	plan    []decision.ClassPlan  // текущие распределения и закрепления классов
	routed  map[model.LinkID]bool // маршрут по умолчанию в таблице канала поставлен
	shaping map[model.LinkID]Shaping
	prevSVM string // src_valid_mark до Setup — вернуть при Teardown
}

var _ Dataplane = (*System)(nil)

func NewSystem(log *slog.Logger) (Dataplane, error) {
	if _, err := exec.LookPath("nft"); err != nil {
		return nil, fmt.Errorf("dataplane: nft not found: %w", err)
	}
	return &System{log: log}, nil
}

const (
	sysctlForward = "/proc/sys/net/ipv4/ip_forward"
	sysctlSVM     = "/proc/sys/net/ipv4/conf/all/src_valid_mark"
)

func (s *System) Setup(ctx context.Context, spec Spec) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := validateSpec(spec); err != nil {
		return err
	}
	// Остатки прошлого запуска (в т. ч. аварийного) снимаются до установки.
	s.spec = spec
	_ = s.cleanupLocked(ctx, false)

	// Форвардинг не возвращается при Teardown: без демона сеть должна
	// продолжать работать через основную таблицу (fail-open).
	if err := writeSysctl(sysctlForward, "1"); err != nil {
		return err
	}
	prev, err := readSysctl(sysctlSVM)
	if err != nil {
		return err
	}
	if s.prevSVM == "" { // повторный Setup не должен запомнить уже наше значение
		s.prevSVM = prev
	}
	// rp_filter учитывает метку пакета только при src_valid_mark=1 — иначе
	// ответы из канала без маршрута по умолчанию в main отбрасываются.
	if err := writeSysctl(sysctlSVM, "1"); err != nil {
		return err
	}

	fail := func(err error) error {
		_ = s.cleanupLocked(ctx, false)
		_ = writeSysctl(sysctlSVM, s.prevSVM)
		s.prevSVM = ""
		return err
	}
	if err := s.addRulesLocked(); err != nil {
		return fail(err)
	}
	s.routed = make(map[model.LinkID]bool, len(spec.Links))
	for _, l := range spec.Links {
		if err := s.routeLocked(l); err != nil {
			s.log.Warn("dataplane: link has no route yet, kept unusable", "link", l.Link.ID, "err", err)
			continue
		}
		s.routed[l.Link.ID] = true
	}
	// До первого плана — каждому классу первый разрешённый канал по приоритету.
	c := spec.Classify.withDefault()
	s.plan = initialPlan(c, spec.Links, s.routed)
	if err := runNft(ctx, renderNAT(spec)+renderBase(spec)+renderPlan(c, spec.Links, s.plan)); err != nil {
		return fail(err)
	}
	// Очереди — качество, а не связь: без них сеть работает, поэтому ошибка
	// не срывает Setup (fail-open), а видна в журнале.
	s.shaping = make(map[model.LinkID]Shaping, len(spec.Links))
	for i, l := range spec.Links {
		if err := s.shapeLocked(ctx, i, l); err != nil {
			s.log.Warn("dataplane: link queues not set", "link", l.Link.ID, "err", err)
		}
	}
	s.up = true
	s.log.Info("dataplane: setup done", "links", len(spec.Links), "routed", len(s.routed))
	return nil
}

func validateSpec(spec Spec) error {
	if !validIfname(spec.LANInterface) {
		return fmt.Errorf("dataplane: bad LAN interface %q", spec.LANInterface)
	}
	for _, l := range spec.Links {
		if !validIfname(l.Link.Interface) {
			return fmt.Errorf("dataplane: link %s: bad interface %q", l.Link.ID, l.Link.Interface)
		}
		if l.FwMark == 0 || l.FwMark&^LinkMarkMask != 0 {
			return fmt.Errorf("dataplane: link %s: mark %#x outside %#x", l.Link.ID, l.FwMark, LinkMarkMask)
		}
		if l.Table <= 0 || l.Table >= 253 && l.Table <= 255 {
			return fmt.Errorf("dataplane: link %s: bad table %d", l.Link.ID, l.Table)
		}
	}
	if len(spec.Links) >= rulePrefSpan {
		return errors.New("dataplane: too many links")
	}
	if err := validateForwards(spec); err != nil {
		return fmt.Errorf("dataplane: %w", err)
	}
	return nil
}

// addRulesLocked: сначала main без маршрута по умолчанию (адреса домашней
// сети и подключённые сети побеждают метку), затем fwmark → таблица канала.
func (s *System) addRulesLocked() error {
	sup := netlink.NewRule()
	sup.Family = unix.AF_INET
	sup.Priority = rulePrefBase
	sup.Table = unix.RT_TABLE_MAIN
	sup.SuppressPrefixlen = 0
	if err := netlink.RuleAdd(sup); err != nil {
		return fmt.Errorf("dataplane: rule suppress_prefixlength: %w", err)
	}
	mask := LinkMarkMask
	for i, l := range s.spec.Links {
		r := netlink.NewRule()
		r.Family = unix.AF_INET
		r.Priority = rulePrefBase + 1 + i
		r.Table = l.Table
		r.Mark = l.FwMark
		r.Mask = &mask
		if err := netlink.RuleAdd(r); err != nil {
			return fmt.Errorf("dataplane: rule for %s: %w", l.Link.ID, err)
		}
	}
	return nil
}

// routeLocked ставит маршрут по умолчанию в таблицу канала.
func (s *System) routeLocked(l LinkSpec) error {
	link, err := netlink.LinkByName(l.Link.Interface)
	if err != nil {
		return err
	}
	gw := l.Gateway
	if !gw.IsValid() {
		if gw, err = dhcpGateway(link); err != nil {
			return err
		}
	}
	return netlink.RouteReplace(&netlink.Route{
		LinkIndex: link.Attrs().Index,
		Dst:       &net.IPNet{IP: net.IPv4zero, Mask: net.CIDRMask(0, 32)},
		Gw:        gw.AsSlice(),
		Table:     l.Table,
	})
}

// RepairRoutes сверяет маршрут по умолчанию в таблице каждого канала с
// нужным (интерфейс и шлюз — из конфига или DHCP) и ставит заново, если его
// нет или он устарел. Канал, которому маршрут поставить нельзя (интерфейса
// нет), помечается без маршрута — SetBalance не включит его, пока не починится.
func (s *System) RepairRoutes(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.up {
		return nil
	}
	var errs []error
	for _, l := range s.spec.Links {
		ok, err := s.routeCurrentLocked(l)
		if err != nil {
			errs = append(errs, err)
		}
		if ok {
			continue
		}
		if err := s.routeLocked(l); err != nil {
			if s.routed[l.Link.ID] {
				s.log.Warn("dataplane: link route lost and cannot be restored yet", "link", l.Link.ID, "err", err)
			}
			s.routed[l.Link.ID] = false
			continue
		}
		s.log.Info("dataplane: link route restored", "link", l.Link.ID)
		s.routed[l.Link.ID] = true
	}
	if err := s.repairShapingLocked(ctx); err != nil {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

// routeCurrentLocked — в таблице канала есть маршрут по умолчанию через его
// интерфейс и нужный шлюз.
func (s *System) routeCurrentLocked(l LinkSpec) (bool, error) {
	link, err := netlink.LinkByName(l.Link.Interface)
	if err != nil {
		return false, nil // интерфейса нет — чинить нечем, это не ошибка сверки
	}
	want := l.Gateway
	if !want.IsValid() {
		// Шлюз DHCP сейчас неизвестен — годится любой маршрут через интерфейс:
		// иначе короткая пропажа маршрута в main выкинула бы рабочий канал.
		want, _ = dhcpGateway(link)
	}
	routes, err := netlink.RouteListFiltered(unix.AF_INET, &netlink.Route{Table: l.Table}, netlink.RT_FILTER_TABLE)
	if err != nil {
		return false, fmt.Errorf("dataplane: routes of table %d: %w", l.Table, err)
	}
	for _, r := range routes {
		if (r.Dst == nil || r.Dst.IP.IsUnspecified()) && r.LinkIndex == link.Attrs().Index {
			gw, _ := netip.AddrFromSlice(r.Gw.To4())
			if !want.IsValid() || gw == want {
				return true, nil
			}
		}
	}
	return false, nil
}

// dhcpGateway — шлюз из маршрута по умолчанию в main через этот интерфейс
// (его ставит DHCP-клиент канала).
func dhcpGateway(link netlink.Link) (netip.Addr, error) {
	routes, err := netlink.RouteListFiltered(unix.AF_INET,
		&netlink.Route{Table: unix.RT_TABLE_MAIN, LinkIndex: link.Attrs().Index},
		netlink.RT_FILTER_TABLE|netlink.RT_FILTER_OIF)
	if err != nil {
		return netip.Addr{}, err
	}
	for _, r := range routes {
		if (r.Dst == nil || r.Dst.IP.IsUnspecified()) && r.Gw != nil {
			if a, ok := netip.AddrFromSlice(r.Gw.To4()); ok {
				return a, nil
			}
		}
	}
	return netip.Addr{}, fmt.Errorf("no default route via %s in main table", link.Attrs().Name)
}

func (s *System) Teardown(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	err := s.cleanupLocked(ctx, false)
	if s.prevSVM != "" {
		err = errors.Join(err, writeSysctl(sysctlSVM, s.prevSVM))
		s.prevSVM = ""
	}
	s.up = false
	return err
}

// Cleanup снимает разметку демона без работающего процесса — после
// аварийного завершения (ExecStopPost службы). src_valid_mark не трогается:
// прежнее значение знал только упавший процесс. purge — убрать и NAT
// (удаление Tross из системы).
func Cleanup(ctx context.Context, log *slog.Logger, spec Spec, purge bool) error {
	if _, err := exec.LookPath("nft"); err != nil {
		return fmt.Errorf("dataplane: nft not found: %w", err)
	}
	s := &System{log: log, spec: spec}
	return s.cleanupLocked(ctx, purge)
}

// cleanupLocked снимает всё, чем владеет демон: таблицу inet tross, ip rule
// из диапазона демона, маршруты в таблицах каналов текущей спецификации.
// NAT остаётся (fail-open), если не purge.
func (s *System) cleanupLocked(ctx context.Context, purge bool) error {
	var errs []error
	script := fmt.Sprintf("add table inet %s\ndelete table inet %s\n", nftTable, nftTable)
	if purge {
		script += fmt.Sprintf("add table inet %s\ndelete table inet %s\n", nftNATTable, nftNATTable)
		// Очереди переживают остановку демона (как NAT) — снимает их только purge.
		s.shaping = map[model.LinkID]Shaping{}
		for i, l := range s.spec.Links {
			if err := s.unshapeLocked(ctx, i, l); err != nil {
				errs = append(errs, err)
			}
		}
	}
	if err := runNft(ctx, script); err != nil {
		errs = append(errs, err)
	}
	rules, err := netlink.RuleList(unix.AF_INET)
	if err != nil {
		errs = append(errs, err)
	}
	for _, r := range rules {
		if r.Priority >= rulePrefBase && r.Priority < rulePrefBase+rulePrefSpan {
			rr := r
			if err := netlink.RuleDel(&rr); err != nil && !errors.Is(err, unix.ENOENT) {
				errs = append(errs, fmt.Errorf("rule %d: %w", r.Priority, err))
			}
		}
	}
	for _, l := range s.spec.Links {
		routes, err := netlink.RouteListFiltered(unix.AF_INET, &netlink.Route{Table: l.Table}, netlink.RT_FILTER_TABLE)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		for _, r := range routes {
			rr := r
			if err := netlink.RouteDel(&rr); err != nil && !errors.Is(err, unix.ESRCH) {
				errs = append(errs, fmt.Errorf("route in table %d: %w", l.Table, err))
			}
		}
	}
	return errors.Join(errs...)
}

// SetBalance — распределение для класса default (как до классов).
func (s *System) SetBalance(ctx context.Context, shares []decision.LinkShare) error {
	var pins []model.LinkID
	for _, sh := range shares {
		pins = append(pins, sh.Link)
	}
	return s.SetPlan(ctx, []decision.ClassPlan{{Class: model.ClassDefault, Shares: shares, PinLinks: pins}})
}

func (s *System) SetPlan(ctx context.Context, plan []decision.ClassPlan) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.up {
		return errors.New("dataplane: not set up")
	}
	next := make([]decision.ClassPlan, 0, len(plan))
	for _, p := range plan {
		var ok []decision.LinkShare
		for _, sh := range p.Shares {
			l, known := s.linkLocked(sh.Link)
			if !known || sh.Weight <= 0 {
				continue
			}
			// Маршрута могло не быть при Setup (кабель не был вставлен).
			if !s.routed[sh.Link] {
				if err := s.routeLocked(l); err != nil {
					s.log.Warn("dataplane: link still has no route, left out of plan", "link", sh.Link, "err", err)
					continue
				}
				s.routed[sh.Link] = true
			}
			ok = append(ok, sh)
		}
		p.Shares = ok
		next = append(next, p)
	}
	merged := mergePlan(s.plan, next)
	if plansEqual(merged, s.plan) {
		return nil
	}
	if err := runNft(ctx, renderPlan(s.spec.Classify.withDefault(), s.spec.Links, merged)); err != nil {
		return err
	}
	s.plan = merged
	return nil
}

func (s *System) linkLocked(id model.LinkID) (LinkSpec, bool) {
	for _, l := range s.spec.Links {
		if l.Link.ID == id {
			return l, true
		}
	}
	return LinkSpec{}, false
}

func (s *System) AddToSet(ctx context.Context, set SetName, addr netip.Addr, ttl time.Duration) error {
	s.mu.Lock()
	known := set == SetDPI || set == SetProxy || slices.Contains(s.spec.Classify.domainSets(), set)
	s.mu.Unlock()
	if !known {
		return fmt.Errorf("dataplane: unknown set %q", set)
	}
	if !addr.Is4() {
		return fmt.Errorf("dataplane: %s is not IPv4", addr)
	}
	sec := max(int64(ttl/time.Second), 1)
	return runNft(ctx, renderAddElement(set, addr.String(), sec))
}

func (s *System) FlushConntrack(_ context.Context, id model.LinkID) error {
	s.mu.Lock()
	l, ok := s.linkLocked(id)
	s.mu.Unlock()
	if !ok {
		return fmt.Errorf("dataplane: unknown link %q", id)
	}
	c, err := conntrack.Dial(nil)
	if err != nil {
		return fmt.Errorf("dataplane: conntrack: %w", err)
	}
	defer c.Close()
	f := conntrack.NewFilter().Family(netfilter.ProtoIPv4).Mark(l.FwMark).MarkMask(LinkMarkMask)
	if err := c.FlushFilter(f); err != nil {
		return fmt.Errorf("dataplane: flush conntrack of %s: %w", id, err)
	}
	return nil
}

func (s *System) Connections(context.Context) ([]Connection, error) {
	s.mu.Lock()
	spec := s.spec
	s.mu.Unlock()
	c, err := conntrack.Dial(nil)
	if err != nil {
		return nil, fmt.Errorf("dataplane: conntrack: %w", err)
	}
	defer c.Close()
	flows, err := c.DumpFilter(conntrack.NewFilter().Family(netfilter.ProtoIPv4), nil)
	if err != nil {
		return nil, fmt.Errorf("dataplane: dump conntrack: %w", err)
	}
	var out []Connection
	for _, f := range flows {
		if f.Mark&(LinkMarkMask|classMarkMask) == 0 {
			continue
		}
		o := f.TupleOrig
		cn := Connection{
			Proto:   protoName(o.Proto.Protocol),
			Src:     netip.AddrPortFrom(o.IP.SourceAddress.Unmap(), o.Proto.SourcePort),
			Dst:     netip.AddrPortFrom(o.IP.DestinationAddress.Unmap(), o.Proto.DestinationPort),
			Timeout: time.Duration(f.Timeout) * time.Second,
			Packets: f.CountersOrig.Packets + f.CountersReply.Packets,
			Bytes:   f.CountersOrig.Bytes + f.CountersReply.Bytes,
		}
		cn.Link, cn.Class = decodeMark(spec, f.Mark)
		cn.Tin = tinOf(f.Mark)
		if f.ProtoInfo.TCP != nil {
			cn.State = tcpState(f.ProtoInfo.TCP.State)
		}
		if f.Status.DstNAT() {
			r := f.TupleReply
			cn.Forward = netip.AddrPortFrom(r.IP.SourceAddress.Unmap(), r.Proto.SourcePort)
		}
		out = append(out, cn)
	}
	return out, nil
}

func (s *System) Pins(ctx context.Context) ([]Pin, error) {
	s.mu.Lock()
	spec, up := s.spec, s.up
	s.mu.Unlock()
	if !up {
		return nil, errors.New("dataplane: not set up")
	}
	var out []Pin
	for _, ps := range pinSets(spec) {
		cmd := exec.CommandContext(ctx, "nft", "-j", "list", "set", "inet", nftTable, ps.name)
		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		data, err := cmd.Output()
		if err != nil {
			return nil, fmt.Errorf("nft list set %s: %w: %s", ps.name, err, strings.TrimSpace(stderr.String()))
		}
		pins, err := parsePinSet(ps, data)
		if err != nil {
			return nil, fmt.Errorf("dataplane: %w", err)
		}
		out = append(out, pins...)
	}
	return out, nil
}

// runNft применяет скрипт одной транзакцией: при ошибке ядро не меняется.
func runNft(ctx context.Context, script string) error {
	cmd := exec.CommandContext(ctx, "nft", "-f", "-")
	cmd.Stdin = strings.NewReader(script)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("nft: %w: %s", err, strings.TrimSpace(stderr.String()))
	}
	return nil
}

func readSysctl(path string) (string, error) {
	b, err := os.ReadFile(path)
	return strings.TrimSpace(string(b)), err
}

func writeSysctl(path, v string) error {
	if err := os.WriteFile(path, []byte(v), 0o644); err != nil {
		return fmt.Errorf("sysctl %s: %w", path, err)
	}
	return nil
}
