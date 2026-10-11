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
	"strings"
	"sync"
	"time"

	"github.com/ti-mo/conntrack"
	"github.com/ti-mo/netfilter"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"tross/core/model"
)

// System — dataplane на ядре Linux: ip rule + таблицы маршрутизации каналов
// (netlink), таблица inet tross (nft), conntrack (netlink).
type System struct {
	log *slog.Logger

	mu      sync.Mutex
	spec    Spec
	up      bool
	usable  map[model.LinkID]bool
	routed  map[model.LinkID]bool // маршрут по умолчанию в таблице канала поставлен
	prevSVM string                // src_valid_mark до Setup — вернуть при Teardown
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
	_ = s.cleanupLocked(ctx)

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
		_ = s.cleanupLocked(ctx)
		_ = writeSysctl(sysctlSVM, s.prevSVM)
		s.prevSVM = ""
		return err
	}
	if err := s.addRulesLocked(); err != nil {
		return fail(err)
	}
	s.usable = make(map[model.LinkID]bool, len(spec.Links))
	s.routed = make(map[model.LinkID]bool, len(spec.Links))
	for _, l := range spec.Links {
		if err := s.routeLocked(l); err != nil {
			s.log.Warn("dataplane: link has no route yet, kept unusable", "link", l.Link.ID, "err", err)
			continue
		}
		s.routed[l.Link.ID] = true
		s.usable[l.Link.ID] = true
	}
	if err := runNft(ctx, renderBase(spec)+renderChoose(spec.Links, s.usable)); err != nil {
		return fail(err)
	}
	s.up = true
	s.log.Info("dataplane: setup done", "links", len(spec.Links), "usable", len(s.usable))
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
	err := s.cleanupLocked(ctx)
	if s.prevSVM != "" {
		err = errors.Join(err, writeSysctl(sysctlSVM, s.prevSVM))
		s.prevSVM = ""
	}
	s.up = false
	return err
}

// cleanupLocked снимает всё, чем владеет демон: таблицу inet tross, ip rule
// из диапазона демона, маршруты в таблицах каналов текущей спецификации.
func (s *System) cleanupLocked(ctx context.Context) error {
	var errs []error
	if err := runNft(ctx, fmt.Sprintf("add table inet %s\ndelete table inet %s\n", nftTable, nftTable)); err != nil {
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

func (s *System) SetLinkUsable(ctx context.Context, id model.LinkID, usable bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.up {
		return errors.New("dataplane: not set up")
	}
	l, ok := s.linkLocked(id)
	if !ok {
		return fmt.Errorf("dataplane: unknown link %q", id)
	}
	if usable && !s.routed[id] {
		if err := s.routeLocked(l); err != nil {
			return fmt.Errorf("dataplane: link %s: %w", id, err)
		}
		s.routed[id] = true
	}
	if s.usable[id] == usable {
		return nil
	}
	s.usable[id] = usable
	return runNft(ctx, renderChoose(s.spec.Links, s.usable))
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
	if set != SetDPI && set != SetProxy {
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
