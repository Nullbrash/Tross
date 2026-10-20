//go:build linux

package dataplane

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"net/netip"
	"slices"
	"time"

	"github.com/google/nftables"
)

// AddToSets — через netlink одной транзакцией: запуск nft стоит ~28 мс на
// ноутбуке-стенде, а резолвер ждёт множества, прежде чем ответить клиенту.
func (s *System) AddToSets(_ context.Context, elems []SetElement) error {
	if len(elems) == 0 {
		return nil
	}
	s.mu.Lock()
	known := s.knownSetsLocked()
	s.mu.Unlock()
	bySet := map[SetName][]nftables.SetElement{}
	var order []SetName
	for _, e := range elems {
		if !slices.Contains(known, e.Set) {
			return fmt.Errorf("dataplane: unknown set %q", e.Set)
		}
		if !e.Addr.Is4() {
			return fmt.Errorf("dataplane: %s is not IPv4", e.Addr)
		}
		a := e.Addr.As4()
		if _, ok := bySet[e.Set]; !ok {
			order = append(order, e.Set)
		}
		bySet[e.Set] = append(bySet[e.Set], nftables.SetElement{Key: a[:], Timeout: max(e.Timeout, time.Second)})
	}
	c, err := nftables.New()
	if err != nil {
		return fmt.Errorf("dataplane: netlink: %w", err)
	}
	defer c.CloseLasting()
	table := &nftables.Table{Name: nftTable, Family: nftables.TableFamilyINet}
	for _, name := range order {
		set := &nftables.Set{Table: table, Name: string(name), KeyType: nftables.TypeIPAddr, HasTimeout: true}
		if err := c.SetAddElements(set, bySet[name]); err != nil {
			return fmt.Errorf("dataplane: set %s: %w", name, err)
		}
	}
	if err := c.Flush(); err != nil {
		return fmt.Errorf("dataplane: add elements: %w", err)
	}
	return nil
}

// AddToSet — один адрес (тесты, ручная проверка).
func (s *System) AddToSet(ctx context.Context, set SetName, addr netip.Addr, ttl time.Duration) error {
	return s.AddToSets(ctx, []SetElement{{Set: set, Addr: addr, Timeout: ttl}})
}

func (s *System) knownSetsLocked() []SetName {
	out := append([]SetName{SetProxy}, s.spec.Classify.domainSets()...)
	for _, l := range s.spec.DPI.Links {
		out = append(out, DPISet(l.Index))
	}
	if len(s.spec.DPI.Links) > 0 {
		out = append(out, SetDPIDevices)
	}
	for i := range s.spec.Links {
		out = append(out, DomainLinkSet(i))
	}
	return out
}

func (s *System) SetDNS(ctx context.Context, up bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.spec.DNS.enabled() {
		return nil
	}
	if err := runNft(ctx, renderDNS(s.spec, up)); err != nil {
		return err
	}
	s.dnsUp = up
	return nil
}

// SetDevices — множества правил через netlink; таблицы DNS и NAT
// пересобираются целиком, только если в них что-то поменялось: смена адреса
// устройства редка, а пересборка NAT сбрасывает счётчики защиты пробросов.
// Установленные соединения переживают её — привязка NAT хранится в conntrack.
func (s *System) SetDevices(ctx context.Context, b DeviceBinding) error {
	if err := validateBinding(b); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	var errs []error
	if err := s.setDeviceSetsLocked(b.Rules); err != nil {
		errs = append(errs, err)
	}
	if s.spec.DNS.enabled() && b.DNS != nil && !maps.Equal(b.DNS, s.spec.DNS.Devices) {
		prev := s.spec.DNS.Devices
		s.spec.DNS.Devices = maps.Clone(b.DNS)
		if err := runNft(ctx, renderDNS(s.spec, s.dnsUp)); err != nil {
			s.spec.DNS.Devices = prev
			errs = append(errs, err)
		}
	}
	fw := slices.Clone(s.spec.Forwards)
	changed := false
	for i, f := range fw {
		if to, ok := b.Forwards[f.Name]; ok && to != f.To {
			fw[i].To, changed = to, true
		}
	}
	if changed {
		next := s.spec
		next.Forwards = fw
		if err := runNft(ctx, renderNAT(next)); err != nil {
			errs = append(errs, err)
		} else {
			s.spec.Forwards = fw
		}
	}
	return errors.Join(errs...)
}

func (s *System) setDeviceSetsLocked(rules map[SetName][]netip.Addr) error {
	known := s.spec.Classify.deviceSets()
	var names []SetName
	for name, as := range rules {
		if !slices.Contains(known, name) {
			return fmt.Errorf("dataplane: unknown device set %q", name)
		}
		if !slices.Equal(as, s.devSets[name]) {
			names = append(names, name)
		}
	}
	if len(names) == 0 {
		return nil
	}
	slices.Sort(names)
	c, err := nftables.New()
	if err != nil {
		return fmt.Errorf("dataplane: netlink: %w", err)
	}
	defer c.CloseLasting()
	table := &nftables.Table{Name: nftTable, Family: nftables.TableFamilyINet}
	for _, name := range names {
		set := &nftables.Set{Table: table, Name: string(name), KeyType: nftables.TypeIPAddr}
		c.FlushSet(set)
		var elems []nftables.SetElement
		for _, a := range rules[name] {
			k := a.As4()
			elems = append(elems, nftables.SetElement{Key: k[:]})
		}
		if len(elems) > 0 {
			if err := c.SetAddElements(set, elems); err != nil {
				return fmt.Errorf("dataplane: set %s: %w", name, err)
			}
		}
	}
	if err := c.Flush(); err != nil {
		return fmt.Errorf("dataplane: device sets: %w", err)
	}
	if s.devSets == nil {
		s.devSets = map[SetName][]netip.Addr{}
	}
	for _, name := range names {
		s.devSets[name] = slices.Clone(rules[name])
	}
	return nil
}
