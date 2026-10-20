//go:build linux

package dataplane

import (
	"context"
	"fmt"
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
	return runNft(ctx, renderDNS(s.spec, up))
}
