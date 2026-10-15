//go:build linux

package dataplane

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"strings"

	"github.com/vishvananda/netlink"

	"tross/core/model"
)

// runTc — команды tc одним процессом; force — не останавливаться на
// ошибках (снятие того, чего может уже не быть).
func runTc(ctx context.Context, script string, force bool) error {
	args := []string{"-batch", "-"}
	if force {
		args = append([]string{"-force"}, args...)
	}
	cmd := exec.CommandContext(ctx, "tc", args...)
	cmd.Stdin = strings.NewReader(script)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil && !force {
		return fmt.Errorf("tc: %w: %s", err, strings.TrimSpace(stderr.String()))
	}
	return nil
}

// cakeRate — скорость CAKE, стоящего корнем на устройстве (бит/с; 0 — без
// ограничения); ok=false — CAKE там нет.
func cakeRate(ctx context.Context, dev string) (uint64, bool) {
	out, err := exec.CommandContext(ctx, "tc", "-j", "qdisc", "show", "dev", dev, "root").Output()
	if err != nil {
		return 0, false
	}
	var qs []struct {
		Kind    string `json:"kind"`
		Options struct {
			// Скорость CAKE в tc -j — байты в секунду.
			Bandwidth json.RawMessage `json:"bandwidth"`
		} `json:"options"`
	}
	if json.Unmarshal(out, &qs) != nil || len(qs) == 0 || qs[0].Kind != "cake" {
		return 0, false
	}
	var bytesPerSec uint64
	if json.Unmarshal(qs[0].Options.Bandwidth, &bytesPerSec) != nil {
		return 0, true // "unlimited"
	}
	return bytesPerSec * 8, true
}

func ensureIfb(name string) error {
	l, err := netlink.LinkByName(name)
	if err != nil {
		l = &netlink.Ifb{LinkAttrs: netlink.LinkAttrs{Name: name}}
		if err := netlink.LinkAdd(l); err != nil {
			return fmt.Errorf("add %s: %w", name, err)
		}
	}
	return netlink.LinkSetUp(l)
}

// shapeLocked ставит очереди канала. Уже стоящие очереди (прошлый запуск —
// они переживают остановку демона) сохраняют свою скорость, пока демон не
// посчитает новую: без этого перезапуск сбрасывал бы её до «без
// ограничения».
func (s *System) shapeLocked(ctx context.Context, i int, l LinkSpec) error {
	iface, ifb := l.Link.Interface, ifbName(i)
	if !l.SQM {
		return s.unshapeLocked(ctx, i, l)
	}
	sh, ok := s.shaping[l.Link.ID]
	if !ok {
		sh = Shaping{Link: l.Link.ID}
		sh.UpBps, _ = cakeRate(ctx, iface)
		sh.DownBps, _ = cakeRate(ctx, ifb)
	}
	if err := ensureIfb(ifb); err != nil {
		return err
	}
	_ = runTc(ctx, renderShapingFilterDel(iface), true)
	if err := runTc(ctx, renderShapingSetup(iface, ifb, sh), false); err != nil {
		return fmt.Errorf("dataplane: shaping on %s: %w", iface, err)
	}
	s.shaping[l.Link.ID] = sh
	return nil
}

// unshapeLocked снимает только своё: CAKE корнем и IFB демона. Чужую
// очередь на интерфейсе (настроенную вручную) канал без SQM не трогает.
func (s *System) unshapeLocked(ctx context.Context, i int, l LinkSpec) error {
	delete(s.shaping, l.Link.ID)
	_, ours := cakeRate(ctx, l.Link.Interface)
	if _, err := netlink.LinkByName(ifbName(i)); err == nil {
		ours = true
	}
	if !ours {
		return nil
	}
	_ = runTc(ctx, renderShapingRemove(l.Link.Interface), true)
	if ifb, err := netlink.LinkByName(ifbName(i)); err == nil {
		if err := netlink.LinkDel(ifb); err != nil {
			return fmt.Errorf("dataplane: delete %s: %w", ifbName(i), err)
		}
	}
	return nil
}

func (s *System) SetShaping(ctx context.Context, shaping []Shaping) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.up {
		return errors.New("dataplane: not set up")
	}
	var errs []error
	for _, sh := range shaping {
		i := s.linkIndexLocked(sh.Link)
		if i < 0 || !s.spec.Links[i].SQM {
			continue
		}
		l := s.spec.Links[i]
		prev, ok := s.shaping[sh.Link]
		if ok && prev == sh {
			continue
		}
		if _, there := cakeRate(ctx, l.Link.Interface); !ok || !there {
			// Интерфейс пересоздан (очереди ушли вместе с ним) — ставим заново.
			s.shaping[sh.Link] = sh
			if err := s.shapeLocked(ctx, i, l); err != nil {
				errs = append(errs, err)
			}
			continue
		}
		if err := runTc(ctx, renderShapingRates(l.Link.Interface, ifbName(i), sh), false); err != nil {
			errs = append(errs, fmt.Errorf("dataplane: rates on %s: %w", l.Link.Interface, err))
			continue
		}
		s.shaping[sh.Link] = sh
	}
	return errors.Join(errs...)
}

// repairShapingLocked — очереди каналов, чей интерфейс пересоздан или
// потерял их, ставятся заново с последней скоростью.
func (s *System) repairShapingLocked(ctx context.Context) error {
	var errs []error
	for i, l := range s.spec.Links {
		if !l.SQM {
			continue
		}
		if _, ok := cakeRate(ctx, l.Link.Interface); ok {
			continue
		}
		if _, err := netlink.LinkByName(l.Link.Interface); err != nil {
			continue // интерфейса нет — нечего чинить, канал непригоден
		}
		if err := s.shapeLocked(ctx, i, l); err != nil {
			errs = append(errs, err)
		} else {
			s.log.Info("dataplane: link queues restored", "link", l.Link.ID)
		}
	}
	return errors.Join(errs...)
}

func (s *System) linkIndexLocked(id model.LinkID) int {
	for i, l := range s.spec.Links {
		if l.Link.ID == id {
			return i
		}
	}
	return -1
}
