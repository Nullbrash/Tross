package daemon

import (
	"context"
	"io"
	"log/slog"
	"net/netip"
	"testing"
	"time"

	"tross/core/event"
	"tross/core/model"
	"tross/internal/devices"
	"tross/internal/store"
)

func TestDHCPReservationsAndForeignServer(t *testing.T) {
	ctx := context.Background()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	cfg := exampleCfg(t)
	cfg.Daemon.DryRun = false
	cfg.LAN.DHCP.Enabled, cfg.LAN.DHCP.Dir, cfg.LAN.DHCP.Unit = true, t.TempDir(), "none"
	st, _ := store.Open("", store.DefaultRetention())
	defer st.Close()
	svc, err := devices.New(ctx, devices.Options{Store: st, Log: log})
	if err != nil {
		t.Fatal(err)
	}
	bus := event.NewBus()
	evs, unsub := bus.Subscribe(4, event.TopicDHCP)
	defer unsub()
	s := newDHCPService(cfg, svc.Registry(), log, bus)
	if s == nil {
		t.Fatal("dhcp service not created")
	}
	now := time.Now()
	obs := func(mac model.MAC, ip string, at time.Time) {
		if err := svc.Observe(ctx, devices.Observation{MAC: mac, IP: netip.MustParseAddr(ip), At: at}); err != nil {
			t.Fatal(err)
		}
	}
	phone, phone2 := model.MAC{0xa6, 0, 0, 0, 0, 1}, model.MAC{0xda, 0, 0, 0, 0, 2}
	obs(phone, "192.168.10.120", now.Add(-time.Hour))
	obs(phone2, "192.168.10.121", now)
	obs(model.MAC{0, 3, 0x93, 0, 0, 3}, "192.168.10.130", now.Add(-40*24*time.Hour)) // давно не было
	obs(model.MAC{0, 3, 0x93, 0, 0, 4}, "192.168.20.5", now)                         // вне сети раздачи
	if _, err := svc.Merge(ctx, "dev-a60000000001", "dev-da0000000002"); err != nil {
		t.Fatal(err)
	}
	rs := s.reservations()
	if len(rs) != 1 || len(rs[0].MACs) != 2 || rs[0].Addr != netip.MustParseAddr("192.168.10.121") {
		t.Fatalf("reservations %+v", rs)
	}
	if !dhcpServiceIsNilInDryRun(t) {
		t.Error("dry run must not manage dnsmasq")
	}

	// Ответ своего сервера — не событие; чужого — событие и запись, повтор
	// в течение часа — без нового события.
	s.onServer(cfg.LAN.DHCP.Gateway, model.MAC{2, 0, 0, 0, 0, 1})
	router := netip.MustParseAddr("192.168.10.254")
	s.onServer(router, model.MAC{0x10, 0, 0, 0, 0, 1})
	s.onServer(router, model.MAC{0x10, 0, 0, 0, 0, 1})
	select {
	case e := <-evs:
		if e.Data.(event.DHCPEvent).Server != router.String() {
			t.Errorf("event %+v", e)
		}
	case <-time.After(time.Second):
		t.Fatal("no event about the router's DHCP")
	}
	select {
	case e := <-evs:
		t.Errorf("repeated event %+v", e)
	case <-time.After(100 * time.Millisecond):
	}
	stt := s.status(ctx)
	if len(stt.Foreign) != 1 || stt.Foreign[0].Server != router || stt.Reservations != 1 || stt.Running {
		t.Errorf("status %+v", stt)
	}
}

func dhcpServiceIsNilInDryRun(t *testing.T) bool {
	cfg := exampleCfg(t)
	cfg.LAN.DHCP.Enabled, cfg.Daemon.DryRun = true, true
	return newDHCPService(cfg, nil, nil, nil) == nil
}
