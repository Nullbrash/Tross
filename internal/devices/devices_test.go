package devices

import (
	"context"
	"io"
	"log/slog"
	"net/netip"
	"testing"
	"time"

	coredevices "tross/core/devices"
	"tross/core/event"
	"tross/core/model"
	"tross/internal/store"
)

func newService(t *testing.T, opts Options) (*Service, *store.SQLite) {
	t.Helper()
	st, err := store.Open("", store.DefaultRetention())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	opts.Store, opts.Log = st, slog.New(slog.NewTextHandler(io.Discard, nil))
	s, err := New(context.Background(), opts)
	if err != nil {
		t.Fatal(err)
	}
	return s, st
}

func TestServiceObserveSaveAndEvents(t *testing.T) {
	ctx := context.Background()
	bus := event.NewBus()
	evs, unsub := bus.Subscribe(16, event.TopicDeviceNew, event.TopicDeviceSame)
	defer unsub()
	changes := 0
	var probed []string
	s, st := newService(t, Options{Bus: bus, NotifyNew: true, OnChange: func() { changes++ }, Probe: func(d model.Device) { probed = append(probed, d.ID) }})

	now := time.Now()
	m := model.MAC{0xa6, 0, 0, 0, 0, 1}
	ip := netip.MustParseAddr("192.168.10.30")
	if err := s.Observe(ctx, Observation{MAC: m, Hints: model.DeviceHints{DHCPHostname: "Galaxy-S23-Home"}, At: now}); err != nil {
		t.Fatal(err)
	}
	// Новое устройство сохранено сразу, событие — с подсказкой имени.
	if ds, _ := st.Devices(ctx); len(ds) != 1 {
		t.Fatalf("saved %d devices", len(ds))
	}
	e := (<-evs).Data.(event.DeviceEvent)
	if e.ID != "dev-a60000000001" || e.Name != "Galaxy-S23-Home" || e.Type != model.DeviceTypePhone {
		t.Errorf("event %+v", e)
	}
	if len(probed) != 0 || changes != 0 {
		t.Errorf("no address yet: probed %v, changes %d", probed, changes)
	}
	// Адрес пришёл — привязка правил пересобирается, имя спрашивается один раз.
	s.Observe(ctx, Observation{MAC: m, IP: ip, At: now.Add(time.Second)})
	s.Observe(ctx, Observation{MAC: m, IP: ip, At: now.Add(time.Minute)})
	if changes != 1 || len(probed) != 1 {
		t.Errorf("changes %d, probed %v", changes, probed)
	}
	// «Последний раз в сети» и история адресов — пачкой при Flush.
	if ds, _ := st.Devices(ctx); !ds[0].LastSeen.Equal(now.Add(time.Second)) {
		t.Errorf("last seen saved before flush: %v", ds[0].LastSeen)
	}
	s.Flush(ctx)
	if ds, _ := st.Devices(ctx); !ds[0].LastSeen.Equal(now.Add(time.Minute)) {
		t.Errorf("last seen after flush: %v", ds[0].LastSeen)
	}
	addrs, _ := st.DeviceAddrs(ctx, "dev-a60000000001")
	if len(addrs) != 1 || addrs[0].IP != ip || !addrs[0].First.Equal(now.Add(time.Second).Truncate(time.Millisecond)) {
		t.Errorf("addrs %+v", addrs)
	}

	// Смена случайного MAC: событие device.same, объединение — по команде.
	m2 := model.MAC{0xda, 0, 0, 0, 0, 2}
	s.Observe(ctx, Observation{MAC: m2, IP: netip.MustParseAddr("192.168.10.31"), Hints: model.DeviceHints{DHCPHostname: "Galaxy-S23-Home"}, At: now.Add(2 * time.Minute)})
	<-evs // device.new
	same := (<-evs)
	if same.Topic != event.TopicDeviceSame || same.Data.(event.DeviceEvent).SameAs != "dev-a60000000001" {
		t.Fatalf("same event %+v", same)
	}
	d, err := s.Merge(ctx, "dev-a60000000001", "dev-da0000000002")
	if err != nil || len(d.MACs) != 2 {
		t.Fatalf("merge %+v %v", d, err)
	}
	addrs, _ = s.Addrs(ctx, "dev-a60000000001")
	if len(addrs) != 2 {
		t.Errorf("history after merge %+v", addrs)
	}
	if ds, _ := st.Devices(ctx); len(ds) != 1 {
		t.Errorf("stored after merge: %d", len(ds))
	}

	// Правка и забвение.
	name := "Телефон"
	if d, err := s.Update(ctx, d.ID, coredevices.Edit{Name: &name}); err != nil || d.Name != name {
		t.Fatalf("update %+v %v", d, err)
	}
	if err := s.Forget(ctx, d.ID); err != nil {
		t.Fatal(err)
	}
	if ds, _ := st.Devices(ctx); len(ds) != 0 {
		t.Errorf("forgotten device stored")
	}
}

func TestServiceLimit(t *testing.T) {
	ctx := context.Background()
	s, _ := newService(t, Options{MaxDevices: 2})
	for i := range 3 {
		err := s.Observe(ctx, Observation{MAC: model.MAC{0xa6, 0, 0, 0, 0, byte(i + 1)}, At: time.Now()})
		if (i < 2) != (err == nil) {
			t.Errorf("device %d: %v", i, err)
		}
	}
	// Известное устройство при полном реестре — учитывается.
	if err := s.Observe(ctx, Observation{MAC: model.MAC{0xa6, 0, 0, 0, 0, 1}, At: time.Now()}); err != nil {
		t.Error(err)
	}
}

func TestServiceLoadsSaved(t *testing.T) {
	ctx := context.Background()
	st, _ := store.Open("", store.DefaultRetention())
	defer st.Close()
	_ = st.SaveDevices(ctx, []model.Device{{ID: "dev-a60000000001", MACs: []model.MAC{{0xa6, 0, 0, 0, 0, 1}}, Name: "TV"}})
	s, err := New(ctx, Options{Store: st, Log: slog.New(slog.NewTextHandler(io.Discard, nil))})
	if err != nil {
		t.Fatal(err)
	}
	if d, ok := s.Registry().ByMAC(model.MAC{0xa6, 0, 0, 0, 0, 1}); !ok || d.Name != "TV" {
		t.Errorf("not loaded: %+v", d)
	}
}

func TestServicePlaceholderLoggedNotStored(t *testing.T) {
	ctx := context.Background()
	s, st := newService(t, Options{})
	o := Observation{MAC: model.MAC{0x02}, IP: netip.MustParseAddr("192.168.10.77"), At: time.Now()}
	for range 3 {
		_ = s.Observe(ctx, o)
	}
	if ds, _ := st.Devices(ctx); len(ds) != 0 || len(s.List()) != 0 {
		t.Errorf("placeholder stored: %v", ds)
	}
	if len(s.placeholder) != 1 {
		t.Errorf("placeholder log state %v", s.placeholder)
	}
}
