package daemon

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	coredevices "tross/core/devices"
	"tross/core/model"
	"tross/core/profile"
	"tross/internal/api"
	"tross/internal/config"
	"tross/internal/dataplane"
	"tross/internal/devices"
	"tross/internal/store"
)

func ref(t *testing.T, s string) coredevices.Ref {
	t.Helper()
	r, err := coredevices.ParseRef(s)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// deviceCfg — пример конфига с правилом, режимом DNS и пробросом по MAC
// телефона и с правилом по IP.
func deviceCfg(t *testing.T) *config.Config {
	t.Helper()
	cfg := exampleCfg(t)
	cfg.Classify.Rules = []config.ClassifyRule{
		{Name: "phone-bulk", Class: model.ClassBulk, Devices: []coredevices.Ref{ref(t, "a6:00:00:00:00:01")}},
		{Name: "pc-bulk", Class: model.ClassBulk, Devices: []coredevices.Ref{ref(t, "192.168.10.20")}},
		{Name: "anyone", Class: model.ClassBulk},
	}
	for i := range cfg.Classify.Rules {
		cfg.Classify.Rules[i].Ports = []profile.PortRange{{From: 5000 + uint16(i), To: 5000 + uint16(i)}}
	}
	cfg.DNS.Devices = []config.DNSDevice{{Address: ref(t, "a6:00:00:00:00:01"), Mode: model.DNSExempt}}
	cfg.Inbound.Forwards = []config.PortForward{{Name: "phone", Proto: "tcp", Port: profile.PortRange{From: 4000, To: 4000}, To: ref(t, "a6:00:00:00:00:01")}}
	return cfg
}

func TestDeviceBinding(t *testing.T) {
	ctx := context.Background()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	cfg := deviceCfg(t)
	st, _ := store.Open("", store.DefaultRetention())
	defer st.Close()
	svc, err := devices.New(ctx, devices.Options{Store: st, Log: log})
	if err != nil {
		t.Fatal(err)
	}
	dp := dataplane.NewFake(log)
	b := newDeviceBinder(cfg, svc.Registry(), dp, log)

	// Телефона ещё нет: правило по MAC — с пустым множеством (не совпадает
	// ни с кем), проброс — без адреса, правило по IP — сразу с адресом.
	spec, err := dataplaneSpec(cfg, b)
	if err != nil {
		t.Fatal(err)
	}
	r0 := ruleNamed(t, spec, "phone-bulk")
	r1 := ruleNamed(t, spec, "pc-bulk")
	if r0.SourceSet != dataplane.DeviceSet(0) || len(r0.Sources) != 0 || r1.SourceSet != dataplane.DeviceSet(1) || len(r1.Sources) != 1 {
		t.Fatalf("rules: %+v / %+v", r0, r1)
	}
	if r2 := ruleNamed(t, spec, "anyone"); r2.SourceSet != "" {
		t.Errorf("rule without devices got a set: %+v", r2)
	}
	if spec.Forwards[0].To.IsValid() || len(spec.DNS.Devices) != 0 {
		t.Errorf("unknown phone: forward %v, dns %v", spec.Forwards[0].To, spec.DNS.Devices)
	}

	// Телефон появился: адрес — во множество правила, в режимы DNS и в проброс.
	phone := netip.MustParseAddr("192.168.10.30")
	svc.Observe(ctx, devices.Observation{MAC: model.MAC{0xa6, 0, 0, 0, 0, 1}, IP: phone, At: time.Now()})
	bd := b.binding()
	if !slices.Equal(bd.Rules[dataplane.DeviceSet(0)], []netip.Addr{phone}) || bd.DNS[phone] != model.DNSExempt || bd.Forwards["phone"] != phone {
		t.Fatalf("binding %+v", bd)
	}
	// Режим DNS, заданный через API устройству вне конфига, — тоже в привязке.
	tv := netip.MustParseAddr("192.168.10.40")
	svc.Observe(ctx, devices.Observation{MAC: model.MAC{0, 3, 0x93, 0, 0, 2}, IP: tv, At: time.Now()})
	block := model.DNSBlock
	a := &devicesAPI{svc: svc, binder: b, def: model.DNSRedirect}
	if _, err := a.Update(ctx, "dev-000393000002", api.DeviceEdit{DNSMode: &block}); err != nil {
		t.Fatal(err)
	}
	if b.binding().DNS[tv] != model.DNSBlock {
		t.Errorf("api dns mode not bound: %v", b.binding().DNS)
	}
	// У телефона режим DNS — из конфига: через API не меняется.
	if _, err := a.Update(ctx, "dev-a60000000001", api.DeviceEdit{DNSMode: &block}); !errors.Is(err, api.ErrConfigured) {
		t.Errorf("config dns mode changed through api: %v", err)
	}
	list := a.List()
	byID := map[string]api.Device{}
	for _, d := range list {
		byID[d.ID] = d
	}
	if d := byID["dev-a60000000001"]; d.DNSModeFrom != "config" || d.DNSModeEffective != model.DNSExempt || !d.Online {
		t.Errorf("phone dto %+v", d)
	}
	if d := byID["dev-000393000002"]; d.DNSModeFrom != "device" || d.UPnPEffective != model.UPnPDeny {
		t.Errorf("tv dto %+v", d)
	}
	if _, err := a.Get(ctx, "dev-missing"); !errors.Is(err, api.ErrNoDevice) {
		t.Errorf("missing device: %v", err)
	}
	bad := model.DeviceType("fridge")
	if _, err := a.Update(ctx, "dev-000393000002", api.DeviceEdit{Type: &bad}); err == nil || errors.Is(err, api.ErrNoDevice) {
		t.Errorf("bad type: %v", err)
	}

	// Применение: только при изменениях.
	runCtx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() { b.run(runCtx); close(done) }()
	b.changed()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && dp.Binding().Forwards["phone"] != phone {
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	<-done
	if dp.Binding().Forwards["phone"] != phone {
		t.Fatalf("binding not applied: %+v", dp.Binding())
	}

	// Классификатор узнаёт телефон по MAC из правила.
	cat, _ := serviceCatalog(cfg)
	cls, err := newClassifier(cfg, cat, nil, b.refs)
	if err != nil {
		t.Fatal(err)
	}
	f := model.Flow{Src: netip.AddrPortFrom(phone, 40000), Dst: netip.MustParseAddrPort("203.0.113.1:5000"), Proto: model.ProtoTCP}
	if c := cls.Classify(f); !strings.HasSuffix(c.Source, "phone-bulk") {
		t.Errorf("phone rule by MAC: %+v", c)
	}
	f.Src = netip.AddrPortFrom(tv, 40000)
	if c := cls.Classify(f); strings.HasSuffix(c.Source, "phone-bulk") {
		t.Errorf("another device matched the phone rule: %+v", c)
	}
}

func ruleNamed(t *testing.T, spec dataplane.Spec, name string) dataplane.ClassRule {
	t.Helper()
	for _, r := range spec.Classify.Rules {
		if r.Name == name {
			return r
		}
	}
	t.Fatalf("no rule %s", name)
	return dataplane.ClassRule{}
}
