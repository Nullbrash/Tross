package devices

import (
	"net/netip"
	"slices"
	"testing"
	"time"

	"tross/core/model"
)

var t0 = time.Date(2026, 1, 10, 12, 0, 0, 0, time.UTC)

func mac(t *testing.T, s string) model.MAC {
	t.Helper()
	m, err := model.ParseMAC(s)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func observe(t *testing.T, r *Registry, o Observation) Change {
	t.Helper()
	ch, err := r.Observe(o)
	if err != nil {
		t.Fatal(err)
	}
	return ch
}

func TestVendor(t *testing.T) {
	cases := map[string]string{
		"00:03:93:00:00:01": "Apple", // MA-L
		"b8:27:eb:12:34:56": "Raspberry Pi Foundation",
		"02:03:93:00:00:01": "", // случайный MAC — префикс ничего не значит
		"00:00:00:00:00:00": "",
	}
	for m, want := range cases {
		if got := Vendor(mac(t, m)); got != want {
			t.Errorf("Vendor(%s) = %q, want %q", m, got, want)
		}
	}
	// Префикс MA-S длиннее MA-L, под которым он лежит: берётся самый длинный.
	if len(ouiList) == 0 {
		t.Fatal("OUI list is empty")
	}
	var mas ouiEntry
	for _, e := range ouiList {
		if e.bits == 36 {
			mas = e
			break
		}
	}
	var m model.MAC
	v := mas.prefix << 12
	for i := 5; i >= 0; i-- {
		m[i], v = byte(v), v>>8
	}
	if m.IsRandomized() {
		t.Skip("first MA-S block is locally administered")
	}
	if got := Vendor(m); got != mas.name {
		t.Errorf("MA-S %s: %q, want %q", m, got, mas.name)
	}
}

func TestGuessType(t *testing.T) {
	cases := []struct {
		h    model.DeviceHints
		want model.DeviceType
	}{
		{model.DeviceHints{DHCPHostname: "Owners-iPhone"}, model.DeviceTypePhone},
		{model.DeviceHints{DHCPHostname: "Galaxy-S23", DHCPVendorClass: "android-dhcp-14"}, model.DeviceTypePhone},
		{model.DeviceHints{DHCPVendorClass: "android-dhcp-11"}, model.DeviceTypePhone},
		// ТВ на Android присылает тот же класс DHCP, что телефон.
		{model.DeviceHints{DHCPHostname: "BRAVIA-4K-VH2", DHCPVendorClass: "android-dhcp-11"}, model.DeviceTypeTV},
		{model.DeviceHints{DHCPHostname: "DESKTOP-7Q2K1LM", DHCPVendorClass: "MSFT 5.0"}, model.DeviceTypePC},
		{model.DeviceHints{DHCPVendorClass: "MSFT 5.0"}, model.DeviceTypePC},
		{model.DeviceHints{DHCPHostname: "PS5-123"}, model.DeviceTypeConsole},
		{model.DeviceHints{Vendor: "Sony Interactive Entertainment"}, model.DeviceTypeConsole},
		{model.DeviceHints{DHCPHostname: "ESP_3A1B2C"}, model.DeviceTypeSmartHome},
		{model.DeviceHints{Vendor: "Espressif"}, model.DeviceTypeSmartHome},
		{model.DeviceHints{DHCPHostname: "raspberrypi"}, model.DeviceTypeServer},
		{model.DeviceHints{SSDPServer: "Linux/4.4 UPnP/1.0 webOS/1.0"}, model.DeviceTypeTV},
		{model.DeviceHints{MDNSModel: "MacBookPro18,3", DHCPHostname: "anything"}, model.DeviceTypePC},
		{model.DeviceHints{MDNSName: "Kitchen-TV.local"}, model.DeviceTypeTV},
		// Не ловить подстроки: «Ernest», «VivoBook», «Pixelbook».
		{model.DeviceHints{DHCPHostname: "Ernest-laptop-x"}, model.DeviceTypeOther},
		{model.DeviceHints{DHCPHostname: "VivoBook-15"}, model.DeviceTypeOther},
		{model.DeviceHints{DHCPHostname: "Pixelbook"}, model.DeviceTypeOther},
		{model.DeviceHints{}, model.DeviceTypeOther},
	}
	for _, c := range cases {
		if got := GuessType(c.h); got != c.want {
			t.Errorf("GuessType(%+v) = %s, want %s", c.h, got, c.want)
		}
	}
}

func TestSuggestName(t *testing.T) {
	if got := SuggestName(model.DeviceHints{MDNSName: "Kitchen-TV.local", DHCPHostname: "android-1234"}); got != "Kitchen-TV" {
		t.Errorf("mdns first: %q", got)
	}
	if got := SuggestName(model.DeviceHints{MDNSName: "iPhone.local", DHCPHostname: "Owners-iPhone"}); got != "Owners-iPhone" {
		t.Errorf("generic mdns skipped: %q", got)
	}
	if got := SuggestName(model.DeviceHints{DHCPHostname: "localhost"}); got != "" {
		t.Errorf("generic only: %q", got)
	}
}

func TestProfiles(t *testing.T) {
	for _, c := range []struct {
		t         model.DeviceType
		confirmed bool
		want      model.UPnPLevel
	}{
		{model.DeviceTypeConsole, true, model.UPnPAllow},
		{model.DeviceTypePC, true, model.UPnPAsk},
		{model.DeviceTypeTV, true, model.UPnPDeny},
		{model.DeviceTypeSmartHome, true, model.UPnPDeny},
		// Угаданный тип ничего не ослабляет.
		{model.DeviceTypeConsole, false, model.UPnPDeny},
		{model.DeviceTypePC, false, model.UPnPDeny},
	} {
		if got := DefaultUPnP(c.t, c.confirmed); got != c.want {
			t.Errorf("DefaultUPnP(%s, %v) = %s, want %s", c.t, c.confirmed, got, c.want)
		}
	}
	d := model.Device{Type: model.DeviceTypeConsole, TypeConfirmed: true, UPnP: model.UPnPDeny}
	if EffectiveUPnP(d) != model.UPnPDeny {
		t.Error("user level must win over the profile")
	}
}

func TestObserveNewAndKnown(t *testing.T) {
	r := NewRegistry()
	m := mac(t, "00:03:93:aa:bb:cc")
	ip := netip.MustParseAddr("192.168.10.20")
	ch := observe(t, r, Observation{MAC: m, IP: ip, Hints: model.DeviceHints{DHCPHostname: "MacBook-Work"}, At: t0})
	if !ch.New || !ch.Changed || ch.Device.ID != "dev-000393aabbcc" {
		t.Fatalf("new: %+v", ch)
	}
	if ch.Device.Hints.Vendor != "Apple" || ch.Device.Type != model.DeviceTypePC || ch.Device.Addr != ip {
		t.Errorf("hints/type/addr: %+v", ch.Device)
	}
	ch = observe(t, r, Observation{MAC: m, IP: ip, At: t0.Add(time.Minute)})
	if ch.New || ch.Changed || !ch.Device.LastSeen.Equal(t0.Add(time.Minute)) {
		t.Errorf("seen again: %+v", ch)
	}
	if d, ok := r.ByIP(ip); !ok || d.ID != ch.Device.ID {
		t.Error("ByIP")
	}
	// Адрес перешёл к другому устройству — у прежнего снимается.
	m2 := mac(t, "00:03:93:00:00:02")
	ch = observe(t, r, Observation{MAC: m2, IP: ip, At: t0.Add(2 * time.Minute)})
	if len(ch.Others) != 1 || ch.Others[0].Addr.IsValid() {
		t.Errorf("address moved: others %+v", ch.Others)
	}
	if d, _ := r.ByIP(ip); d.ID != ch.Device.ID {
		t.Error("ByIP after move")
	}
	if _, err := r.Observe(Observation{MAC: mac(t, "01:00:5e:00:00:fb"), At: t0}); err == nil {
		t.Error("multicast MAC accepted")
	}
}

func TestUserTypeIsKept(t *testing.T) {
	r := NewRegistry()
	m := mac(t, "00:03:93:aa:bb:cc")
	d := observe(t, r, Observation{MAC: m, At: t0}).Device
	console := model.DeviceTypeConsole
	d, err := r.Update(d.ID, Edit{Type: &console})
	if err != nil || !d.TypeConfirmed || EffectiveUPnP(d) != model.UPnPAllow {
		t.Fatalf("update: %+v %v", d, err)
	}
	ch := observe(t, r, Observation{MAC: m, Hints: model.DeviceHints{DHCPHostname: "Owners-iPhone"}, At: t0.Add(time.Minute)})
	if ch.Device.Type != model.DeviceTypeConsole {
		t.Errorf("user type overwritten by guess: %s", ch.Device.Type)
	}
	empty := model.DeviceType("")
	d, _ = r.Update(d.ID, Edit{Type: &empty})
	if d.TypeConfirmed || d.Type != model.DeviceTypePhone {
		t.Errorf("reset to guess: %+v", d)
	}
	bad := model.UPnPLevel("maybe")
	if _, err := r.Update(d.ID, Edit{UPnP: &bad}); err == nil {
		t.Error("invalid upnp level accepted")
	}
}

// Телефон сменил случайный MAC: новая запись предполагает прежнюю; объединяет
// только пользователь.
func TestRandomMACChange(t *testing.T) {
	r := NewRegistry()
	old := observe(t, r, Observation{MAC: mac(t, "a6:11:22:33:44:55"), IP: netip.MustParseAddr("192.168.10.30"),
		Hints: model.DeviceHints{DHCPHostname: "Galaxy-S23-Home", DHCPParams: "1,3,6,15,26,28,51,58,59,43"}, At: t0}).Device
	name := "Телефон"
	old, _ = r.Update(old.ID, Edit{Name: &name})

	// Сначала ARP без подсказок, имя — следом.
	nm := mac(t, "da:99:88:77:66:55")
	ch := observe(t, r, Observation{MAC: nm, At: t0.Add(5 * time.Second)})
	if !ch.New || ch.Device.MaybeSame != nil {
		t.Fatalf("no hints yet: %+v", ch.Device.MaybeSame)
	}
	ch = observe(t, r, Observation{MAC: nm, IP: netip.MustParseAddr("192.168.10.31"),
		Hints: model.DeviceHints{DHCPHostname: "Galaxy-S23-Home", DHCPParams: "1,3,6,15,26,28,51,58,59,43"}, At: t0.Add(8 * time.Second)})
	s := ch.Device.MaybeSame
	if s == nil || s.ID != old.ID || !slices.Contains(s.Reasons, "dhcp_hostname") {
		t.Fatalf("suggestion: %+v", s)
	}
	// Сам реестр не объединяет: прежняя запись цела, настройки на месте.
	if _, ok := r.Get(old.ID); !ok || len(r.List()) != 2 {
		t.Fatal("registry merged on its own")
	}

	merged, others, err := r.Merge(old.ID, ch.Device.ID)
	if err != nil {
		t.Fatal(err)
	}
	if merged.Name != "Телефон" || len(merged.MACs) != 2 || merged.Addr != netip.MustParseAddr("192.168.10.31") || merged.MaybeSame != nil {
		t.Errorf("merged: %+v", merged)
	}
	if !slices.Contains(merged.Aliases, ch.Device.ID) || len(others) != 0 || len(r.List()) != 1 {
		t.Errorf("aliases %v, others %v, list %d", merged.Aliases, others, len(r.List()))
	}
	// Ссылки на влитую запись и на любой её MAC ведут к итоговой.
	for _, ref := range []string{ch.Device.ID, nm.String(), old.ID} {
		if d, ok := r.Resolve(ref); !ok || d.ID != old.ID {
			t.Errorf("Resolve(%s)", ref)
		}
	}
	if d, ok := r.ByIP(netip.MustParseAddr("192.168.10.31")); !ok || d.ID != old.ID {
		t.Error("ByIP after merge")
	}
	if _, _, err := r.Merge(old.ID, old.ID); err != ErrSame {
		t.Errorf("self merge: %v", err)
	}
}

// Два одинаковых телефона в доме: предположение снимается, когда оба в сети.
func TestTwinPhonesNotSame(t *testing.T) {
	r := NewRegistry()
	h := model.DeviceHints{DHCPHostname: "Redmi-Note-12", DHCPParams: "1,3,6"}
	a := observe(t, r, Observation{MAC: mac(t, "a6:00:00:00:00:01"), Hints: h, At: t0}).Device
	b := observe(t, r, Observation{MAC: mac(t, "a6:00:00:00:00:02"), Hints: h, At: t0.Add(30 * time.Second)})
	if b.Device.MaybeSame == nil || b.Device.MaybeSame.ID != a.ID {
		t.Fatalf("expected a suggestion first: %+v", b.Device.MaybeSame)
	}
	ch := observe(t, r, Observation{MAC: a.MACs[0], At: t0.Add(time.Minute)})
	if len(ch.Others) != 1 || ch.Others[0].ID != b.Device.ID || ch.Others[0].MaybeSame != nil {
		t.Fatalf("suggestion not withdrawn: %+v", ch.Others)
	}
	// Подсказка у молодой записи не возвращает снятое предположение.
	ch = observe(t, r, Observation{MAC: b.Device.MACs[0], Hints: model.DeviceHints{MDNSModel: "x"}, At: t0.Add(90 * time.Second)})
	if ch.Device.MaybeSame != nil {
		t.Errorf("suggestion came back: %+v", ch.Device.MaybeSame)
	}
}

func TestSuggestionRules(t *testing.T) {
	cases := []struct {
		name     string
		old, new model.DeviceHints
		same     bool
	}{
		{"different names", model.DeviceHints{DHCPHostname: "Galaxy-S23-A"}, model.DeviceHints{DHCPHostname: "Galaxy-S23-B"}, false},
		{"generic name only", model.DeviceHints{DHCPHostname: "iPhone"}, model.DeviceHints{DHCPHostname: "iPhone"}, false},
		{"fingerprint only", model.DeviceHints{DHCPParams: "1,3,6"}, model.DeviceHints{DHCPParams: "1,3,6"}, false},
		{"mdns name", model.DeviceHints{MDNSName: "Owners-iPad.local"}, model.DeviceHints{MDNSName: "owners-ipad.local"}, true},
		{"duid client-id", model.DeviceHints{DHCPClientID: "ff00010001abcdef"}, model.DeviceHints{DHCPClientID: "FF00010001ABCDEF"}, true},
		{"generic + other name differs", model.DeviceHints{DHCPHostname: "iPhone", MDNSName: "A.local"}, model.DeviceHints{DHCPHostname: "Owners-iPhone", MDNSName: "A.local"}, true},
	}
	for _, c := range cases {
		r := NewRegistry()
		old := observe(t, r, Observation{MAC: mac(t, "a6:00:00:00:00:01"), Hints: c.old, At: t0}).Device
		got := observe(t, r, Observation{MAC: mac(t, "a6:00:00:00:00:02"), Hints: c.new, At: t0.Add(time.Minute)}).Device.MaybeSame
		if (got != nil && got.ID == old.ID) != c.same {
			t.Errorf("%s: suggestion %+v, want same=%v", c.name, got, c.same)
		}
	}
}

func TestSuggestionWindowAndTie(t *testing.T) {
	r := NewRegistry()
	h := model.DeviceHints{DHCPHostname: "Work-Laptop"}
	observe(t, r, Observation{MAC: mac(t, "a6:00:00:00:00:01"), Hints: h, At: t0})
	got := observe(t, r, Observation{MAC: mac(t, "a6:00:00:00:00:02"), Hints: h, At: t0.Add(SameWindow + time.Hour)}).Device
	if got.MaybeSame != nil {
		t.Errorf("too old a record suggested: %+v", got.MaybeSame)
	}
	// Две пропавшие записи с тем же именем — какую предложить, неясно.
	r = NewRegistry()
	observe(t, r, Observation{MAC: mac(t, "a6:00:00:00:00:01"), Hints: h, At: t0})
	observe(t, r, Observation{MAC: mac(t, "a6:00:00:00:00:02"), At: t0.Add(time.Hour)})
	// Вторая запись получает то же имя позже, когда уже не молода.
	observe(t, r, Observation{MAC: mac(t, "a6:00:00:00:00:02"), Hints: h, At: t0.Add(2 * time.Hour)})
	got = observe(t, r, Observation{MAC: mac(t, "a6:00:00:00:00:03"), Hints: h, At: t0.Add(3 * time.Hour)}).Device
	if got.MaybeSame != nil {
		t.Errorf("tie must give no suggestion: %+v", got.MaybeSame)
	}
}

func TestDismissAndForget(t *testing.T) {
	r := NewRegistry()
	h := model.DeviceHints{MDNSName: "Living-Room.local"}
	old := observe(t, r, Observation{MAC: mac(t, "a6:00:00:00:00:01"), Hints: h, At: t0}).Device
	nw := observe(t, r, Observation{MAC: mac(t, "a6:00:00:00:00:02"), Hints: h, At: t0.Add(time.Minute)}).Device
	if nw.MaybeSame == nil {
		t.Fatal("no suggestion")
	}
	d, err := r.Dismiss(nw.ID)
	if err != nil || d.MaybeSame != nil || !slices.Contains(d.NotSame, old.ID) {
		t.Fatalf("dismiss: %+v %v", d, err)
	}
	// Новая подсказка не возвращает отклонённое.
	d = observe(t, r, Observation{MAC: nw.MACs[0], Hints: model.DeviceHints{DHCPParams: "1"}, At: t0.Add(2 * time.Minute)}).Device
	if d.MaybeSame != nil {
		t.Errorf("dismissed suggestion came back: %+v", d.MaybeSame)
	}
	if err := r.Forget(old.ID); err != nil {
		t.Fatal(err)
	}
	if _, ok := r.ByMAC(old.MACs[0]); ok {
		t.Error("forgotten device still found by MAC")
	}
	if ch := observe(t, r, Observation{MAC: old.MACs[0], At: t0.Add(time.Hour)}); !ch.New {
		t.Error("forgotten device must come back as new")
	}
}

func TestLoadRoundTrip(t *testing.T) {
	r := NewRegistry()
	observe(t, r, Observation{MAC: mac(t, "00:03:93:aa:bb:cc"), IP: netip.MustParseAddr("192.168.10.5"), At: t0})
	saved := r.List()
	r2 := NewRegistry()
	r2.Load(saved)
	if d, ok := r2.ByIP(netip.MustParseAddr("192.168.10.5")); !ok || d.ID != saved[0].ID {
		t.Error("ByIP after Load")
	}
	if ch := observe(t, r2, Observation{MAC: saved[0].MACs[0], At: t0.Add(time.Minute)}); ch.New {
		t.Error("loaded device seen as new")
	}
}

// Предположение третьей записи о влитой переходит на итоговую.
func TestMergeRepointsSuggestions(t *testing.T) {
	r := NewRegistry()
	a := observe(t, r, Observation{MAC: mac(t, "00:03:93:00:00:01"), At: t0}).Device
	b := observe(t, r, Observation{MAC: mac(t, "a6:00:00:00:00:02"), Hints: model.DeviceHints{MDNSName: "Tablet.local"}, At: t0.Add(time.Hour)}).Device
	c := observe(t, r, Observation{MAC: mac(t, "a6:00:00:00:00:03"), Hints: model.DeviceHints{MDNSName: "Tablet.local"}, At: t0.Add(2 * time.Hour)}).Device
	if c.MaybeSame == nil || c.MaybeSame.ID != b.ID {
		t.Fatalf("setup: %+v", c.MaybeSame)
	}
	_, others, err := r.Merge(a.ID, b.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(others) != 1 || others[0].ID != c.ID || others[0].MaybeSame.ID != a.ID {
		t.Fatalf("others: %+v", others)
	}
	if _, _, err := r.Merge(a.ID, "dev-missing"); err != ErrNotFound {
		t.Errorf("missing src: %v", err)
	}
}
