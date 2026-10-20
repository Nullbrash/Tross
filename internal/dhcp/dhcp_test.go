package dhcp

import (
	"context"
	"io"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"tross/core/model"
)

func testConfig(t *testing.T) Config {
	dir := t.TempDir()
	return Config{
		Interface: "lan", Prefix: netip.MustParsePrefix("192.168.10.0/24"),
		First: netip.MustParseAddr("192.168.10.100"), Last: netip.MustParseAddr("192.168.10.249"),
		Gateway: netip.MustParseAddr("192.168.10.1"), Lease: 12 * time.Hour,
		Dir: dir, PIDFile: filepath.Join(dir, "dnsmasq.pid"),
	}
}

func TestRenderConf(t *testing.T) {
	c := testConfig(t)
	got, err := RenderConf(c)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"port=0\n", "interface=lan\n",
		"dhcp-range=192.168.10.100,192.168.10.249,255.255.255.0,43200\n",
		"dhcp-option=option:router,192.168.10.1\n", "dhcp-option=option:dns-server,192.168.10.1\n",
		"dhcp-authoritative\n", "dhcp-hostsfile=" + filepath.Join(c.Dir, "hosts") + "\n",
		"pid-file=" + c.PIDFile + "\n",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("conf lacks %q:\n%s", want, got)
		}
	}
	c.Interface = "lan\ndhcp-range=evil"
	if _, err := RenderConf(c); err == nil {
		t.Error("newline in a value accepted")
	}
	c = testConfig(t)
	c.Gateway = netip.MustParseAddr("10.0.0.1")
	if _, err := RenderConf(c); err == nil {
		t.Error("gateway outside the network accepted")
	}
}

func TestRenderHostsAndLeases(t *testing.T) {
	a := model.MAC{0xa6, 0, 0, 0, 0, 1}
	b := model.MAC{0xda, 0, 0, 0, 0, 2}
	got := RenderHosts([]Reservation{
		{MACs: []model.MAC{a, b}, Addr: netip.MustParseAddr("192.168.10.120")},
		{MACs: []model.MAC{{0, 3, 0x93, 0, 0, 3}}, Addr: netip.MustParseAddr("192.168.10.20")},
		{Addr: netip.MustParseAddr("192.168.10.30")},
	})
	want := "00:03:93:00:00:03,192.168.10.20\na6:00:00:00:00:01,da:00:00:00:00:02,192.168.10.120\n"
	if got != want {
		t.Errorf("hosts:\n%s\nwant:\n%s", got, want)
	}
	ls := ParseLeases(strings.NewReader("1767225600 a6:00:00:00:00:01 192.168.10.120 Galaxy-Lab 01:a6:00:00:00:00:01\n" +
		"1767225700 00:03:93:00:00:03 192.168.10.20 * *\nbroken line\n1 zz 1.2.3.4 x\n"))
	if len(ls) != 2 || ls[0].Hostname != "Galaxy-Lab" || ls[0].MAC != a || ls[1].Hostname != "" || ls[1].Expires.Unix() != 1767225700 {
		t.Errorf("leases %+v", ls)
	}
}

func TestManager(t *testing.T) {
	c := testConfig(t)
	c.Unit = "tross-dhcp.service"
	m := NewManager(c, slog.New(slog.NewTextHandler(io.Discard, nil)))
	var calls []string
	m.systemctl = func(_ context.Context, args ...string) error {
		calls = append(calls, strings.Join(args, " "))
		return nil
	}
	rs := []Reservation{{MACs: []model.MAC{{0xa6, 0, 0, 0, 0, 1}}, Addr: netip.MustParseAddr("192.168.10.120")}}
	if err := m.Start(context.Background(), rs); err != nil {
		t.Fatal(err)
	}
	// Конфиг новый — служба перезапускается; файлы на месте.
	if len(calls) != 1 || calls[0] != "restart tross-dhcp.service" {
		t.Errorf("systemctl calls %v", calls)
	}
	if b, _ := os.ReadFile(filepath.Join(c.Dir, "hosts")); string(b) != "a6:00:00:00:00:01,192.168.10.120\n" {
		t.Errorf("hosts file %q", b)
	}
	if fi, err := os.Stat(filepath.Join(c.Dir, "hosts")); err != nil || fi.Mode().Perm()&0o004 == 0 && os.PathSeparator == '/' {
		t.Errorf("hosts file must be world-readable: %v %v", fi.Mode(), err)
	}
	// Тот же конфиг, dnsmasq не запущен — служба поднимается снова.
	if err := m.Start(context.Background(), rs); err != nil || len(calls) != 2 {
		t.Errorf("start again: %v %v", err, calls)
	}
	// Те же закреплённые адреса — ничего не делается; новые — файл и сигнал
	// (процесса нет — ошибка, файл всё равно записан).
	if err := m.SetReservations(rs); err != nil {
		t.Errorf("same reservations: %v", err)
	}
	rs = append(rs, Reservation{MACs: []model.MAC{{0xa6, 0, 0, 0, 0, 2}}, Addr: netip.MustParseAddr("192.168.10.121")})
	if err := m.SetReservations(rs); err == nil {
		t.Error("no dnsmasq to signal, want an error")
	}
	if b, _ := os.ReadFile(filepath.Join(c.Dir, "hosts")); !strings.Contains(string(b), "192.168.10.121") {
		t.Errorf("hosts not rewritten: %q", b)
	}
	if m.Running() {
		t.Error("no pid file, yet running")
	}
	ls, err := m.Leases()
	if err != nil || len(ls) != 0 {
		t.Errorf("no lease file: %v %v", ls, err)
	}
}
