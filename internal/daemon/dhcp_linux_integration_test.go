//go:build linux && integration

// Раздача адресов на стенде: настоящий dnsmasq по конфигу демона,
// закреплённый адрес после объединения записей (смена случайного MAC),
// второй DHCP-сервер в LAN, раздача без демона.
package daemon

import (
	"bytes"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"tross/internal/api"
)

// dhcpc — обмен DHCP из клиента с вымышленным MAC: выданный адрес и сервер.
func dhcpc(t *testing.T, mac, hostname string) (netip.Addr, netip.Addr) {
	t.Helper()
	out, err := inNS("tl-client", labsrvBin(t)+" dhcpc -mac "+mac+" -hostname "+hostname)
	if err != nil {
		t.Fatalf("dhcpc %s: %v %s", mac, err, out)
	}
	f := strings.Fields(out)
	if len(f) != 2 {
		t.Fatalf("dhcpc output %q", out)
	}
	return netip.MustParseAddr(f[0]), netip.MustParseAddr(f[1])
}

func TestDHCPOnStand(t *testing.T) {
	if _, err := os.Stat("/usr/sbin/dnsmasq"); err != nil {
		t.Skip("no dnsmasq")
	}
	dir := "/run/tross-dhcp-itest"
	_ = os.RemoveAll(dir)
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	cfg := classCfg(t)
	d := &cfg.LAN.DHCP
	d.Enabled, d.Range, d.Lease, d.Gateway = true, "192.168.77.100-192.168.77.150", 2*time.Minute, netip.MustParseAddr("192.168.77.1")
	d.Dir, d.PIDFile, d.Unit = dir, filepath.Join(dir, "dnsmasq.pid"), "none"

	stop := startDaemon(t, cfg)
	defer stop()
	conf := filepath.Join(dir, "dnsmasq.conf")
	until(t, 10*time.Second, "dnsmasq config written", func() bool { _, err := os.Stat(conf); return err == nil })
	// Как служба tross-dhcp: dnsmasq сам по себе, с правами по умолчанию
	// (сбрасывает root — закреплённые адреса читает без него).
	if out, err := inNS("tl-tross", "dnsmasq --conf-file="+conf); err != nil {
		t.Fatalf("dnsmasq: %v %s", err, out)
	}
	t.Cleanup(func() { _, _ = inNS("tl-tross", "kill $(cat "+d.PIDFile+")") })

	ip1, server := dhcpc(t, "a6:00:00:00:00:51", "Galaxy-Lab")
	first, last, _ := d.DHCPRange()
	if server != d.Gateway || ip1.Less(first) || last.Less(ip1) {
		t.Fatalf("lease %s from %s", ip1, server)
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		dev, ok := apiDevice(t, cfg, "dev-a60000000051")
		if ok && dev.Addr == ip1 && dev.Hints.DHCPHostname == "Galaxy-Lab" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("device from DHCP with address %s: %v %+v", ip1, ok, dev)
		}
		time.Sleep(250 * time.Millisecond)
	}
	// Тот же телефон со случайным MAC: другой адрес, предложение объединить.
	ip2, _ := dhcpc(t, "da:00:00:00:00:52", "Galaxy-Lab")
	if ip2 == ip1 {
		t.Fatalf("second MAC got the same address %s", ip2)
	}
	until(t, 5*time.Second, "suggestion to merge", func() bool {
		dev, ok := apiDevice(t, cfg, "dev-da0000000052")
		return ok && dev.MaybeSame != nil && dev.MaybeSame.ID == "dev-a60000000051"
	})
	resp, err := http.Post("http://"+cfg.API.Listen+"/api/devices/dev-a60000000051/merge", "application/json", bytes.NewBufferString(`{"from":"dev-da0000000052"}`))
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("merge: %v %v", resp, err)
	}
	resp.Body.Close()
	// Закреплённый адрес — общий для обоих MAC: прежний MAC получает адрес
	// нового, а не свой прежний.
	hosts := filepath.Join(dir, "hosts")
	until(t, 10*time.Second, "reservation for both MACs", func() bool {
		b, _ := os.ReadFile(hosts)
		return strings.Contains(string(b), "a6:00:00:00:00:51,da:00:00:00:00:52,"+ip2.String())
	})
	if got, _ := dhcpc(t, "a6:00:00:00:00:51", "Galaxy-Lab"); got != ip2 {
		t.Errorf("old MAC after merge got %s, want the reserved %s", got, ip2)
	}
	var st api.DHCPStatus
	getJSON(t, "http://"+cfg.API.Listen+"/api/dhcp", &st)
	// Адрес двух MAC держит один: аренда второго снята.
	if !st.Running || st.Reservations < 1 || len(st.Leases) != 1 || st.Leases[0].Addr != ip2 || st.Leases[0].MAC.String() != "a6:00:00:00:00:51" {
		t.Errorf("status %+v", st)
	}

	// Второй сервер в сети (роутер с включённой раздачей).
	udhcpdConf := filepath.Join(dir, "udhcpd.conf")
	if err := os.WriteFile(udhcpdConf, []byte("interface eth0\nstart 192.168.77.200\nend 192.168.77.210\nlease_file "+dir+"/udhcpd.leases\npidfile "+dir+"/udhcpd.pid\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	udhcpd := exec.Command("ip", "netns", "exec", "tl-client", "busybox", "udhcpd", "-f", udhcpdConf)
	if err := udhcpd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = udhcpd.Process.Kill(); _ = udhcpd.Wait() })
	time.Sleep(500 * time.Millisecond)
	_, _ = inNS("tl-client", labsrvBin(t)+" dhcpc -mac a6:00:00:00:00:53 -hostname other")
	until(t, 10*time.Second, "foreign DHCP server noticed", func() bool {
		getJSON(t, "http://"+cfg.API.Listen+"/api/dhcp", &st)
		return len(st.Foreign) == 1 && st.Foreign[0].Server.String() == benchClient
	})
	_ = udhcpd.Process.Kill()
	_ = udhcpd.Wait()
	var evs struct{ Events []struct{ Topic string } }
	getJSON(t, "http://"+cfg.API.Listen+"/api/events?limit=200", &evs)
	found := false
	for _, e := range evs.Events {
		found = found || e.Topic == "dhcp"
	}
	if !found {
		t.Error("no dhcp event about the foreign server")
	}

	// Демон остановлен — адреса раздаются дальше.
	stop()
	if ip, server := dhcpc(t, "a6:00:00:00:00:54", "after-stop"); server != d.Gateway || !ip.IsValid() {
		t.Errorf("without the daemon: %s from %s", ip, server)
	}
}
