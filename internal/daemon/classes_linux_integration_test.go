//go:build linux && integration

// Сценарии классов Этапа 2: демон целиком с configs/lab-classes.yaml,
// трафик из tl-client, «интернет» — tl-inet.
package daemon

import (
	"bytes"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"

	"tross/internal/config"
)

const (
	benchClient = "192.168.77.10"
	// otherDevice — устройства нет: адрес только для «объясни решение»
	// (куда пошла бы новая сессия без закрепления).
	otherDevice = "192.168.77.11"
	stunRequest = `\x00\x01\x00\x00\x21\x12\xa4\x42abcdefghijkl`
)

// classCfg — configs/lab-classes.yaml: стенд Этапа 1 с классами как в
// configs/example.yaml (подробности — в самом файле).
func classCfg(t *testing.T) *config.Config {
	t.Helper()
	path := "configs/lab-classes.yaml"
	if _, err := os.Stat(path); err != nil {
		path = "../../configs/lab-classes.yaml"
	}
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	cfg.Daemon.DataDir = t.TempDir()
	return cfg
}

func labsrvBin(t *testing.T) string {
	t.Helper()
	l := os.Getenv("LAB_NETNS")
	if l == "" {
		t.Fatal("LAB_NETNS is not set (run via scripts/lab-itest)")
	}
	return l[:strings.LastIndex(l, "/scripts/")] + "/bin/labsrv"
}

func inNS(ns, script string) (string, error) {
	out, err := exec.Command("ip", "netns", "exec", ns, "bash", "-c", script).CombinedOutput()
	return string(out), err
}

// udpFrom — один датаграм с клиента (новый порт источника — новое соединение).
func udpFrom(t *testing.T, port, payload string) {
	t.Helper()
	if out, err := inNS("tl-client", "printf '"+payload+"' > /dev/udp/"+benchSrv+"/"+port); err != nil {
		t.Fatalf("udp to %s: %v %s", port, err, out)
	}
	time.Sleep(300 * time.Millisecond)
}

type apiConn struct {
	Proto, Src, Dst, Link, Class, Forward string
}

func clientConns(t *testing.T, cfg *config.Config, query string) []apiConn {
	t.Helper()
	var resp struct{ Connections []apiConn }
	getJSON(t, "http://"+cfg.API.Listen+"/api/connections?limit=5000&device="+benchClient+"&"+query, &resp)
	return resp.Connections
}

// linksTo — каналы соединений клиента к порту (и классу, если задан).
func linksTo(t *testing.T, cfg *config.Config, class, dst string) map[string]int {
	t.Helper()
	m := map[string]int{}
	for _, c := range clientConns(t, cfg, "class="+class) {
		if strings.HasSuffix(c.Dst, dst) {
			m[c.Link]++
		}
	}
	return m
}

type apiExplain struct {
	Classification struct{ Class, Service string }
	Shares         []struct{ Link string }
	Pin            *struct {
		Kind, Link string
	}
	Link, Reason string
}

func explain(t *testing.T, cfg *config.Config, q url.Values) apiExplain {
	t.Helper()
	var ex apiExplain
	getJSON(t, "http://"+cfg.API.Listen+"/api/explain?"+q.Encode(), &ex)
	return ex
}

func onlyLink(m map[string]int, want string) bool { return len(m) == 1 && m[want] > 0 }

// Игра и звонок держат канал всю сессию: канал isp1 стал хуже isp2 —
// новые сессии других устройств пошли бы через isp2, но новые соединения
// этого устройства остаются на isp1, а идущий поток не прерывается.
func TestSessionsHoldLinkWhenBetterAppears(t *testing.T) {
	cfg := classCfg(t)
	startDaemon(t, cfg)
	flow := exec.Command("ip", "netns", "exec", "tl-client", labsrvBin(t), "udpping",
		"-target", benchSrv+":9000", "-rate", "20", "-n", "1000", "-wait", "2s")
	var out bytes.Buffer
	flow.Stdout, flow.Stderr = &out, &out
	if err := flow.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = flow.Process.Kill(); _ = flow.Wait() })
	udpFrom(t, "9001", stunRequest)
	time.Sleep(time.Second)
	if g, v := linksTo(t, cfg, "gaming", ":9000"), linksTo(t, cfg, "voip", ":9001"); !onlyLink(g, "isp1") || !onlyLink(v, "isp1") {
		t.Fatalf("session start: game %v, call %v — want isp1 (lowest latency)", g, v)
	}

	lab(t, "shape", "isp1", "60", "1", "0", "0", "0")
	t.Cleanup(func() { lab(t, "shape", "isp1", "8", "1", "0", "0", "0") })
	newSession := url.Values{"src": {otherDevice}, "dst": {benchSrv + ":9000"}, "proto": {"udp"}}
	took := until(t, 60*time.Second, "new game sessions via isp2", func() bool { return explain(t, cfg, newSession).Link == "isp2" })
	t.Logf("measure: plan for new game sessions moved to isp2 in %v", took.Round(100*time.Millisecond))

	// Внутри сессии: новые соединения игры и звонка — по-прежнему isp1.
	udpFrom(t, "9000", "rejoin")
	udpFrom(t, "9001", stunRequest)
	if g, v := linksTo(t, cfg, "gaming", ":9000"), linksTo(t, cfg, "voip", ":9001"); !onlyLink(g, "isp1") || !onlyLink(v, "isp1") {
		t.Errorf("inside the session: game %v, call %v — want all on isp1", g, v)
	}
	if ex := explain(t, cfg, url.Values{"src": {benchClient}, "dst": {benchSrv + ":9001"}, "proto": {"udp"}, "signature": {"stun"}}); ex.Pin == nil || ex.Pin.Link != "isp1" || ex.Pin.Kind != "session" {
		t.Errorf("explain of the call: %+v (pin %+v)", ex, ex.Pin)
	}

	if err := flow.Wait(); err != nil {
		t.Fatalf("udpping: %v %s", err, out.String())
	}
	f := strings.Fields(out.String()) // sent N, received M, ...
	if len(f) < 4 {
		t.Fatalf("udpping output: %q", out.String())
	}
	got, _ := strconv.Atoi(strings.TrimSuffix(f[3], ","))
	if got < 980 {
		t.Errorf("game flow lost packets across the plan change: %s", strings.TrimSpace(out.String()))
	}
	t.Logf("measure: game flow across the plan change: %s", strings.TrimSpace(out.String()))
}

// Торрент никогда не идёт через LTE: при падении обоих проводных прочее
// уходит в LTE, а загрузки отклоняются сразу; рукопожатие BitTorrent на
// чужом порту через LTE обрывается.
func TestTorrentNeverViaLTE(t *testing.T) {
	cfg := classCfg(t)
	startDaemon(t, cfg)
	connect := func(port string) error {
		_, err := inNS("tl-client", "timeout 4 bash -c '</dev/tcp/"+benchSrv+"/"+port+"'")
		return err
	}
	if err := connect("88"); err != nil {
		t.Fatalf("torrent with wired links up: %v", err)
	}
	if m := linksTo(t, cfg, "bulk", ":88"); m["lte"] > 0 || len(m) == 0 {
		t.Fatalf("torrent links with wired up: %v", m)
	}
	lab(t, "break", "isp1", "loss")
	t.Cleanup(func() { lab(t, "restore", "isp1") })
	lab(t, "break", "isp2", "loss")
	t.Cleanup(func() { lab(t, "restore", "isp2") })
	waitVia(t, "wan3", 30*time.Second)

	start := time.Now()
	if err := connect("88"); err == nil {
		t.Fatal("torrent connected with only LTE alive")
	}
	refused := time.Since(start)
	if refused > 2*time.Second {
		t.Errorf("torrent refusal took %v — must be immediate", refused)
	}
	out, err := inNS("tl-client", `exec 3<>/dev/tcp/`+benchSrv+`/5201 && printf '\x13BitTorrent protocol' >&3 && sleep 1 && printf 'x' >&3 && sleep 1 && printf 'y' >&3 && echo still-open`)
	if err == nil && strings.Contains(out, "still-open") {
		t.Errorf("BitTorrent handshake over LTE was not cut: %q", out)
	}
	if m := linksTo(t, cfg, "bulk", ""); m["lte"] > 0 {
		t.Errorf("bulk connections via LTE: %v", m)
	}
	t.Logf("measure: torrent refused in %v with only LTE alive", refused.Round(10*time.Millisecond))
}

// youtubeAddrs кладёт адреса «YouTube» стенда в множество сервиса — как
// сделает резолвер этапа 4.
func youtubeAddrs(t *testing.T, n int) []string {
	t.Helper()
	out, err := exec.Command("nft", "list", "sets", "inet", "tross").Output()
	if err != nil {
		t.Fatal(err)
	}
	set := ""
	for _, f := range strings.Fields(string(out)) {
		if strings.HasPrefix(f, "tross_dp_youtube_video_") {
			set = f
			break
		}
	}
	if set == "" {
		t.Fatal("no youtube video set in the ruleset")
	}
	var addrs, elems []string
	for i := range n {
		a := "203.0.113." + strconv.Itoa(70+i)
		addrs = append(addrs, a)
		elems = append(elems, a+" timeout 10m")
	}
	if out, err := exec.Command("nft", "add", "element", "inet", "tross", set, "{ "+strings.Join(elems, ", ")+" }").CombinedOutput(); err != nil {
		t.Fatalf("add youtube addresses: %v %s", err, out)
	}
	return addrs
}

func watch(t *testing.T, addr string) {
	t.Helper()
	if out, err := inNS("tl-client", "wget -q -T 3 --tries=1 -O /dev/null 'http://"+addr+":89/bytes?n=20000'"); err != nil {
		t.Fatalf("video from %s: %v %s", addr, err, out)
	}
}

// Видео: потоки YouTube одного устройства — одним каналом, хотя класс
// делит соединения между проводными; LTE — только при падении обоих
// проводных, после их возврата новые потоки снова на проводных.
func TestVideoOneLinkAndLTEOnlyOnFailure(t *testing.T) {
	cfg := classCfg(t)
	startDaemon(t, cfg)
	addrs := youtubeAddrs(t, 8)
	// Адрес → домен объяснению даст резолвер (этап 4); пока домен — в запросе.
	ex := explain(t, cfg, url.Values{"src": {otherDevice}, "dst": {addrs[0] + ":89"}, "domain": {"rr1---sn-lab.googlevideo.com"}})
	if ex.Classification.Service != "youtube" || len(ex.Shares) != 2 {
		t.Fatalf("youtube address explained as %+v — want youtube split over two links", ex)
	}
	for _, a := range addrs {
		watch(t, a)
	}
	m := linksTo(t, cfg, "streaming", "")
	if len(m) != 1 || m["lte"] > 0 {
		t.Fatalf("one device's YouTube streams: %v — want one wired link", m)
	}
	t.Logf("measure: 8 YouTube addresses of one device: %v", m)

	lab(t, "break", "isp1", "loss")
	t.Cleanup(func() { lab(t, "restore", "isp1") })
	lab(t, "break", "isp2", "loss")
	t.Cleanup(func() { lab(t, "restore", "isp2") })
	waitVia(t, "wan3", 30*time.Second)
	watch(t, addrs[1])
	if m := linksTo(t, cfg, "streaming", addrs[1]+":89"); m["lte"] == 0 {
		t.Errorf("video with both wired down: %v — want LTE", m)
	}

	lab(t, "restore", "isp1")
	lab(t, "restore", "isp2")
	waitVia(t, "wan1", 60*time.Second)
	watch(t, addrs[2])
	var latest apiConn
	for _, c := range clientConns(t, cfg, "class=streaming") {
		if strings.HasSuffix(c.Dst, addrs[2]+":89") {
			latest = c
		}
	}
	if latest.Link == "" || latest.Link == "lte" {
		t.Errorf("video after wired links returned: %+v — want a wired link", latest)
	}
}

// Пробросы работают через оба проводных канала, ответ — тем же каналом.
func TestPortForwardThroughBothLinks(t *testing.T) {
	cfg := classCfg(t)
	startDaemon(t, cfg)
	srv := exec.Command("ip", "netns", "exec", "tl-client", labsrvBin(t), "serve",
		"-http", benchClient+":25565", "-udp", benchClient+":25565")
	if err := srv.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = srv.Process.Kill(); _ = srv.Wait() })
	until(t, 5*time.Second, "server on the client", func() bool {
		out, _ := inNS("tl-client", "ss -ltn sport = :25565")
		return strings.Contains(out, "25565")
	})
	for _, wan := range []string{"100.64.1.2", "100.64.2.2"} {
		out, err := inNS("tl-inet", "wget -q -T 3 --tries=1 -O - http://"+wan+":25565/")
		if err != nil || strings.TrimSpace(out) != "ok" {
			t.Errorf("forward via %s: %q, %v", wan, out, err)
		}
	}
	var resp struct{ Connections []apiConn }
	getJSON(t, "http://"+cfg.API.Listen+"/api/connections?limit=5000", &resp)
	via := map[string]bool{}
	for _, c := range resp.Connections {
		if c.Forward == benchClient+":25565" {
			via[c.Link] = true
		}
	}
	if !via["isp1"] || !via["isp2"] {
		t.Errorf("inbound forwarded connections by link: %v — want isp1 and isp2", via)
	}
}

// Очереди сквозь демон: isp1 «у провайдера» — 200/50 Мбит/с с большим
// буфером (netem стенда — до ~0,6 с очереди). Под загрузкой демон сам находит скорость канала по росту
// задержки (без настроек и тестов) и ставит очередь ниже неё; тест скорости
// по команде — база из замера (на время теста ограничение снято).
func TestSQMLearnsLinkSpeed(t *testing.T) {
	clearQueues(t)
	cfg := classCfg(t)
	for i := range cfg.Links {
		cfg.Links[i].SQM.Enabled = cfg.Links[i].ID == "isp1"
	}
	lab(t, "shape", "isp1", "8", "1", "0", "200", "50")
	t.Cleanup(func() { lab(t, "shape", "isp1", "8", "1", "0", "0", "0") })
	startDaemon(t, cfg)
	type dir struct {
		RateBps uint64 `json:"rate_bps"`
		BaseBps uint64 `json:"base_bps"`
		Basis   string `json:"basis"`
	}
	sqmOf := func() (d, u dir) {
		var resp struct {
			Links []struct {
				ID  string
				SQM *struct{ Down, Up dir }
			}
		}
		getJSON(t, "http://"+cfg.API.Listen+"/api/links", &resp)
		for _, l := range resp.Links {
			if l.ID == "isp1" && l.SQM != nil {
				return l.SQM.Down, l.SQM.Up
			}
		}
		t.Fatal("isp1 has no sqm in /api/links")
		return
	}
	if d, _ := sqmOf(); d.RateBps != 0 {
		t.Fatalf("before any load the queue must be unlimited: %+v", d)
	}
	load := exec.Command("ip", "netns", "exec", "tl-client", labsrvBin(t), "load",
		"-url", "http://"+benchSrv, "-down", "4", "-duration", "40s")
	if err := load.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = load.Process.Kill(); _ = load.Wait() })
	took := until(t, 40*time.Second, "passive base from saturation", func() bool {
		d, _ := sqmOf()
		return d.Basis == "passive" && d.RateBps > 0
	})
	d, u := sqmOf()
	t.Logf("measure: download queue learned in %v: rate %d, base %d; upload rate %d (%s)", took.Round(100*time.Millisecond), d.RateBps, d.BaseBps, u.RateBps, u.Basis)
	// Отдача при загрузке — подтверждения: её очередь не должна получить
	// их скорость базой (урезала бы отдачу до пары Мбит/с).
	if u.RateBps != 0 && u.RateBps < 30_000_000 {
		t.Errorf("upload queue cut to %d bit/s by the download's delay", u.RateBps)
	}
	if d.RateBps > 200_000_000 || d.RateBps < 120_000_000 {
		t.Errorf("learned queue %d bit/s — want below the 200 Mbit/s link", d.RateBps)
	}
	var links struct{ Links []struct{ ID, State string } }
	getJSON(t, "http://"+cfg.API.Listen+"/api/links", &links)
	for _, l := range links.Links {
		if l.ID == "isp1" && l.State != "up" && l.State != "degraded" {
			t.Errorf("isp1 under load went %s — the queue must keep it usable", l.State)
		}
	}
	_ = load.Process.Kill()
	_ = load.Wait()

	resp, err := http.Post("http://"+cfg.API.Listen+"/api/links/isp1/speedtest", "", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if d, _ = sqmOf(); d.Basis != "test" || d.BaseBps < 160_000_000 || d.BaseBps > 210_000_000 {
		t.Errorf("after speed test: %+v — want base from the test ≈ 200 Mbit/s", d)
	}
	t.Logf("measure: after speed test: rate %d, base %d", d.RateBps, d.BaseBps)
}

// clearQueues снимает очереди с каналов стенда: они переживают остановку
// демона, и тест иначе начал бы со скорости, оставленной прошлым тестом.
func clearQueues(t *testing.T) {
	t.Helper()
	for i := range wans {
		_ = exec.Command("tc", "qdisc", "del", "dev", wans[i], "root").Run()
		_ = exec.Command("tc", "qdisc", "del", "dev", wans[i], "ingress").Run()
		_ = exec.Command("ip", "link", "del", "ifb-tross"+strconv.Itoa(i)).Run()
	}
}

// cakeCfg — стенд с классами и очередями на всех каналах (как
// scripts/lab-cake-config); очереди прошлых тестов сняты.
func cakeCfg(t *testing.T) *config.Config {
	t.Helper()
	clearQueues(t)
	cfg := classCfg(t)
	for i := range cfg.Links {
		cfg.Links[i].SQM.Enabled = true
	}
	return cfg
}

type sqmDir struct {
	RateBps uint64 `json:"rate_bps"`
	BaseBps uint64 `json:"base_bps"`
	Basis   string `json:"basis"`
}

func linkSQM(t *testing.T, cfg *config.Config, id string) (d, u sqmDir) {
	t.Helper()
	var resp struct {
		Links []struct {
			ID  string
			SQM *struct{ Down, Up sqmDir }
		}
	}
	getJSON(t, "http://"+cfg.API.Listen+"/api/links", &resp)
	for _, l := range resp.Links {
		if l.ID == id && l.SQM != nil {
			return l.SQM.Down, l.SQM.Up
		}
	}
	t.Fatalf("%s has no sqm in /api/links", id)
	return
}

// startLoad — нагрузка labsrv с клиента стенда до конца теста.
func startLoad(t *testing.T, args ...string) *exec.Cmd {
	t.Helper()
	cmd := exec.Command("ip", append([]string{"netns", "exec", "tl-client", labsrvBin(t), "load"}, args...)...)
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
	return cmd
}

// Скорость канала упала под нагрузкой (вечер у провайдера) — очередь
// догоняет её сама, без перезапуска, и пинг возвращается; канал снова
// быстрый — очередь растёт обратно.
func TestSQMFollowsSpeedChange(t *testing.T) {
	cfg := cakeCfg(t)
	lab(t, "shape", "isp1", "8", "1", "0", "300", "100")
	t.Cleanup(func() { lab(t, "shape", "isp1", "8", "1", "0", "0", "0") })
	startDaemon(t, cfg)
	startLoad(t, "-url", "http://"+benchSrv, "-down", "4", "-duration", "150s")
	until(t, 30*time.Second, "base learned at 300 Mbit/s", func() bool { d, _ := linkSQM(t, cfg, "isp1"); return d.RateBps > 0 })
	d, _ := linkSQM(t, cfg, "isp1")
	t.Logf("measure: at 300 Mbit/s: queue %d (%s)", d.RateBps, d.Basis)

	lab(t, "shape", "isp1", "8", "1", "0", "120", "100")
	took := until(t, 30*time.Second, "queue follows the drop to 120 Mbit/s", func() bool {
		d, _ := linkSQM(t, cfg, "isp1")
		return d.RateBps > 0 && d.RateBps < 120_000_000
	})
	d, u := linkSQM(t, cfg, "isp1")
	t.Logf("measure: drop 300 → 120 Mbit/s followed in %v: queue %d; upload %d (%s)", took.Round(100*time.Millisecond), d.RateBps, u.RateBps, u.Basis)
	if u.RateBps != 0 && u.RateBps < 30_000_000 {
		t.Errorf("upload queue cut to %d bit/s by the download's delay", u.RateBps)
	}
	// Пинг игры после подстройки — у простоя, не у раздутой очереди.
	time.Sleep(5 * time.Second)
	out, err := exec.Command("ip", "netns", "exec", "tl-client", labsrvBin(t), "udpping",
		"-target", benchSrv+":9000", "-rate", "20", "-n", "100").CombinedOutput()
	if err != nil {
		t.Fatalf("udpping: %v %s", err, out)
	}
	t.Logf("measure: game under load after the drop: %s", strings.TrimSpace(string(out)))
	if avg := avgRTT(t, string(out)); avg > 8+15+5 {
		t.Errorf("game ping %.1f ms under load after the drop — want ≤ idle + 15 ms", avg)
	}

	lab(t, "shape", "isp1", "8", "1", "0", "300", "100")
	time.Sleep(60 * time.Second)
	d2, _ := linkSQM(t, cfg, "isp1")
	if d2.RateBps <= d.RateBps {
		t.Errorf("queue did not grow back after the link recovered: %d → %d", d.RateBps, d2.RateBps)
	}
	t.Logf("measure: 60 s after recovery to 300 Mbit/s: queue %d → %d", d.RateBps, d2.RateBps)
}

// avgRTT — средняя задержка из строки udpping «… rtt min/avg/max a/b/c ms …».
func avgRTT(t *testing.T, s string) float64 {
	t.Helper()
	i := strings.Index(s, "rtt min/avg/max ")
	if i < 0 {
		t.Fatalf("no rtt in %q", s)
	}
	parts := strings.Split(strings.Fields(s[i+len("rtt min/avg/max "):])[0], "/")
	avg, err := strconv.ParseFloat(parts[1], 64)
	if err != nil {
		t.Fatalf("rtt in %q: %v", s, err)
	}
	return avg
}

// Два устройства в одной корзине: у одного 16 потоков загрузки, у другого
// один — CAKE делит канал между устройствами, а не между потоками
// (вопрос 2 плана Этапа 3).
func TestCakeSharesBetweenDevices(t *testing.T) {
	cfg := cakeCfg(t)
	for i := range cfg.Links {
		if cfg.Links[i].ID == "isp1" {
			cfg.Links[i].SQM.DownMbit, cfg.Links[i].SQM.UpMbit = 100, 100 // база из конфига: без обучения
		}
	}
	lab(t, "shape", "isp1", "8", "1", "0", "100", "100")
	t.Cleanup(func() { lab(t, "shape", "isp1", "8", "1", "0", "0", "0") })
	const second = "192.168.77.11"
	if out, err := inNS("tl-client", "ip addr add "+second+"/24 dev eth0"); err != nil {
		t.Fatalf("second device address: %v %s", err, out)
	}
	t.Cleanup(func() { _, _ = inNS("tl-client", "ip addr del "+second+"/24 dev eth0") })
	startDaemon(t, cfg)
	many := startLoad(t, "-url", "http://"+benchSrv, "-down", "16", "-duration", "20s")
	one := startLoad(t, "-url", "http://"+benchSrv, "-down", "1", "-duration", "20s", "-src", second)
	_ = many.Wait()
	_ = one.Wait()
	rate := func(c *exec.Cmd) float64 {
		s := c.Stdout.(*bytes.Buffer).String()
		i := strings.Index(s, "down ")
		if i < 0 {
			t.Fatalf("no rate in %q", s)
		}
		v, _ := strconv.ParseFloat(strings.Fields(s[i+5:])[0], 64)
		return v
	}
	m, o := rate(many), rate(one)
	t.Logf("measure: device with 16 flows %.1f Mbit/s, device with 1 flow %.1f Mbit/s", m, o)
	if o < (m+o)*0.35 {
		t.Errorf("one-flow device got %.1f of %.1f Mbit/s — want about half", o, m+o)
	}
}
