//go:build linux && integration

package dataplane

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"testing"
	"time"

	"tross/core/decision"
	"tross/core/model"
	"tross/core/sqm"
)

// sqmStand — стенд с классами и очередями на isp1: игра — голос, загрузки
// (TCP 88) — фон, прочее — без корзины (обычное по DSCP).
func sqmStand(t *testing.T) Spec {
	t.Helper()
	spec := classStand(t)
	for i := range spec.Links {
		spec.Links[i].SQM = spec.Links[i].Link.ID == "isp1"
	}
	pol := spec.Classify.Policies
	for cl, tin := range map[model.TrafficClass]sqm.Tin{model.ClassGaming: sqm.TinVoice, model.ClassBulk: sqm.TinBulk} {
		p := pol[cl]
		p.Tin = tin
		pol[cl] = p
	}
	return spec
}

// tinPackets — пакеты по корзинам CAKE устройства (порядок tc: фон,
// обычное, видео, голос).
func tinPackets(t *testing.T, dev string) []uint64 {
	t.Helper()
	out, err := exec.Command("tc", "-s", "-j", "qdisc", "show", "dev", dev, "root").Output()
	if err != nil {
		t.Fatalf("tc show %s: %v", dev, err)
	}
	var qs []struct {
		Kind string `json:"kind"`
		Tins []struct {
			SentPackets uint64 `json:"sent_packets"`
		} `json:"tins"`
	}
	if err := json.Unmarshal(out, &qs); err != nil || len(qs) == 0 || qs[0].Kind != "cake" || len(qs[0].Tins) != 4 {
		t.Fatalf("no cake with 4 tins on %s: %v\n%s", dev, err, out)
	}
	var n []uint64
	for _, tin := range qs[0].Tins {
		n = append(n, tin.SentPackets)
	}
	return n
}

func setupSQM(t *testing.T) *System {
	t.Helper()
	s := newSystem(t)
	if err := s.Setup(context.Background(), sqmStand(t)); err != nil {
		t.Fatal(err)
	}
	// Всё — через isp1, где очереди.
	setPlan(t, s,
		decision.ClassPlan{Class: model.ClassDefault, Shares: one("isp1"), PinLinks: []model.LinkID{"isp1"}},
		decision.ClassPlan{Class: model.ClassGaming, Shares: one("isp1"), PinLinks: []model.LinkID{"isp1"}},
		decision.ClassPlan{Class: model.ClassBulk, Shares: one("isp1"), PinLinks: []model.LinkID{"isp1"}},
	)
	return s
}

// Корзина класса доходит до CAKE в обе стороны: на выходе — из метки
// пакета, на входе — из метки соединения, восстановленной до IFB.
// Заодно проверяет порядок корзин в метке (1 — фон … 4 — голос).
func TestCakeTinsFollowClasses(t *testing.T) {
	setupSQM(t)
	const bulk, best, voice = 0, 1, 3
	diff := func(a, b []uint64) []int64 {
		d := make([]int64, len(a))
		for i := range a {
			d[i] = int64(b[i]) - int64(a[i])
		}
		return d
	}

	before := tinPackets(t, "wan1")
	for range 5 {
		udp(t, "9002", "game") // правило lab-game → игры
	}
	if d := diff(before, tinPackets(t, "wan1")); d[voice] < 5 {
		t.Errorf("game UDP out of wan1 by tin %v — want ≥ 5 in voice", d)
	}

	upBefore, downBefore := tinPackets(t, "wan1"), tinPackets(t, ifbName(0))
	if out, err := inClient(t, "wget -q -T 5 --tries=1 -O /dev/null 'http://"+srv+":88/bytes?n=300000'"); err != nil {
		t.Fatalf("bulk fetch: %v %s", err, out)
	}
	if d := diff(downBefore, tinPackets(t, ifbName(0))); d[bulk] < 100 || d[bulk] < d[best] {
		t.Errorf("bulk download into the home by tin %v — want it in bulk", d)
	}
	if d := diff(upBefore, tinPackets(t, "wan1")); d[bulk] < 10 {
		t.Errorf("bulk upload (acks) by tin %v — want it in bulk", d)
	}

	downBefore = tinPackets(t, ifbName(0))
	if got, err := fetch(t, 300_000); err != nil || got != 300_000 {
		t.Fatalf("default fetch: %d, %v", got, err)
	}
	if d := diff(downBefore, tinPackets(t, ifbName(0))); d[best] < 100 || d[bulk] > d[best]/10 {
		t.Errorf("default download by tin %v — want best effort", d)
	}
}

// Скорость очереди на входе действительно ограничивает загрузку.
func TestCakeRateLimitsDownload(t *testing.T) {
	s := setupSQM(t)
	ctx := context.Background()
	if err := s.SetShaping(ctx, []Shaping{{Link: "isp1", DownBps: 20_000_000, UpBps: 10_000_000}}); err != nil {
		t.Fatal(err)
	}
	if d, _ := cakeRate(ctx, ifbName(0)); d != 20_000_000 {
		t.Errorf("ifb cake rate %d, want 20 Mbit/s", d)
	}
	if u, _ := cakeRate(ctx, "wan1"); u != 10_000_000 {
		t.Errorf("wan1 cake rate %d, want 10 Mbit/s", u)
	}
	start := time.Now()
	if got, err := fetch(t, 5_000_000); err != nil || got != 5_000_000 {
		t.Fatalf("fetch: %d, %v", got, err)
	}
	took := time.Since(start)
	mbit := 5_000_000 * 8 / took.Seconds() / 1e6
	if mbit > 21 || mbit < 12 {
		t.Errorf("download through a 20 Mbit/s queue: %.1f Mbit/s", mbit)
	}
	t.Logf("measure: 5 MB through a 20 Mbit/s queue in %v (%.1f Mbit/s)", took.Round(10*time.Millisecond), mbit)
}

// Очереди переживают остановку демона с последней скоростью, перезапуск её
// не сбрасывает, пересозданный интерфейс получает их обратно, purge снимает.
func TestCakeLifecycle(t *testing.T) {
	s := setupSQM(t)
	ctx := context.Background()
	if err := s.SetShaping(ctx, []Shaping{{Link: "isp1", DownBps: 300_000_000, UpBps: 100_000_000}}); err != nil {
		t.Fatal(err)
	}
	if err := s.Teardown(ctx); err != nil {
		t.Fatal(err)
	}
	if d, ok := cakeRate(ctx, ifbName(0)); !ok || d != 300_000_000 {
		t.Fatalf("after teardown: cake %v, rate %d", ok, d)
	}
	if err := s.Setup(ctx, sqmStand(t)); err != nil {
		t.Fatal(err)
	}
	if d, _ := cakeRate(ctx, ifbName(0)); d != 300_000_000 {
		t.Errorf("restart reset the download rate to %d", d)
	}
	if u, _ := cakeRate(ctx, "wan1"); u != 100_000_000 {
		t.Errorf("restart reset the upload rate to %d", u)
	}

	lab := os.Getenv("LAB_NETNS")
	if out, err := exec.Command(lab, "recreate", "isp1").CombinedOutput(); err != nil {
		t.Fatalf("recreate isp1: %v %s", err, out)
	}
	if _, ok := cakeRate(ctx, "wan1"); ok {
		t.Fatal("recreated interface kept its queue — the check proves nothing")
	}
	before, _ := exec.Command("tc", "qdisc", "show", "dev", "wan1").CombinedOutput()
	remembered := s.shaping["isp1"]
	if err := s.RepairRoutes(ctx); err != nil {
		t.Fatal(err)
	}
	if u, ok := cakeRate(ctx, "wan1"); !ok || u != 100_000_000 {
		after, _ := exec.Command("tc", "qdisc", "show", "dev", "wan1").CombinedOutput()
		t.Errorf("after recreate + repair: cake %v, rate %d (remembered %+v)\nbefore repair: %s\nafter: %s", ok, u, remembered, before, after)
	}

	if err := Cleanup(ctx, s.log, sqmStand(t), true); err != nil {
		t.Fatal(err)
	}
	if _, ok := cakeRate(ctx, "wan1"); ok {
		t.Error("purge left cake on wan1")
	}
	if out, err := exec.Command("ip", "link", "show", ifbName(0)).CombinedOutput(); err == nil {
		t.Errorf("purge left %s:\n%s", ifbName(0), out)
	}
}
