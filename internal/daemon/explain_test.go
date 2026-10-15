package daemon

import (
	"context"
	"io"
	"log/slog"
	"net/netip"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"tross/core/decision"
	"tross/core/event"
	"tross/core/model"
	"tross/internal/config"
	"tross/internal/dataplane"
	"tross/internal/linkmon"
)

// explainBench — классы и правила из configs/example.yaml, монитор-подделка,
// первый план уже применён.
func explainBench(t *testing.T) (*explainer, *dataplane.Fake, *balancer) {
	t.Helper()
	path := "../../configs/example.yaml"
	if _, err := os.Stat(path); err != nil {
		path = "configs/example.yaml" // lab-itest запускает тесты из корня репозитория
	}
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	var links []model.Link
	for _, l := range cfg.Links {
		links = append(links, l.Model())
	}
	mon := linkmon.NewFake(links, event.NewBus(), time.Hour, 1)
	dp := dataplane.NewFake(log)
	b, err := newBalancer(log, dp, mon, cfg.Policies())
	if err != nil {
		t.Fatal(err)
	}
	cat, err := serviceCatalog(cfg)
	if err != nil {
		t.Fatal(err)
	}
	x, err := newExplainer(cfg, cat, b, dp)
	if err != nil {
		t.Fatal(err)
	}
	mon.Tick()
	b.apply(context.Background())
	return x, dp, b
}

func classPlan(t *testing.T, b *balancer, c model.TrafficClass) decision.ClassPlan {
	t.Helper()
	for _, p := range b.applied() {
		if p.Class == c {
			return p
		}
	}
	t.Fatalf("no plan for %s", c)
	return decision.ClassPlan{}
}

var device = netip.MustParseAddr("192.168.1.20")

func TestExplainNewGameSession(t *testing.T) {
	x, _, b := explainBench(t)
	f := model.Flow{Proto: model.ProtoUDP, Src: netip.AddrPortFrom(device, 0), Dst: netip.MustParseAddrPort("203.0.113.7:27015")}
	ex, err := x.explain(context.Background(), f)
	if err != nil {
		t.Fatal(err)
	}
	p := classPlan(t, b, model.ClassGaming)
	if ex.Classification.Class != model.ClassGaming || len(p.Shares) != 1 || ex.Link != p.Shares[0].Link {
		t.Fatalf("explain = %+v, plan %+v", ex, p)
	}
	if ex.Pin != nil || !strings.Contains(ex.Reason, "new session pin") || ex.Method != model.MethodDirect {
		t.Errorf("explain = %+v", ex)
	}
}

func TestExplainFollowsKernelPin(t *testing.T) {
	x, dp, b := explainBench(t)
	p := classPlan(t, b, model.ClassGaming)
	other := slices.IndexFunc(p.PinLinks, func(id model.LinkID) bool { return id != p.Shares[0].Link })
	if other < 0 {
		t.Fatalf("gaming pins only %v", p.PinLinks)
	}
	pinned := p.PinLinks[other]
	dp.SetObserved(nil, []dataplane.Pin{
		// Закрепление другого устройства и за каналом вне PinLinks — не в счёт.
		{Class: model.ClassGaming, Device: netip.MustParseAddr("192.168.1.21"), Link: p.Shares[0].Link, Expires: time.Hour},
		{Class: model.ClassGaming, Device: device, Link: "nowhere", Expires: time.Hour},
		{Class: model.ClassGaming, Device: device, Link: pinned, Expires: 90 * time.Minute},
	})
	f := model.Flow{Proto: model.ProtoUDP, Src: netip.AddrPortFrom(device, 0), Dst: netip.MustParseAddrPort("203.0.113.7:27015")}
	ex, err := x.explain(context.Background(), f)
	if err != nil {
		t.Fatal(err)
	}
	if ex.Link != pinned || ex.Pin == nil || ex.Pin.Kind != model.StickSession || ex.Pin.ExpiresS != 5400 {
		t.Errorf("explain = %+v (pin %+v), want pinned to %s", ex, ex.Pin, pinned)
	}
}

func TestExplainServicePinAndNotes(t *testing.T) {
	x, dp, b := explainBench(t)
	p := classPlan(t, b, model.ClassStreaming)
	link := p.PinLinks[len(p.PinLinks)-1]
	dp.SetObserved(nil, []dataplane.Pin{{Class: model.ClassStreaming, Service: "youtube", Device: device, Link: link, Expires: time.Minute}})
	f := model.Flow{Proto: model.ProtoTCP, Src: netip.AddrPortFrom(device, 0), Dst: netip.MustParseAddrPort("198.51.100.9:443"), Domain: "rr3---sn-abc.googlevideo.com"}
	ex, err := x.explain(context.Background(), f)
	if err != nil {
		t.Fatal(err)
	}
	if ex.Classification.Service != "youtube" || ex.Link != link || ex.Pin == nil || ex.Pin.Kind != model.StickService {
		t.Errorf("explain = %+v", ex)
	}
	if !slices.ContainsFunc(ex.Notes, func(n string) bool { return strings.HasPrefix(n, "domain:") }) {
		t.Errorf("no note about domains in the kernel: %v", ex.Notes)
	}
}

func TestExplainBeforeFirstPlan(t *testing.T) {
	x, _, b := explainBench(t)
	b.mu.Lock()
	b.current = nil
	b.mu.Unlock()
	ex, err := x.explain(context.Background(), model.Flow{Proto: model.ProtoTCP, Src: netip.AddrPortFrom(device, 0), Dst: netip.MustParseAddrPort("198.51.100.9:443")})
	if err != nil || ex.Link != "" || !strings.HasPrefix(ex.Reason, "no plan yet") {
		t.Errorf("explain = %+v, %v", ex, err)
	}
}
