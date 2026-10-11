package decision

import (
	"reflect"
	"testing"
	"time"

	"tross/core/model"
)

func st(id string, prio int, state model.LinkState, rttMs int, mbit uint64) model.LinkStatus {
	return model.LinkStatus{
		Link: model.Link{ID: model.LinkID(id), Priority: prio},
		Health: model.LinkHealth{State: state, RTT: time.Duration(rttMs) * time.Millisecond,
			Throughput: model.Throughput{DownBps: mbit * 1_000_000}},
	}
}

var (
	up   = model.LinkStateUp
	deg  = model.LinkStateDegraded
	down = model.LinkStateDown
	rest = model.LinkStateRestricted
)

func pol(sel model.Selector) model.Policy {
	return model.Policy{Selector: sel, Links: []model.LinkID{"isp1", "isp2"}, Fallback: []model.LinkID{"lte"}}
}

func TestBalanceOrderedAndFallback(t *testing.T) {
	links := []model.LinkStatus{st("isp1", 10, up, 8, 0), st("isp2", 20, up, 12, 0), st("lte", 100, up, 50, 0)}
	cases := []struct {
		name string
		isp1 model.LinkState
		isp2 model.LinkState
		lte  model.LinkState
		want []LinkShare
	}{
		{"all up — first of pool", up, up, up, []LinkShare{{"isp1", 1}}},
		{"isp1 down — next", down, up, up, []LinkShare{{"isp2", 1}}},
		{"degraded is usable", deg, up, up, []LinkShare{{"isp1", 1}}},
		{"restricted is not", rest, up, up, []LinkShare{{"isp2", 1}}},
		{"wired down — fallback LTE", down, down, up, []LinkShare{{"lte", 1}}},
		{"nothing usable", down, rest, down, nil},
	}
	for _, c := range cases {
		links[0].Health.State, links[1].Health.State, links[2].Health.State = c.isp1, c.isp2, c.lte
		if got := Balance(pol(model.SelectOrdered), links); !reflect.DeepEqual(got, c.want) {
			t.Errorf("%s: got %v, want %v", c.name, got, c.want)
		}
	}
}

func TestBalanceNeverUsesLinkOutsidePolicy(t *testing.T) {
	// Класс bulk: LTE нет ни в Links, ни в Fallback — никогда через LTE.
	p := model.Policy{Selector: model.SelectBalanced, Links: []model.LinkID{"isp1", "isp2"}}
	links := []model.LinkStatus{st("isp1", 10, down, 0, 0), st("isp2", 20, down, 0, 0), st("lte", 100, up, 50, 60)}
	if got := Balance(p, links); got != nil {
		t.Fatalf("LTE must not be used for a class that excludes it: %v", got)
	}
}

func TestBalanceEmptyLinksMeansAllButFallback(t *testing.T) {
	p := model.Policy{Selector: model.SelectOrdered, Fallback: []model.LinkID{"lte"}}
	links := []model.LinkStatus{st("isp2", 20, up, 0, 0), st("lte", 1, up, 0, 0), st("isp1", 10, up, 0, 0)}
	if got := Balance(p, links); !reflect.DeepEqual(got, []LinkShare{{"isp1", 1}}) {
		t.Fatalf("priority order without Links: %v", got)
	}
}

func TestBalanceLatencyAndThroughput(t *testing.T) {
	links := []model.LinkStatus{st("isp1", 10, up, 15, 100), st("isp2", 20, up, 9, 400), st("lte", 100, up, 50, 60)}
	if got := Balance(pol(model.SelectLowestLatency), links); got[0].Link != "isp2" {
		t.Fatalf("lowest latency: %v", got)
	}
	links[1].Health.RTT = 0 // неизвестная задержка не считается лучшей
	if got := Balance(pol(model.SelectLowestLatency), links); got[0].Link != "isp1" {
		t.Fatalf("unknown rtt must lose: %v", got)
	}
	if got := Balance(pol(model.SelectBestThroughput), links); got[0].Link != "isp2" {
		t.Fatalf("best throughput: %v", got)
	}
}

func TestBalanceWeighted(t *testing.T) {
	links := []model.LinkStatus{st("isp1", 10, up, 8, 300), st("isp2", 20, up, 12, 100), st("lte", 100, up, 50, 60)}
	got := Balance(pol(model.SelectBalanced), links)
	if !reflect.DeepEqual(got, []LinkShare{{"isp1", 75}, {"isp2", 25}}) {
		t.Fatalf("weights by throughput: %v", got)
	}
	links[1].Health.Throughput.DownBps = 0
	got = Balance(pol(model.SelectBalanced), links)
	if !reflect.DeepEqual(got, []LinkShare{{"isp1", 1}, {"isp2", 1}}) {
		t.Fatalf("unknown throughput must give equal weights: %v", got)
	}
	links[0].Health.Throughput.DownBps, links[1].Health.Throughput.DownBps = 1000_000_000, 1_000_000
	got = Balance(pol(model.SelectBalanced), links)
	if got[1].Weight < 1 {
		t.Fatalf("small link must keep weight >= 1: %v", got)
	}
}
