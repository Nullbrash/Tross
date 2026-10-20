package upnp

import (
	"net/netip"
	"testing"
	"time"

	"tross/core/model"
)

var (
	pc    = netip.MustParseAddr("192.168.10.20")
	other = netip.MustParseAddr("192.168.10.30")
)

func req(port uint16) Request {
	return Request{Via: ViaIGD, Proto: model.ProtoTCP, ExtPort: port, IntPort: port, Client: pc, Source: pc, Lease: 30 * time.Minute, Desc: "TorrentClient"}
}

func TestDecideBasics(t *testing.T) {
	l := DefaultLimits()
	cases := []struct {
		name   string
		r      func() Request
		level  model.UPnPLevel
		out    Outcome
		reason Reason
	}{
		{"allowed", func() Request { return req(51413) }, model.UPnPAllow, Allow, ""},
		{"deny level", func() Request { return req(51413) }, model.UPnPDeny, Deny, NotAuthorized},
		{"unset level", func() Request { return req(51413) }, "", Deny, NotAuthorized},
		{"ask", func() Request { return req(51413) }, model.UPnPAsk, Ask, ""},
		{"other client", func() Request { r := req(51413); r.Client = other; return r }, model.UPnPAllow, Deny, NotAuthorized},
		{"low internal port", func() Request { r := req(51413); r.IntPort = 80; return r }, model.UPnPAllow, Deny, NotAuthorized},
		{"low external port", func() Request { return req(80) }, model.UPnPAllow, Deny, NotAuthorized},
		{"bad proto", func() Request { r := req(51413); r.Proto = "icmp"; return r }, model.UPnPAllow, Deny, NotAuthorized},
	}
	for _, c := range cases {
		d := Decide(c.r(), c.level, nil, l, nil, nil)
		if d.Outcome != c.out || d.Reason != c.reason {
			t.Errorf("%s: %+v", c.name, d)
		}
	}
	// «Спрашивать», но программа разрешена «всегда» — без вопроса.
	if d := Decide(req(51413), model.UPnPAsk, []string{"TORRENTCLIENT"}, l, nil, nil); d.Outcome != Allow {
		t.Errorf("program allowed always: %+v", d)
	}
	// Без описания «всегда» не сработает.
	r := req(51413)
	r.Desc = ""
	if d := Decide(r, model.UPnPAsk, []string{""}, l, nil, nil); d.Outcome != Ask {
		t.Errorf("empty description: %+v", d)
	}
}

func TestDecideLeaseAndPorts(t *testing.T) {
	l := DefaultLimits()
	r := req(51413)
	r.Lease = 0
	if d := Decide(r, model.UPnPAllow, nil, l, nil, nil); d.Lease != time.Hour || !d.Permanent {
		t.Errorf("permanent: %+v", d)
	}
	r.Lease = 24 * time.Hour
	if d := Decide(r, model.UPnPAllow, nil, l, nil, nil); d.Lease != time.Hour || d.Permanent {
		t.Errorf("capped: %+v", d)
	}
	existing := []Mapping{{Proto: model.ProtoTCP, ExtPort: 51413, Addr: other, IntPort: 51413}}
	// Порт занят другим устройством: без «любой порт» — отказ, с ним — другой.
	if d := Decide(req(51413), model.UPnPAllow, nil, l, existing, nil); d.Outcome != Deny || d.Reason != Conflict {
		t.Errorf("conflict: %+v", d)
	}
	r = req(51413)
	r.AnyPort, r.IntPort = true, 51413
	if d := Decide(r, model.UPnPAllow, nil, l, existing, nil); d.Outcome != Allow || d.ExtPort != 51414 {
		t.Errorf("any port: %+v", d)
	}
	// Тот же порт по UDP — свободен; свой проброс — продление.
	r = req(51413)
	r.Proto = model.ProtoUDP
	if d := Decide(r, model.UPnPAllow, nil, l, existing, nil); d.Outcome != Allow || d.ExtPort != 51413 {
		t.Errorf("udp on the same port: %+v", d)
	}
	mine := []Mapping{{Proto: model.ProtoTCP, ExtPort: 51413, Addr: pc, IntPort: 51413}}
	if d := Decide(req(51413), model.UPnPAllow, nil, l, mine, nil); d.Outcome != Allow {
		t.Errorf("renew own: %+v", d)
	}
	// Ручной проброс на порту.
	taken := func(p model.Protocol, port uint16) bool { return p == model.ProtoTCP && port == 51413 }
	if d := Decide(req(51413), model.UPnPAllow, nil, l, nil, taken); d.Outcome != Deny || d.Reason != Conflict {
		t.Errorf("manual forward: %+v", d)
	}
	// NAT-PMP с подсказкой ниже минимума — выдаётся внутренний порт.
	r = Request{Via: ViaNATPMP, Proto: model.ProtoUDP, ExtPort: 80, IntPort: 3074, Client: pc, Source: pc, Lease: time.Hour, AnyPort: true}
	if d := Decide(r, model.UPnPAllow, nil, l, nil, nil); d.Outcome != Allow || d.ExtPort != 3074 {
		t.Errorf("low suggestion: %+v", d)
	}
}

func TestDecidePerDeviceLimit(t *testing.T) {
	l := DefaultLimits()
	l.MaxPerDevice = 2
	ex := []Mapping{
		{Proto: model.ProtoTCP, ExtPort: 2000, Addr: pc, IntPort: 2000},
		{Proto: model.ProtoUDP, ExtPort: 2000, Addr: pc, IntPort: 2000},
	}
	if d := Decide(req(3000), model.UPnPAllow, nil, l, ex, nil); d.Outcome != Deny || d.Reason != NoResources {
		t.Errorf("over limit: %+v", d)
	}
	// Продление своего — не новый проброс.
	if d := Decide(req(2000), model.UPnPAllow, nil, l, ex, nil); d.Outcome != Allow {
		t.Errorf("renew at the limit: %+v", d)
	}
	// Другому устройству предел не мешает.
	r := req(3000)
	r.Client, r.Source = other, other
	if d := Decide(r, model.UPnPAllow, nil, l, ex, nil); d.Outcome != Allow {
		t.Errorf("other device: %+v", d)
	}
	if CanDelete(other, ex[0]) || !CanDelete(pc, ex[0]) {
		t.Error("CanDelete")
	}
}

func TestPickWrapsAround(t *testing.T) {
	l := DefaultLimits()
	r := Request{Proto: model.ProtoTCP, ExtPort: 65535, IntPort: 65535, AnyPort: true}
	got := pick(r, l, func(p uint16) bool { return p == 1024 })
	if got != 1024 {
		t.Errorf("wrap: %d", got)
	}
	if pick(r, l, func(uint16) bool { return false }) != 0 {
		t.Error("nothing free")
	}
}
