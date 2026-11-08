package proxypolicy

import (
	"net/netip"
	"testing"
	"time"

	"tross/core/model"
)

func TestOrderAndException(t *testing.T) {
	now := time.Date(2026, 11, 9, 0, 0, 0, 0, time.UTC)
	rules := []Rule{
		{ID: "system-dot", Stage: StageSystem, Action: ActionBlock, Match: Match{Port: 853, Protocol: model.ProtoTCP}},
		{ID: "proxy-example", Stage: StageProxy, Action: ActionProxy, Match: Match{Domain: "example.com"}},
		{ID: "direct-example", Stage: StageDirect, Action: ActionDirect, Match: Match{Domain: "example.com"}},
		{ID: "geo-ru", Stage: StageGeoIPRU, Action: ActionDirect, Match: Match{GeoIP: "ru"}},
		{ID: "acl-apple", Stage: StageACL, Action: ActionProxy, Match: Match{ACL: "Apple"}},
		{ID: "fallback", Stage: StageDefault, Action: ActionProxy},
	}
	flow := Flow{DeviceID: "dev-a", Domain: "example.com", Protocol: model.ProtoTCP, Port: 443, ACL: map[string]bool{"Apple": true}}
	d, err := Decide(flow, rules, nil, now)
	if err != nil || d.Action != ActionProxy || d.RuleID != "proxy-example" {
		t.Fatalf("got %#v, %v", d, err)
	}
	ex := TemporaryException{ID: "tmp-1", Action: ActionDirect, Match: Match{DeviceID: "dev-a", Domain: "example.com"}, CreatedAt: now, ExpiresAt: now.Add(time.Hour), CreatedBy: "admin"}
	d, err = Decide(flow, rules, []TemporaryException{ex}, now)
	if err != nil || d.Action != ActionDirect || d.Stage != StageException {
		t.Fatalf("exception got %#v, %v", d, err)
	}
	d, err = Decide(Flow{Port: 853, Protocol: model.ProtoTCP}, rules, []TemporaryException{{ID: "bad-override", Action: ActionDirect, Match: Match{Port: 853}, CreatedAt: now, ExpiresAt: now.Add(time.Hour), CreatedBy: "admin"}}, now)
	if err != nil || d.Action != ActionBlock || d.Stage != StageSystem {
		t.Fatalf("system block got %#v, %v", d, err)
	}
}

func TestValidation(t *testing.T) {
	if err := (ListVersion{Source: "geoip", Version: "2026-11-09", SHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", CheckedAt: time.Now()}).Validate(); err != nil {
		t.Fatal(err)
	}
	if err := (ListVersion{Source: "geoip", Version: "v", SHA256: "bad", CheckedAt: time.Now()}).Validate(); err == nil {
		t.Fatal("short checksum accepted")
	}
	if err := (TemporaryException{ID: "x", Action: ActionProxy, Match: Match{IP: netip.MustParseAddr("192.0.2.1")}, CreatedAt: time.Now(), ExpiresAt: time.Now().Add(time.Hour), CreatedBy: "admin"}).Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestImportKaringGroups(t *testing.T) {
	r, err := ImportKaringGroups([]KaringGroup{{
		ID: "chosen", Action: ActionProxy, Domains: []string{"Video.Example"},
		ACL: []string{"Apple"}, GeoSite: []string{"ru"}, Processes: []string{"browser.exe"},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Rules) != 3 || len(r.Unsupported) != 1 {
		t.Fatalf("rules=%#v unsupported=%#v", r.Rules, r.Unsupported)
	}
	if _, ok := r.ACL["Apple"]; !ok {
		t.Fatal("configured ACL missing")
	}
	var domain Rule
	for _, rule := range r.Rules {
		if rule.Match.Domain != "" {
			domain = rule
		}
	}
	if domain.Match.Domain != "video.example" || domain.Action != ActionProxy || domain.Stage != StageProxy {
		t.Fatalf("domain=%#v", domain)
	}
}
