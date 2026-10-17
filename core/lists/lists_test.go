package lists

import (
	"slices"
	"strings"
	"testing"

	"tross/core/model"
)

func TestIndexMatch(t *testing.T) {
	var x Index[string]
	x.Add("example.com", model.MatchSuffix, "suffix")
	x.Add("www.example.com", model.MatchExact, "exact")
	x.Add("video", model.MatchKeyword, "kw")
	got := func(d string) []string {
		var out []string
		x.Match(d, func(_ string, _ model.MatchKind, v string) { out = append(out, v) })
		slices.Sort(out)
		return out
	}
	for d, want := range map[string][]string{
		"example.com":          {"suffix"},
		"www.example.com":      {"exact", "suffix"},
		"a.b.example.com":      {"suffix"},
		"notexample.com":       nil, // не по границе метки
		"googlevideo.com":      {"kw"},
		"video.example.com":    {"kw", "suffix"},
		"example.com.evil.org": nil,
	} {
		if g := got(d); !slices.Equal(g, want) {
			t.Errorf("%s: %v, want %v", d, g, want)
		}
	}
	if x.Len() != 3 {
		t.Errorf("Len = %d", x.Len())
	}
}

func rule(p string, purpose model.ListPurpose) model.DomainRule {
	return model.DomainRule{Pattern: p, Match: model.MatchSuffix, Purpose: purpose}
}

// Слои: ручные > выученные > встроенные > онлайн. Встроенный «не трогать»
// перекрывает чужой онлайн-список обхода, а ручное правило — встроенное.
func TestRulesLayers(t *testing.T) {
	r := NewRules()
	if err := r.SetBuiltin(Builtin()); err != nil {
		t.Fatal(err)
	}
	if err := r.SetOnline("itdog", []model.DomainRule{rule("ntp.org", model.PurposeBypass), rule("blocked.example", model.PurposeBypass)}); err != nil {
		t.Fatal(err)
	}
	if got, _ := r.Lookup("pool.ntp.org"); got.Purpose != model.PurposeNever || got.Layer != model.LayerBuiltin {
		t.Errorf("builtin must beat online: %+v", got)
	}
	if got, _ := r.Lookup("www.blocked.example"); got.Purpose != model.PurposeBypass || got.Source != "itdog" {
		t.Errorf("online bypass: %+v", got)
	}
	_ = r.SetManual([]model.DomainRule{rule("time.google.com", model.PurposeBypass)})
	if got, _ := r.Lookup("time.google.com"); got.Layer != model.LayerManual {
		t.Errorf("manual must beat builtin: %+v", got)
	}
	if err := r.Learn(model.DomainRule{Pattern: "blocked.example", Match: model.MatchSuffix, Method: model.MethodDirectDPI}); err != nil {
		t.Fatal(err)
	}
	if got, _ := r.Lookup("blocked.example"); got.Layer != model.LayerLearned {
		t.Errorf("learned must beat online: %+v", got)
	}
	all := r.Match("blocked.example")
	if len(all) != 2 || all[0].Layer != model.LayerLearned || all[1].Layer != model.LayerOnline {
		t.Errorf("Match order: %+v", all)
	}
	// Источник заменяется и убирается целиком.
	_ = r.SetOnline("itdog", nil)
	if got, ok := r.Lookup("other.blocked.example"); ok && got.Layer == model.LayerOnline {
		t.Errorf("removed source still matches: %+v", got)
	}
	m, l, b, on := r.Counts()
	if m != 1 || l != 1 || b != len(Builtin()) || len(on) != 0 {
		t.Errorf("counts %d %d %d %v", m, l, b, on)
	}
}

func TestRulesRejectInvalid(t *testing.T) {
	r := NewRules()
	err := r.SetManual([]model.DomainRule{rule("ok.example", model.PurposeBypass), {Pattern: "BAD..", Match: model.MatchSuffix}, rule("c.example", model.PurposeClass)})
	if err == nil {
		t.Error("invalid rules accepted silently")
	}
	if _, ok := r.Lookup("ok.example"); !ok {
		t.Error("valid rule dropped with invalid ones")
	}
	if _, ok := r.Lookup("c.example"); ok {
		t.Error("class rule without class accepted")
	}
}

func TestBuiltinValid(t *testing.T) {
	for _, b := range Builtin() {
		if err := (func() error { b.Layer = model.LayerBuiltin; return b.Validate() })(); err != nil {
			t.Errorf("%s: %v", b.Pattern, err)
		}
	}
}

func TestParseText(t *testing.T) {
	in := `# комментарий
! adblock
// ещё
example.com
*.wild.example
+.plus.example
.dot.example
full:exact.example
domain:dom.example @ads
keyword:tracker
regexp:^ad[0-9]+\.example$
0.0.0.0 hosts.example
127.0.0.1 localhost
||adblock.example^
Пример.РФ
bad..name
WWW.Upper.Example.
`
	p, err := ParseText(strings.NewReader(in))
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, r := range p.Rules {
		got = append(got, string(r.Match)+":"+r.Pattern)
	}
	want := []string{
		"suffix:example.com", "suffix:wild.example", "suffix:plus.example", "suffix:dot.example",
		"exact:exact.example", "suffix:dom.example", "keyword:tracker", "suffix:hosts.example",
		"suffix:adblock.example", "suffix:xn--e1afmkfd.xn--p1ai", "suffix:www.upper.example",
	}
	if !slices.Equal(got, want) {
		t.Errorf("rules:\n got %v\nwant %v", got, want)
	}
	if p.Skipped != 1 || p.Bad != 1 {
		t.Errorf("skipped %d, bad %d — want 1, 1", p.Skipped, p.Bad)
	}
}

// pb — сборка protobuf для теста: поля length-delimited и varint.
func pbBytes(num int, b []byte) []byte {
	out := pbVarint(uint64(num<<3 | 2))
	out = append(out, pbVarint(uint64(len(b)))...)
	return append(out, b...)
}

func pbInt(num int, v uint64) []byte { return append(pbVarint(uint64(num<<3)), pbVarint(v)...) }

func pbVarint(v uint64) []byte {
	var out []byte
	for v >= 0x80 {
		out = append(out, byte(v)|0x80)
		v >>= 7
	}
	return append(out, byte(v))
}

func geoDomain(typ uint64, value string) []byte {
	return append(pbInt(1, typ), pbBytes(2, []byte(value))...)
}

func geoSite(code string, domains ...[]byte) []byte {
	b := pbBytes(1, []byte(code))
	for _, d := range domains {
		b = append(b, pbBytes(2, d)...)
	}
	return b
}

func TestParseGeosite(t *testing.T) {
	data := append(
		pbBytes(1, geoSite("YOUTUBE", geoDomain(geoRoot, "youtube.com"), geoDomain(geoFull, "youtu.be"), geoDomain(geoPlain, "YtImg"), geoDomain(geoRegex, "^x$"))),
		pbBytes(1, geoSite("TWITCH", geoDomain(geoRoot, "twitch.tv")))...)
	p, err := ParseGeosite(data, []string{"youtube"})
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, r := range p.Rules {
		got = append(got, string(r.Match)+":"+r.Pattern)
	}
	if want := []string{"suffix:youtube.com", "exact:youtu.be", "keyword:ytimg"}; !slices.Equal(got, want) || p.Skipped != 1 {
		t.Errorf("got %v (skipped %d), want %v", got, p.Skipped, want)
	}
	if _, err := ParseGeosite(data, []string{"youtube", "netflix"}); err == nil || !strings.Contains(err.Error(), "netflix") {
		t.Errorf("missing category not reported: %v", err)
	}
	if _, err := ParseGeosite([]byte{0x0a, 0xff}, []string{"youtube"}); err == nil {
		t.Error("truncated file accepted")
	}
}
