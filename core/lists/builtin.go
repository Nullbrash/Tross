package lists

import "tross/core/model"

// builtinNever — имена, которые нельзя уводить в обход и прокси: время
// (неверные часы ломают TLS и протоколы прокси), STUN (адрес в звонке должен
// совпадать с адресом трафика), сети игровых платформ, проверки подключения
// (иначе устройство решит, что интернета нет), push, локальные имена.
var builtinNever = []struct {
	pattern string
	kind    model.MatchKind
}{
	{"pool.ntp.org", model.MatchSuffix}, {"ntp.org", model.MatchSuffix},
	{"time.windows.com", model.MatchSuffix}, {"time.apple.com", model.MatchSuffix},
	{"time.google.com", model.MatchSuffix}, {"time.cloudflare.com", model.MatchSuffix},
	{"ntp.ubuntu.com", model.MatchSuffix}, {"time.nist.gov", model.MatchSuffix},
	{"vniiftri.ru", model.MatchSuffix}, {"ntp.msk-ix.ru", model.MatchSuffix},

	{"stun.l.google.com", model.MatchExact}, {"stun1.l.google.com", model.MatchExact},
	{"stun2.l.google.com", model.MatchExact}, {"stun3.l.google.com", model.MatchExact},
	{"stun4.l.google.com", model.MatchExact}, {"stun.services.mozilla.com", model.MatchExact},
	{"global.stun.twilio.com", model.MatchExact}, {"stun.cloudflare.com", model.MatchExact},

	{"nintendo.net", model.MatchSuffix}, {"nintendowifi.net", model.MatchSuffix},
	{"playstation.net", model.MatchSuffix}, {"xboxlive.com", model.MatchSuffix},

	{"msftconnecttest.com", model.MatchSuffix}, {"msftncsi.com", model.MatchSuffix},
	{"connectivitycheck.gstatic.com", model.MatchExact}, {"connectivitycheck.android.com", model.MatchExact},
	{"clients3.google.com", model.MatchExact}, {"captive.apple.com", model.MatchExact},
	{"detectportal.firefox.com", model.MatchExact}, {"nmcheck.gnome.org", model.MatchExact},
	{"network-test.debian.org", model.MatchExact},

	{"push.apple.com", model.MatchSuffix}, {"mtalk.google.com", model.MatchExact},
	{"notify.windows.com", model.MatchSuffix}, {"push.services.mozilla.com", model.MatchExact},

	{"lan", model.MatchSuffix}, {"local", model.MatchSuffix},
	{"home.arpa", model.MatchSuffix}, {"internal", model.MatchSuffix},
}

// Builtin — встроенный слой «никогда не трогать» (источник "tross").
func Builtin() []model.DomainRule {
	out := make([]model.DomainRule, 0, len(builtinNever))
	for _, b := range builtinNever {
		out = append(out, model.DomainRule{Pattern: b.pattern, Match: b.kind, Purpose: model.PurposeNever, Source: "tross"})
	}
	return out
}
