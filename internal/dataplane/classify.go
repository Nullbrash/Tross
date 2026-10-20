package dataplane

import (
	"cmp"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"time"

	"tross/core/decision"
	coredns "tross/core/dns"
	"tross/core/model"
	"tross/core/profile"
	"tross/core/sqm"
)

// classMarkMask — младший байт fwmark/ct mark: номер класса соединения.
// Маршрутизация смотрит только на биты канала (LinkMarkMask), так что класс
// на выбор таблицы не влияет; его читают приоритеты (этап 3) и статистика.
const classMarkMask uint32 = 0x000000ff

// btPeerTTL — сколько помнить адрес пира, по которому TCP-соединение
// оказалось торрентом: следующие соединения к нему сразу идут как bulk.
const btPeerTTL = time.Hour

// Признаки первого пакета с данными (@ih — начало данных за транспортным
// заголовком). У UDP он приходит до выбора канала; у TCP — после.
var signatureExpr = map[string]string{
	// STUN: magic cookie в байтах 4–7.
	profile.SigSTUN: "@ih,32,32 0x2112a442",
	// Discord: запрос IP discovery — тип 1, длина 70, всего 74 байта.
	profile.SigDiscordVoice: "udp length 82 @ih,0,32 0x00010046",
	// uTP SYN: тип 4, версия 1; задержка в байтах 8–11 у SYN нулевая.
	profile.SigUTP: "udp length >= 28 @ih,0,8 0x41 @ih,64,32 0",
	// DHT: запрос в bencode начинается с «d1:ad2:id20:».
	profile.SigDHT: "@ih,0,96 0x64313a6164323a696432303a",
}

// btHandshake — первые 12 байт рукопожатия BitTorrent: 0x13 «BitTorrent ».
const btHandshake = "@ih,0,96 0x13426974546f7272656e7420"

// ClassRule — одно правило классификации в ядре: все заданные поля (И).
type ClassRule struct {
	Name     string
	Class    model.TrafficClass
	Service  string // непусто — сервис с закреплением «устройство + сервис»
	Proto    model.Protocol
	Ports    []profile.PortRange
	Networks []netip.Prefix
	Sources  []netip.Addr
	// SourceSet — множество адресов устройств правила (обновляет демон при
	// смене адреса устройства, SetDevices); Sources — его начальное содержимое.
	SourceSet SetName
	DomainSet SetName // адреса доменов (наполняет резолвер)
	// Domains — домены множества правила пользователя или части профиля
	// (у множеств списков домены — в списках).
	Domains   []string
	Signature string
}

// ClassPolicy — неизменная часть политики класса для ядра.
type ClassPolicy struct {
	Pin    model.Stickiness
	PinTTL time.Duration
	// Allowed — каналы класса (основные и запасные); пусто — все.
	Allowed []model.LinkID
	// Tin — корзина CAKE класса (биты TinMarkMask метки); 0 — по DSCP.
	Tin sqm.Tin
}

// Classify — статическая часть классификации (ставится в Setup); пусто —
// один класс default, как до классов.
type Classify struct {
	Classes  []model.TrafficClass // номер класса в метке — индекс + 1
	Policies map[model.TrafficClass]ClassPolicy
	Rules    []ClassRule
	Services []string // сервисы с закреплением, по порядку
}

// UserRule — правило пользователя из конфига. С устройствами (ByDevice или
// непустые Devices) правило — только для них: адреса — в множестве
// (DeviceSet), пустое множество не совпадает ни с чем; Devices — адреса,
// известные при Setup.
type UserRule struct {
	Name     string
	Class    model.TrafficClass
	ByDevice bool
	Devices  []netip.Addr
	Match    profile.Match
}

// DeviceSet — множество адресов устройств i-го правила пользователя.
func DeviceSet(i int) SetName { return SetName(fmt.Sprintf("tross_ud%d", i)) }

// CompileClassify строит правила ядра в порядке классификатора
// (core/classify): правила пользователя → ручные доменные списки → профили
// (признак > домен > сеть > порт) → прочие списки → default. Класс профиля
// без политики идёт по default.
func CompileClassify(classes []model.TrafficClass, policies map[model.TrafficClass]ClassPolicy, user []UserRule, cat profile.Catalog) Classify {
	c := Classify{Classes: classes, Policies: policies}
	known := func(cl model.TrafficClass) model.TrafficClass {
		if slices.Contains(classes, cl) {
			return cl
		}
		return model.ClassDefault
	}
	if slices.Contains(classes, model.ClassBulk) {
		c.Rules = append(c.Rules, ClassRule{Name: "learned-torrent-peers", Class: model.ClassBulk, Proto: model.ProtoTCP, DomainSet: setBTPeers})
	}
	for i, u := range user {
		r := ruleFromMatch(u.Name, known(u.Class), "", u.Match)
		if u.ByDevice || len(u.Devices) > 0 {
			r.SourceSet, r.Sources = DeviceSet(i), u.Devices
		}
		if len(u.Match.Domains) > 0 {
			r.DomainSet, r.Domains = SetName(fmt.Sprintf("tross_du%d", i)), u.Match.Domains
		}
		c.Rules = append(c.Rules, r)
	}
	for _, cl := range classes {
		c.Rules = append(c.Rules, ClassRule{Name: "list-manual-" + string(cl), Class: cl, DomainSet: listSet("m", cl)})
	}
	type alt = classAlt
	var alts []alt
	for _, s := range cat.Services {
		if s.Disabled {
			continue
		}
		for _, p := range s.Parts {
			svc := ""
			if p.PinService {
				svc = s.ID
				if !slices.Contains(c.Services, s.ID) {
					c.Services = append(c.Services, s.ID)
				}
			}
			for j, m := range p.Match {
				if m.Signature != "" && signatureExpr[m.Signature] == "" {
					// Признак без выражения для первого пакета (BitTorrent по TCP
					// виден только после выбора канала): иначе правило свелось бы к
					// «весь TCP» — его обслуживают защита и множество пиров.
					continue
				}
				r := ruleFromMatch(s.ID+"/"+p.ID, known(p.Class), svc, m)
				if len(m.Domains) > 0 {
					r.DomainSet, r.Domains = SetName(fmt.Sprintf("tross_dp_%s_%s_%d", ident(s.ID), ident(p.ID), j)), m.Domains
				}
				alts = append(alts, alt{rule: r, match: m, score: 10 * specificity(m)})
			}
		}
	}
	// Среди доменных — сначала части с поддоменами доменов других частей
	// (gateway.discord.gg раньше discord.gg): в ядре домены — это адреса, у
	// поддомена и домена они могут совпадать, и выиграло бы первое правило, а
	// классификатор выбирает самый длинный домен.
	for i := range alts {
		if specificity(alts[i].match) == 2 && subdomainOfOther(alts[i].match, alts) {
			alts[i].score++
		}
	}
	slices.SortStableFunc(alts, func(a, b alt) int { return cmp.Compare(b.score, a.score) })
	for _, a := range alts {
		c.Rules = append(c.Rules, a.rule)
	}
	for _, cl := range classes {
		c.Rules = append(c.Rules, ClassRule{Name: "list-" + string(cl), Class: cl, DomainSet: listSet("a", cl)})
	}
	return c
}

type classAlt struct {
	rule  ClassRule
	match profile.Match
	score int
}

func subdomainOfOther(m profile.Match, all []classAlt) bool {
	for _, o := range all {
		if o.rule.Name == "" || o.rule.DomainSet == "" {
			continue
		}
		for _, d := range m.Domains {
			for _, od := range o.match.Domains {
				if strings.HasSuffix(d, "."+od) {
					return true
				}
			}
		}
	}
	return false
}

// setBTPeers — адрес и порт пиров, узнанных по рукопожатию BitTorrent.
const setBTPeers SetName = "tross_btpeer4"

func listSet(layer string, cl model.TrafficClass) SetName {
	return SetName("tross_l" + layer + "_" + ident(string(cl)))
}

// ListSet — множество доменов класса из списков слоя; у выученных и
// встроенных своих множеств классов нет ("").
func ListSet(layer model.RuleLayer, cl model.TrafficClass) SetName {
	switch layer {
	case model.LayerManual:
		return listSet("m", cl)
	case model.LayerOnline:
		return listSet("a", cl)
	}
	return ""
}

// DomainSpecs — множества правил пользователя и частей профилей с их
// доменами: что резолвер кладёт куда.
func (c Classify) DomainSpecs() []coredns.SetSpec {
	var out []coredns.SetSpec
	for _, r := range c.Rules {
		if r.DomainSet != "" && len(r.Domains) > 0 {
			out = append(out, coredns.SetSpec{Name: string(r.DomainSet), Domains: r.Domains})
		}
	}
	return out
}

func specificity(m profile.Match) int {
	switch {
	case m.Signature != "":
		return 3
	case len(m.Domains) > 0:
		return 2
	case len(m.Networks) > 0:
		return 1
	}
	return 0
}

func ruleFromMatch(name string, cl model.TrafficClass, svc string, m profile.Match) ClassRule {
	return ClassRule{Name: name, Class: cl, Service: svc, Proto: m.Proto, Ports: m.Ports, Networks: m.Networks, Signature: m.Signature}
}

// ident — имя для nft (множества, цепочки): только [a-z0-9_].
func ident(s string) string {
	return strings.Map(func(r rune) rune {
		if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '_' {
			return r
		}
		return '_'
	}, strings.ToLower(s))
}

func (c Classify) withDefault() Classify {
	if len(c.Classes) == 0 {
		c.Classes = []model.TrafficClass{model.ClassDefault}
	}
	return c
}

// markOf — метка нового соединения класса до выбора канала: номер класса и
// корзина CAKE (канал добавит цепочка класса).
func (c Classify) markOf(cl model.TrafficClass) uint32 {
	id := c.classID(cl)
	return id | uint32(c.Policies[c.Classes[id-1]].Tin)<<tinShift
}

func (c Classify) classID(cl model.TrafficClass) uint32 {
	if i := slices.Index(c.Classes, cl); i >= 0 {
		return uint32(i + 1)
	}
	return uint32(slices.Index(c.Classes, model.ClassDefault) + 1)
}

// domainSets — множества адресов доменов (без множества пиров BitTorrent).
// deviceSets — множества устройств правил пользователя.
func (c Classify) deviceSets() []SetName {
	var out []SetName
	for _, r := range c.Rules {
		if r.SourceSet != "" {
			out = append(out, r.SourceSet)
		}
	}
	return out
}

func (c Classify) domainSets() []SetName {
	var out []SetName
	for _, r := range c.Rules {
		if r.DomainSet != "" && r.DomainSet != setBTPeers && !slices.Contains(out, r.DomainSet) {
			out = append(out, r.DomainSet)
		}
	}
	return out
}

func stickySet(cid uint32, linkIdx int) string { return fmt.Sprintf("tross_s%d_%d", cid, linkIdx) }
func serviceSet(svcIdx, linkIdx int) string    { return fmt.Sprintf("tross_v%d_%d", svcIdx, linkIdx) }
func classChain(cid uint32) string             { return fmt.Sprintf("cls%d", cid) }
func serviceChain(svcIdx int) string           { return fmt.Sprintf("svc%d", svcIdx) }

func (c Classify) serviceClass(svc string) model.TrafficClass {
	for _, r := range c.Rules {
		if r.Service == svc {
			return r.Class
		}
	}
	return model.ClassDefault
}

// renderClassifySets — множества доменов, закреплений и пиров BitTorrent.
func renderClassifySets(c Classify, links []LinkSpec) string {
	var b strings.Builder
	for _, s := range c.domainSets() {
		fmt.Fprintf(&b, "\tset %s {\n\t\ttype ipv4_addr\n\t\tflags timeout\n\t}\n", s)
	}
	for _, r := range c.Rules {
		if r.SourceSet == "" {
			continue
		}
		fmt.Fprintf(&b, "\tset %s {\n\t\ttype ipv4_addr\n", r.SourceSet)
		if len(r.Sources) > 0 {
			fmt.Fprintf(&b, "\t\telements = { %s }\n", joinAddrs(r.Sources))
		}
		b.WriteString("\t}\n")
	}
	for i := range links {
		fmt.Fprintf(&b, "\tset %s {\n\t\ttype ipv4_addr\n\t\tflags timeout\n\t}\n", DomainLinkSet(i))
	}
	if slices.Contains(c.Classes, model.ClassBulk) {
		fmt.Fprintf(&b, "\tset %s {\n\t\ttype ipv4_addr . inet_service\n\t\tflags dynamic,timeout\n\t\ttimeout %ds\n\t}\n", setBTPeers, int(btPeerTTL/time.Second))
	}
	for _, cl := range c.Classes {
		p := c.Policies[cl]
		if p.Pin == model.StickNone || p.Pin == "" || p.PinTTL <= 0 {
			continue
		}
		typ := "ipv4_addr"
		if p.Pin == model.StickDestination {
			typ = "ipv4_addr . ipv4_addr"
		}
		for i := range links {
			fmt.Fprintf(&b, "\tset %s {\n\t\ttype %s\n\t\tflags dynamic,timeout\n\t\ttimeout %ds\n\t}\n", stickySet(c.classID(cl), i), typ, int(p.PinTTL/time.Second))
		}
	}
	for si, svc := range c.Services {
		ttl := c.Policies[c.serviceClass(svc)].PinTTL
		if ttl <= 0 {
			ttl = decision.DefaultServiceTTL
		}
		for i := range links {
			fmt.Fprintf(&b, "\tset %s {\n\t\ttype ipv4_addr\n\t\tflags dynamic,timeout\n\t\ttimeout %ds\n\t}\n", serviceSet(si, i), int(ttl/time.Second))
		}
	}
	return b.String()
}

// renderClassifyChains — пустые цепочки классов и сервисов (наполняет
// SetPlan), commit и classify с правилами по порядку.
func renderClassifyChains(c Classify) string {
	var b strings.Builder
	for i := range c.Classes {
		fmt.Fprintf(&b, "\tchain %s {\n\t}\n", classChain(uint32(i+1)))
	}
	for si := range c.Services {
		fmt.Fprintf(&b, "\tchain %s {\n\t}\n", serviceChain(si))
	}
	b.WriteString("\tchain commit {\n\t\tct mark set meta mark\n\t}\n")
	b.WriteString("\tchain classify {\n")
	for _, r := range c.Rules {
		cid := c.classID(r.Class)
		target := classChain(cid)
		if r.Service != "" {
			target = serviceChain(slices.Index(c.Services, r.Service))
		}
		fmt.Fprintf(&b, "\t\t%s meta mark set %#x goto %s\n", matchExpr(r), c.markOf(r.Class), target)
	}
	fmt.Fprintf(&b, "\t\tmeta mark set %#x goto %s\n", c.markOf(model.ClassDefault), classChain(c.classID(model.ClassDefault)))
	b.WriteString("\t}\n")
	return b.String()
}

// renderBTGuard — TCP-соединение, в первых пакетах которого оказалось
// рукопожатие BitTorrent, на канале, запрещённом классу bulk: пир
// запоминается (следующие соединения к нему классифицируются bulk) и
// соединение рвётся — клиент переподключится разрешённым путём.
func renderBTGuard(c Classify, links []LinkSpec, lan string) string {
	if !slices.Contains(c.Classes, model.ClassBulk) {
		return ""
	}
	allowed := c.Policies[model.ClassBulk].Allowed
	if len(allowed) == 0 {
		return ""
	}
	var b strings.Builder
	for _, l := range links {
		if slices.Contains(allowed, l.Link.ID) {
			continue
		}
		fmt.Fprintf(&b, "\t\tiifname %s meta l4proto tcp ct state established ct original packets < 8 ct mark and %#x == %#x %s update @%s { ip daddr . tcp dport } reject with tcp reset\n",
			quote(lan), LinkMarkMask, l.FwMark, btHandshake, setBTPeers)
	}
	return b.String()
}

func matchExpr(r ClassRule) string {
	var parts []string
	if r.SourceSet != "" {
		parts = append(parts, "ip saddr @"+string(r.SourceSet))
	} else if len(r.Sources) > 0 {
		parts = append(parts, "ip saddr "+setOf(r.Sources, func(a netip.Addr) string { return a.String() }))
	}
	if r.DomainSet == setBTPeers {
		return "ip daddr . tcp dport @" + string(setBTPeers)
	}
	if r.DomainSet != "" {
		parts = append(parts, "ip daddr @"+string(r.DomainSet))
	}
	if len(r.Networks) > 0 {
		parts = append(parts, "ip daddr "+setOf(r.Networks, func(p netip.Prefix) string { return p.String() }))
	}
	proto := string(r.Proto)
	if len(r.Ports) > 0 {
		ports := setOf(r.Ports, func(p profile.PortRange) string {
			if p.From == p.To {
				return fmt.Sprint(p.From)
			}
			return fmt.Sprintf("%d-%d", p.From, p.To)
		})
		if proto == "" {
			parts = append(parts, "th dport "+ports)
		} else {
			parts = append(parts, proto+" dport "+ports)
		}
	} else if proto != "" {
		parts = append(parts, "meta l4proto "+proto)
	}
	if e := signatureExpr[r.Signature]; e != "" {
		parts = append(parts, e)
	}
	return strings.Join(parts, " ")
}

func joinAddrs(as []netip.Addr) string {
	s := make([]string, len(as))
	for i, a := range as {
		s[i] = a.String()
	}
	return strings.Join(s, ", ")
}

func setOf[T any](v []T, f func(T) string) string {
	if len(v) == 1 {
		return f(v[0])
	}
	s := make([]string, len(v))
	for i, x := range v {
		s[i] = f(x)
	}
	return "{ " + strings.Join(s, ", ") + " }"
}

// renderPlan — содержимое цепочек классов и сервисов по плану. Канал
// класса пуст: если класс запрещает часть каналов, новое соединение
// отклоняется (иначе ушло бы по основной таблице — например, в LTE), если
// разрешены все — идёт по основной таблице (fail-open, как до классов).
func renderPlan(c Classify, links []LinkSpec, plan []decision.ClassPlan) string {
	idx := func(id model.LinkID) int {
		return slices.IndexFunc(links, func(l LinkSpec) bool { return l.Link.ID == id })
	}
	byClass := map[model.TrafficClass]decision.ClassPlan{}
	for _, p := range plan {
		byClass[p.Class] = p
	}
	var b strings.Builder
	chain := func(name string, mark uint32, cl model.TrafficClass, set func(i int) string, key string) {
		p := byClass[cl]
		pol := c.Policies[cl]
		fmt.Fprintf(&b, "flush chain inet %s %s\n", nftTable, name)
		if set != nil {
			// update продлевает срок: он отсчитывается от последнего нового
			// соединения устройства, а не от первого (иначе долгая игра или
			// просмотр теряли бы закрепление посреди сессии).
			for _, id := range p.PinLinks {
				if i := idx(id); i >= 0 {
					fmt.Fprintf(&b, "add rule inet %s %s %s @%s update @%s { %s } meta mark set %#x goto commit\n", nftTable, name, key, set(i), set(i), key, links[i].FwMark|mark)
				}
			}
			// Закрепления за каналами вне PinLinks больше не действуют —
			// очищаются, чтобы не ожить при возврате канала.
			for i, l := range links {
				if !slices.Contains(p.PinLinks, l.Link.ID) {
					fmt.Fprintf(&b, "flush set inet %s %s\n", nftTable, set(i))
				}
			}
		}
		// Канал, выбранный резолвером при DNS-запросе (DNS тем же путём, что
		// и трафик), — только среди долей плана: адрес упавшего канала уходит
		// по долям. При одной доле выбирать нечего.
		if len(p.Shares) > 1 {
			for _, s := range p.Shares {
				i := idx(s.Link)
				if i < 0 || s.Weight <= 0 {
					continue
				}
				remember := ""
				if set != nil {
					remember = fmt.Sprintf(" update @%s { %s }", set(i), key)
				}
				fmt.Fprintf(&b, "add rule inet %s %s ip daddr @%s meta mark set %#x%s goto commit\n", nftTable, name, DomainLinkSet(i), links[i].FwMark|mark, remember)
			}
		}
		pick := pickExpr(links, p.Shares, mark)
		switch {
		case pick == "" && len(pol.Allowed) > 0 && len(pol.Allowed) < len(links):
			// TCP — сбросом: клиент узнаёт об отказе сразу, а не по повтору SYN.
			fmt.Fprintf(&b, "add rule inet %s %s meta l4proto tcp reject with tcp reset\n", nftTable, name)
			fmt.Fprintf(&b, "add rule inet %s %s reject\n", nftTable, name)
			return
		case pick == "":
			return
		}
		fmt.Fprintf(&b, "add rule inet %s %s %s\n", nftTable, name, pick)
		if set != nil {
			for _, s := range p.Shares {
				if i := idx(s.Link); i >= 0 {
					fmt.Fprintf(&b, "add rule inet %s %s meta mark and %#x == %#x update @%s { %s }\n", nftTable, name, LinkMarkMask, links[i].FwMark, set(i), key)
				}
			}
		}
		fmt.Fprintf(&b, "add rule inet %s %s goto commit\n", nftTable, name)
	}
	for _, cl := range c.Classes {
		cid := c.classID(cl)
		pol := c.Policies[cl]
		var set func(int) string
		key := "ip saddr"
		if pol.Pin != model.StickNone && pol.Pin != "" && pol.PinTTL > 0 {
			set = func(i int) string { return stickySet(cid, i) }
			if pol.Pin == model.StickDestination {
				key = "ip saddr . ip daddr"
			}
		}
		chain(classChain(cid), c.markOf(cl), cl, set, key)
	}
	for si, svc := range c.Services {
		cl := c.serviceClass(svc)
		chain(serviceChain(si), c.markOf(cl), cl, func(i int) string { return serviceSet(si, i) }, "ip saddr")
	}
	return b.String()
}

// pickExpr — выбор канала новой сессии: один — метка; несколько — jhash
// «устройство + адрес назначения» по весам (как Engine.Decide для balanced).
func pickExpr(links []LinkSpec, shares []decision.LinkShare, mark uint32) string {
	type part struct {
		mark   uint32
		weight int
	}
	var parts []part
	total := 0
	for _, s := range shares {
		i := slices.IndexFunc(links, func(l LinkSpec) bool { return l.Link.ID == s.Link })
		if i >= 0 && s.Weight > 0 {
			parts = append(parts, part{links[i].FwMark | mark, s.Weight})
			total += s.Weight
		}
	}
	switch len(parts) {
	case 0:
		return ""
	case 1:
		return fmt.Sprintf("meta mark set %#x", parts[0].mark)
	}
	var elems []string
	lo := 0
	for _, p := range parts {
		hi := lo + p.weight - 1
		key := fmt.Sprint(lo)
		if hi > lo {
			key += fmt.Sprintf("-%d", hi)
		}
		elems = append(elems, fmt.Sprintf("%s : %#x", key, p.mark))
		lo = hi + 1
	}
	return fmt.Sprintf("meta mark set jhash ip saddr . ip daddr mod %d map { %s }", total, strings.Join(elems, ", "))
}

// initialPlan — до первого плана: каждому классу — первый по приоритету
// канал с маршрутом из разрешённых классу (как прежний стартовый выбор).
func initialPlan(c Classify, links []LinkSpec, routed map[model.LinkID]bool) []decision.ClassPlan {
	var out []decision.ClassPlan
	for _, cl := range c.Classes {
		allowed := c.Policies[cl].Allowed
		var ls []LinkSpec
		for _, l := range links {
			if len(allowed) == 0 || slices.Contains(allowed, l.Link.ID) {
				ls = append(ls, l)
			}
		}
		p := decision.ClassPlan{Class: cl, Pin: c.Policies[cl].Pin, PinTTL: c.Policies[cl].PinTTL}
		p.Shares = firstByPriority(ls, routed)
		for _, s := range p.Shares {
			p.PinLinks = append(p.PinLinks, s.Link)
		}
		out = append(out, p)
	}
	return out
}

func plansEqual(a, b []decision.ClassPlan) bool {
	return slices.EqualFunc(a, b, func(x, y decision.ClassPlan) bool { return x.Equal(y) })
}

// mergePlan — новый план поверх прежнего: классы, которых нет в новом,
// сохраняют прежнее (SetBalance задаёт только default).
func mergePlan(prev, next []decision.ClassPlan) []decision.ClassPlan {
	out := slices.Clone(prev)
	for _, n := range next {
		if i := slices.IndexFunc(out, func(p decision.ClassPlan) bool { return p.Class == n.Class }); i >= 0 {
			out[i] = n
		} else {
			out = append(out, n)
		}
	}
	return out
}
