package dataplane

import (
	"cmp"
	"fmt"
	"slices"
	"strconv"
	"strings"

	"tross/core/decision"
	"tross/core/model"
)

// Имена и метки в ядре, которыми владеет демон: снимаются только они.
const (
	nftTable = "tross"
	// nftNATTable — masquerade на каналах. Отдельно от nftTable: остановка
	// демона её не снимает, чтобы домашняя сеть продолжала работать через
	// основную таблицу маршрутизации (fail-open); убирает только
	// Cleanup с purge (удаление Tross).
	nftNATTable = "tross_nat"
	// LinkMarkMask — биты fwmark/ct mark с номером канала (совпадает с config.LinkMarkMask).
	LinkMarkMask uint32 = 0x0000ff00
	// rulePrefBase — приоритет правила suppress_prefixlength; правила каналов идут следом.
	// Все ip rule демона лежат в [rulePrefBase, rulePrefBase+rulePrefSpan).
	rulePrefBase = 10000
	rulePrefSpan = 256
)

// renderBase — полное описание таблицы inet tross одной транзакцией.
// Пара «add table; delete table» делает загрузку идемпотентной: старая
// таблица (например, после аварийного завершения) заменяется целиком.
func renderBase(spec Spec) string {
	var b strings.Builder
	fmt.Fprintf(&b, "add table inet %s\ndelete table inet %s\n", nftTable, nftTable)
	fmt.Fprintf(&b, "table inet %s {\n", nftTable)
	fmt.Fprintf(&b, "\tset %s {\n\t\ttype ipv4_addr\n\t\tflags timeout\n\t}\n", SetDPI)
	fmt.Fprintf(&b, "\tset %s {\n\t\ttype ipv4_addr\n\t\tflags timeout\n\t}\n", SetProxy)
	b.WriteString("\tchain prerouting {\n\t\ttype filter hook prerouting priority mangle; policy accept;\n")
	// Метка восстанавливается для всех пакетов соединения, включая ответы
	// из канала: так rp_filter (src_valid_mark=1) находит обратный путь
	// через таблицу канала, а соединение никогда не переезжает.
	fmt.Fprintf(&b, "\t\tct mark and %#x != 0 meta mark set ct mark and %#x return\n", LinkMarkMask, LinkMarkMask)
	fmt.Fprintf(&b, "\t\tiifname %s ct state new jump choose\n", quote(spec.LANInterface))
	b.WriteString("\t}\n")
	b.WriteString("\tchain choose {\n\t}\n")
	// Собственный трафик машины с меткой канала на сокете (пробы монитора,
	// замер скорости, позже — DNS и прокси-ядро): метка сохраняется в
	// соединении, иначе ответ придёт без неё и rp_filter его отбросит.
	b.WriteString("\tchain output {\n\t\ttype route hook output priority mangle; policy accept;\n")
	fmt.Fprintf(&b, "\t\tmeta mark and %#x != 0 ct mark set meta mark and %#x\n", LinkMarkMask, LinkMarkMask)
	b.WriteString("\t}\n}\n")
	return b.String()
}

// renderNAT — таблица masquerade на интерфейсах каналов; заменяется целиком.
func renderNAT(spec Spec) string {
	var wans []string
	for _, l := range spec.Links {
		wans = append(wans, quote(l.Link.Interface))
	}
	var b strings.Builder
	fmt.Fprintf(&b, "add table inet %s\ndelete table inet %s\n", nftNATTable, nftNATTable)
	fmt.Fprintf(&b, "table inet %s {\n", nftNATTable)
	b.WriteString("\tchain postrouting {\n\t\ttype nat hook postrouting priority srcnat; policy accept;\n")
	if len(wans) > 0 {
		fmt.Fprintf(&b, "\t\toifname { %s } masquerade\n", strings.Join(wans, ", "))
	}
	b.WriteString("\t}\n}\n")
	return b.String()
}

// renderChoose — выбор канала для нового соединения из домашней сети по
// распределению. Ни одного канала — метка не ставится, и соединение идёт по
// основной таблице (fail-open). Несколько — jhash от пары «устройство +
// адрес назначения»: одно устройство к одному серверу всегда через один
// канал (сайты не видят смены IP), разные серверы расходятся по весам.
func renderChoose(links []LinkSpec, shares []decision.LinkShare) string {
	marks := make(map[model.LinkID]uint32, len(links))
	for _, l := range links {
		marks[l.Link.ID] = l.FwMark
	}
	type part struct {
		mark   uint32
		weight int
	}
	var parts []part
	total := 0
	for _, s := range shares {
		if m, ok := marks[s.Link]; ok && s.Weight > 0 {
			parts = append(parts, part{m, s.Weight})
			total += s.Weight
		}
	}
	var b strings.Builder
	fmt.Fprintf(&b, "flush chain inet %s choose\n", nftTable)
	switch len(parts) {
	case 0:
	case 1:
		fmt.Fprintf(&b, "add rule inet %s choose meta mark set %#x ct mark set meta mark\n", nftTable, parts[0].mark)
	default:
		var elems []string
		lo := 0
		for _, p := range parts {
			hi := lo + p.weight - 1
			key := strconv.Itoa(lo)
			if hi > lo {
				key += "-" + strconv.Itoa(hi)
			}
			elems = append(elems, fmt.Sprintf("%s : %#x", key, p.mark))
			lo = hi + 1
		}
		fmt.Fprintf(&b, "add rule inet %s choose meta mark set jhash ip saddr . ip daddr mod %d map { %s } ct mark set meta mark\n",
			nftTable, total, strings.Join(elems, ", "))
	}
	return b.String()
}

// firstByPriority — канал для Setup до первого решения балансировщика.
func firstByPriority(links []LinkSpec, routed map[model.LinkID]bool) []decision.LinkShare {
	order := slices.Clone(links)
	// Стабильная сортировка: при равном приоритете решает порядок конфигурации.
	slices.SortStableFunc(order, func(a, b LinkSpec) int { return cmp.Compare(a.Link.Priority, b.Link.Priority) })
	for _, l := range order {
		if routed[l.Link.ID] {
			return []decision.LinkShare{{Link: l.Link.ID, Weight: 1}}
		}
	}
	return nil
}

func renderAddElement(set SetName, addr string, ttlSec int64) string {
	return fmt.Sprintf("add element inet %s %s { %s timeout %ds }\n", nftTable, set, addr, ttlSec)
}

// quote — имя интерфейса как строковый литерал nft. Имена приходят из
// проверенного конфига, но кавычки и обратная косая черта всё равно недопустимы.
func quote(s string) string { return `"` + s + `"` }

func validIfname(s string) bool {
	if s == "" || len(s) > 15 {
		return false
	}
	return !strings.ContainsAny(s, "\"\\ \t\n/")
}
