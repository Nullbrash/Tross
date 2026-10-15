package dataplane

import (
	"cmp"
	"fmt"
	"slices"
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
	c := spec.Classify.withDefault()
	var b strings.Builder
	fmt.Fprintf(&b, "add table inet %s\ndelete table inet %s\n", nftTable, nftTable)
	fmt.Fprintf(&b, "table inet %s {\n", nftTable)
	fmt.Fprintf(&b, "\tset %s {\n\t\ttype ipv4_addr\n\t\tflags timeout\n\t}\n", SetDPI)
	fmt.Fprintf(&b, "\tset %s {\n\t\ttype ipv4_addr\n\t\tflags timeout\n\t}\n", SetProxy)
	b.WriteString(renderClassifySets(c, spec.Links))
	b.WriteString(renderClassifyChains(c))
	b.WriteString("\tchain prerouting {\n\t\ttype filter hook prerouting priority mangle; policy accept;\n")
	b.WriteString(renderBTGuard(c, spec.Links, spec.LANInterface))
	// Метка (канал и класс) восстанавливается для всех пакетов соединения,
	// включая ответы из канала: так rp_filter (src_valid_mark=1) находит
	// обратный путь через таблицу канала, а соединение никогда не переезжает.
	fmt.Fprintf(&b, "\t\tct mark and %#x != 0 meta mark set ct mark and %#x return\n", LinkMarkMask, LinkMarkMask|classMarkMask)
	fmt.Fprintf(&b, "\t\tiifname %s ct state new jump classify\n", quote(spec.LANInterface))
	b.WriteString(renderForwardMarks(spec))
	b.WriteString("\t}\n")
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
	b.WriteString(renderForwardNAT(spec))
	b.WriteString("\tchain postrouting {\n\t\ttype nat hook postrouting priority srcnat; policy accept;\n")
	if len(wans) > 0 {
		fmt.Fprintf(&b, "\t\toifname { %s } masquerade\n", strings.Join(wans, ", "))
	}
	b.WriteString("\t}\n}\n")
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
