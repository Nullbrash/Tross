package dataplane

import (
	"cmp"
	"fmt"
	"slices"
	"strings"

	"tross/core/model"
)

// Имена и метки в ядре, которыми владеет демон. Teardown удаляет только их.
const (
	nftTable = "tross"
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
	var wans []string
	for _, l := range spec.Links {
		wans = append(wans, quote(l.Link.Interface))
	}
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
	b.WriteString("\t}\n")
	b.WriteString("\tchain postrouting {\n\t\ttype nat hook postrouting priority srcnat; policy accept;\n")
	if len(wans) > 0 {
		fmt.Fprintf(&b, "\t\toifname { %s } masquerade\n", strings.Join(wans, ", "))
	}
	b.WriteString("\t}\n}\n")
	return b.String()
}

// renderChoose — выбор канала для нового соединения из домашней сети.
// Пока — первый пригодный по приоритету; ни одного пригодного — метка не
// ставится, и соединение идёт по основной таблице (fail-open).
func renderChoose(links []LinkSpec, usable map[model.LinkID]bool) string {
	var b strings.Builder
	fmt.Fprintf(&b, "flush chain inet %s choose\n", nftTable)
	if l, ok := firstUsable(links, usable); ok {
		fmt.Fprintf(&b, "add rule inet %s choose meta mark set %#x ct mark set meta mark\n", nftTable, l.FwMark)
	}
	return b.String()
}

func firstUsable(links []LinkSpec, usable map[model.LinkID]bool) (LinkSpec, bool) {
	order := slices.Clone(links)
	// Стабильная сортировка: при равном приоритете решает порядок конфигурации.
	slices.SortStableFunc(order, func(a, b LinkSpec) int { return cmp.Compare(a.Link.Priority, b.Link.Priority) })
	for _, l := range order {
		if usable[l.Link.ID] {
			return l, true
		}
	}
	return LinkSpec{}, false
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
