package dataplane

import (
	"errors"
	"fmt"
	"strings"
)

// DPIMark — бит метки пакетов, которые движок обхода (nfqws2) отправил сам:
// они не возвращаются в очередь и не проходят conntrack; остальные биты их
// метки движок берёт у исходного пакета (канал соединения) — по ним ip rule
// ведёт их в канал. У обычного трафика этого бита нет: движок считает своим
// любой пакет хоть с одним битом своей метки. Совпадает с меткой nfqws2 по
// умолчанию и с config.DPIMarkMask.
const DPIMark uint32 = 0x40000000

// SetDPIDevices — устройства со своим зашифрованным DNS: их адреса в
// множества обхода не попадают, поэтому первые пакеты их TLS — в очередь
// канала целиком, имя проверяет hostlist движка.
const SetDPIDevices SetName = "tross_dpidev4"

// DPISet — адреса доменов, которым на канале нужен обход.
func DPISet(i int) SetName { return SetName(fmt.Sprintf("tross_dpi%d", i)) }

// DPILink — канал с движком обхода: номер канала в Spec.Links и очередь.
type DPILink struct {
	Index int
	Queue uint16
}

// DPISpec — обход DPI; без каналов — правил нет.
type DPISpec struct {
	Links []DPILink
}

func validateDPI(spec Spec) error {
	seen := map[uint16]bool{}
	var errs []error
	for _, l := range spec.DPI.Links {
		if l.Index < 0 || l.Index >= len(spec.Links) {
			errs = append(errs, fmt.Errorf("dpi: link index %d out of range", l.Index))
		}
		if seen[l.Queue] {
			errs = append(errs, fmt.Errorf("dpi: queue %d used twice", l.Queue))
		}
		seen[l.Queue] = true
	}
	return errors.Join(errs...)
}

// Пакетов соединения в очередь: SYN, ACK и ClientHello (с запасом на
// ClientHello в нескольких сегментах) — дальше движку делать нечего, а
// переход в программу дорог. Ответы — первые: детекторам нужен RST сервера.
const (
	dpiOutPackets = "1-6"
	dpiInPackets  = "1-3"
)

// renderDPI — множества и цепочки обхода внутри inet tross. Очередь — с
// bypass: нет движка (упал, не запущен) — пакеты идут мимо (fail-open).
// Исходящие — после masquerade (как у движка на роутере: адрес канала),
// входящие — до обратного NAT.
func renderDPI(spec Spec) string {
	var b strings.Builder
	for _, l := range spec.DPI.Links {
		fmt.Fprintf(&b, "\tset %s {\n\t\ttype ipv4_addr\n\t\tflags timeout\n\t}\n", DPISet(l.Index))
	}
	if len(spec.DPI.Links) == 0 {
		return b.String()
	}
	fmt.Fprintf(&b, "\tset %s {\n\t\ttype ipv4_addr\n\t\tflags timeout\n\t}\n", SetDPIDevices)

	b.WriteString("\tchain dpi_post {\n\t\ttype filter hook postrouting priority srcnat + 1; policy accept;\n")
	fmt.Fprintf(&b, "\t\tmeta mark and %#x != 0 return\n", DPIMark)
	for _, l := range spec.DPI.Links {
		wan, q, set := quote(spec.Links[l.Index].Link.Interface), l.Queue, DPISet(l.Index)
		fmt.Fprintf(&b, "\t\toifname %s tcp dport { 80, 443 } ct original packets %s ip daddr @%s counter queue num %d bypass\n", wan, dpiOutPackets, set, q)
		fmt.Fprintf(&b, "\t\toifname %s tcp dport 443 ct original packets %s ct original ip saddr @%s counter queue num %d bypass\n", wan, dpiOutPackets, SetDPIDevices, q)
	}
	b.WriteString("\t}\n")

	b.WriteString("\tchain dpi_pre {\n\t\ttype filter hook prerouting priority dstnat - 1; policy accept;\n")
	for _, l := range spec.DPI.Links {
		wan, q, set := quote(spec.Links[l.Index].Link.Interface), l.Queue, DPISet(l.Index)
		fmt.Fprintf(&b, "\t\tiifname %s tcp sport { 80, 443 } ct reply packets %s ip saddr @%s counter queue num %d bypass\n", wan, dpiInPackets, set, q)
		fmt.Fprintf(&b, "\t\tiifname %s tcp sport 443 ct reply packets %s ct original ip saddr @%s counter queue num %d bypass\n", wan, dpiInPackets, SetDPIDevices, q)
	}
	b.WriteString("\t}\n")

	// QUIC к доменам обхода — отказ: браузер уходит на TCP, где обход
	// работает; остальной QUIC не трогается.
	b.WriteString("\tchain dpi_fwd {\n\t\ttype filter hook forward priority filter - 1; policy accept;\n")
	for _, l := range spec.DPI.Links {
		fmt.Fprintf(&b, "\t\toifname %s udp dport 443 ip daddr @%s counter reject\n", quote(spec.Links[l.Index].Link.Interface), DPISet(l.Index))
	}
	b.WriteString("\t}\n")

	// Пакеты движка — мимо conntrack: это части чужого соединения, а не
	// новые соединения машины.
	b.WriteString("\tchain dpi_raw {\n\t\ttype filter hook output priority raw; policy accept;\n")
	fmt.Fprintf(&b, "\t\tmeta mark and %#x != 0 notrack\n", DPIMark)
	b.WriteString("\t}\n")
	return b.String()
}
