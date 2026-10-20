package dataplane

import (
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"

	"tross/core/model"
	"tross/core/profile"
)

// PortForward — ручной проброс (D-43): новые соединения из интернета на
// порт канала уходят устройству LAN.
type PortForward struct {
	Name   string
	Protos []model.Protocol
	Ports  profile.PortRange
	// To — адрес устройства; пуст — устройство пока без адреса: проброс не
	// действует (входящие на порт отбрасываются фильтром), пока адрес не
	// придёт через SetDevices.
	To netip.Addr
	// ToPort — порт на устройстве; 0 — тот же, что снаружи (для диапазона — только так).
	ToPort uint16
	// Links — каналы, на которых открыт проброс; пусто — все.
	Links []model.LinkID
}

// InboundGuard — защита пробросов, общая для всех: частота новых
// соединений с одного адреса и число одновременных.
type InboundGuard struct {
	NewPerMinute int
	Burst        int
	MaxConns     int
}

const (
	setInRate = "tross_in_rate"
	setInConn = "tross_in_conn"
	// guardSetSize — предел адресов в множествах защиты: при наплыве с
	// множества адресов память ядра не растёт без границы.
	guardSetSize = 65535
)

func validateForwards(spec Spec) error {
	var errs []error
	for _, f := range spec.Forwards {
		if f.To.IsValid() && !f.To.Is4() {
			errs = append(errs, fmt.Errorf("forward %s: target %s is not IPv4", f.Name, f.To))
		}
		if f.Ports.From == 0 || f.Ports.To < f.Ports.From {
			errs = append(errs, fmt.Errorf("forward %s: bad ports %d-%d", f.Name, f.Ports.From, f.Ports.To))
		}
		if f.ToPort != 0 && f.Ports.To != f.Ports.From {
			errs = append(errs, fmt.Errorf("forward %s: target port with a port range", f.Name))
		}
		if len(f.Protos) == 0 {
			errs = append(errs, fmt.Errorf("forward %s: no protocol", f.Name))
		}
		for _, p := range f.Protos {
			if p != model.ProtoTCP && p != model.ProtoUDP {
				errs = append(errs, fmt.Errorf("forward %s: bad protocol %q", f.Name, p))
			}
		}
		for _, id := range f.Links {
			if !slices.ContainsFunc(spec.Links, func(l LinkSpec) bool { return l.Link.ID == id }) {
				errs = append(errs, fmt.Errorf("forward %s: unknown link %q", f.Name, id))
			}
		}
	}
	if len(spec.Forwards) > 0 && (spec.Guard.NewPerMinute <= 0 || spec.Guard.Burst <= 0 || spec.Guard.MaxConns <= 0) {
		errs = append(errs, errors.New("inbound guard: limits must be positive"))
	}
	return errors.Join(errs...)
}

// forwardLinks — каналы проброса в порядке спецификации.
func forwardLinks(spec Spec, f PortForward) []LinkSpec {
	var out []LinkSpec
	for _, l := range spec.Links {
		if len(f.Links) == 0 || slices.Contains(f.Links, l.Link.ID) {
			out = append(out, l)
		}
	}
	return out
}

// forwardMatch — «пришло на порт проброса»: протоколы и порты.
func forwardMatch(f PortForward) string {
	protos := make([]string, len(f.Protos))
	for i, p := range f.Protos {
		protos[i] = string(p)
	}
	l4 := "meta l4proto " + protos[0]
	if len(protos) > 1 {
		l4 = "meta l4proto { " + strings.Join(protos, ", ") + " }"
	}
	port := fmt.Sprint(f.Ports.From)
	if f.Ports.To != f.Ports.From {
		port += fmt.Sprintf("-%d", f.Ports.To)
	}
	return l4 + " th dport " + port
}

// renderForwardMarks — правила для цепочки prerouting таблицы tross: новое
// входящее на проброс помечается каналом, через который пришло. Метка
// восстанавливается для ответов устройства (общее правило восстановления),
// и они уходят в тот же канал: иначе ответ через другой канал шёл бы с
// чужим адресом и терялся. Метка самого пакета нужна rp_filter: обратный
// путь к адресу из интернета — через канал, а не через основную таблицу.
func renderForwardMarks(spec Spec) string {
	var b strings.Builder
	for _, f := range spec.Forwards {
		for _, l := range forwardLinks(spec, f) {
			fmt.Fprintf(&b, "\t\tiifname %s %s ct state new meta mark set %#x ct mark set %#x\n", quote(l.Link.Interface), forwardMatch(f), l.FwMark, l.FwMark)
		}
	}
	return b.String()
}

// renderForwardNAT — множества и цепочки пробросов внутри таблицы tross_nat:
// проброс и защита переживают остановку демона вместе с NAT (D-44) —
// сервер остаётся доступен через основной канал и не теряет защиту.
func renderForwardNAT(spec Spec) string {
	if len(spec.Forwards) == 0 {
		return ""
	}
	g := spec.Guard
	var b strings.Builder
	// Срок записи частоты — пока окно «в минуту» ещё может что-то значить.
	fmt.Fprintf(&b, "\tset %s {\n\t\ttype ipv4_addr\n\t\tsize %d\n\t\tflags dynamic,timeout\n\t\ttimeout 2m\n\t}\n", setInRate, guardSetSize)
	fmt.Fprintf(&b, "\tset %s {\n\t\ttype ipv4_addr\n\t\tsize %d\n\t\tflags dynamic\n\t}\n", setInConn, guardSetSize)
	// Защита — до DNAT (dstnat - 10): отброшенное не доходит до устройства
	// и не занимает запись conntrack.
	b.WriteString("\tchain guard {\n\t\ttype filter hook prerouting priority dstnat - 10; policy accept;\n")
	for _, f := range spec.Forwards {
		fmt.Fprintf(&b, "\t\tiifname { %s } %s ct state new jump inbound\n", ifnames(forwardLinks(spec, f)), forwardMatch(f))
	}
	b.WriteString("\t}\n")
	b.WriteString("\tchain inbound {\n")
	fmt.Fprintf(&b, "\t\tadd @%s { ip saddr limit rate over %d/minute burst %d packets } counter drop\n", setInRate, g.NewPerMinute, g.Burst)
	fmt.Fprintf(&b, "\t\tadd @%s { ip saddr ct count over %d } counter drop\n", setInConn, g.MaxConns)
	b.WriteString("\t}\n")
	b.WriteString("\tchain prerouting {\n\t\ttype nat hook prerouting priority dstnat; policy accept;\n")
	for _, f := range spec.Forwards {
		if !f.To.IsValid() {
			continue
		}
		to := f.To.String()
		if f.ToPort != 0 {
			to = netip.AddrPortFrom(f.To, f.ToPort).String()
		}
		fmt.Fprintf(&b, "\t\tiifname { %s } %s dnat ip to %s\n", ifnames(forwardLinks(spec, f)), forwardMatch(f), to)
	}
	b.WriteString("\t}\n")
	return b.String()
}

// renderInboundFilter — из каналов пересылаются только ответы на свои
// соединения и пробросы; всё прочее (в том числе пакеты на адреса LAN,
// если их направит к нам кто-то в сети провайдера) отбрасывается, как на
// обычном роутере. Живёт в tross_nat: защита не должна пропадать вместе с
// демоном, а исходящим соединениям LAN она не мешает и без него.
func renderInboundFilter(spec Spec) string {
	if len(spec.Links) == 0 {
		return ""
	}
	wans := ifnames(spec.Links)
	var b strings.Builder
	b.WriteString("\tchain forward {\n\t\ttype filter hook forward priority filter; policy accept;\n")
	fmt.Fprintf(&b, "\t\tiifname { %s } ct state established,related accept\n", wans)
	fmt.Fprintf(&b, "\t\tiifname { %s } ct status dnat accept\n", wans)
	fmt.Fprintf(&b, "\t\tiifname { %s } counter drop\n", wans)
	b.WriteString("\t}\n")
	return b.String()
}

func ifnames(links []LinkSpec) string {
	names := make([]string, len(links))
	for i, l := range links {
		names[i] = quote(l.Link.Interface)
	}
	return strings.Join(names, ", ")
}
