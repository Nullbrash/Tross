package dataplane

import (
	"fmt"
	"strings"

	"tross/core/model"
)

const (
	// TinMarkMask — биты метки с корзиной CAKE (1 — фон … 4 — голос):
	// CAKE выбирает корзину по ним (fwmark). Не пересекаются с каналом,
	// классом, метками прокси (0x00ff0000) и zapret (0x40000000) — совпадает
	// с config.TinMarkMask.
	TinMarkMask uint32 = 0x07000000
	tinShift    uint32 = 24
)

// Shaping — скорость очередей канала, бит/с; 0 — без ограничения (корзины
// и деление по устройствам работают, только когда очередь копится у нас).
type Shaping struct {
	Link     model.LinkID
	DownBps  uint64
	UpBps    uint64
	Disabled bool // sqm.enabled: false — очередей на канале нет
}

// ifbName — устройство входящей очереди канала: имя по номеру канала в
// спецификации, т. к. имя интерфейса канала может быть длиннее 15 байт.
func ifbName(linkIdx int) string { return fmt.Sprintf("ifb-tross%d", linkIdx) }

// bandwidth — параметр скорости CAKE: без ограничения — отдельное слово,
// «bandwidth unlimited» tc отвергает.
func bandwidth(bps uint64) string {
	if bps == 0 {
		return "unlimited"
	}
	return fmt.Sprintf("bandwidth %dbit", bps)
}

// cakeOpts — CAKE канала. diffserv4 — корзины; dual-srchost (выход) и
// dual-dsthost (вход) делят канал поровну между устройствами дома, nat —
// устройства видны за masquerade; fwmark — корзина из метки класса;
// ingress — на входе отброшенное тоже считается в скорость.
func cakeOpts(bps uint64, ingress bool) string {
	hosts := "dual-srchost"
	extra := ""
	if ingress {
		hosts, extra = "dual-dsthost", " ingress"
	}
	return fmt.Sprintf("%s diffserv4 %s nat%s fwmark %#x", bandwidth(bps), hosts, extra, TinMarkMask)
}

// renderShapingSetup — очереди канала для `tc -batch`: выход — CAKE на
// интерфейсе канала; вход — перенаправление в IFB с восстановлением метки
// из conntrack (входящие пакеты ещё до NAT и до правил nftables, корзина —
// из метки соединения) и CAKE на IFB. Очереди — replace; фильтр matchall
// заменить нельзя (повтор — «File exists»), его прежде снимает
// renderShapingFilterDel. Устройство IFB создаётся отдельно (netlink).
func renderShapingSetup(iface, ifb string, sh Shaping) string {
	var b strings.Builder
	fmt.Fprintf(&b, "qdisc replace dev %s root cake %s\n", iface, cakeOpts(sh.UpBps, false))
	fmt.Fprintf(&b, "qdisc replace dev %s handle ffff: ingress\n", iface)
	fmt.Fprintf(&b, "filter add dev %s parent ffff: pref 49152 handle 1 matchall action connmark action mirred egress redirect dev %s\n", iface, ifb)
	fmt.Fprintf(&b, "qdisc replace dev %s root cake %s\n", ifb, cakeOpts(sh.DownBps, true))
	return b.String()
}

// renderShapingFilterDel — снять фильтр перенаправления перед повторной
// установкой; запускается с -force (фильтра может не быть).
func renderShapingFilterDel(iface string) string {
	return fmt.Sprintf("filter del dev %s parent ffff: pref 49152\n", iface)
}

// renderShapingRates — смена скорости без пересоздания: очередь не
// сбрасывается, соединения не замечают.
func renderShapingRates(iface, ifb string, sh Shaping) string {
	return fmt.Sprintf("qdisc change dev %s root cake %s\nqdisc change dev %s root cake %s\n",
		iface, bandwidth(sh.UpBps), ifb, bandwidth(sh.DownBps))
}

// renderShapingRemove — снять очереди канала (purge и sqm.enabled: false);
// ошибки «нет такой» ожидаемы — команды идут с -force.
func renderShapingRemove(iface string) string {
	return fmt.Sprintf("qdisc del dev %s root\nqdisc del dev %s handle ffff: ingress\n", iface, iface)
}
