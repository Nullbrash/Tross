// Команда labdevices — разовое прослушивание сети стендом: что устройства
// сами сообщают о себе (DHCP, ARP, mDNS, SSDP) и что из этого угадывает
// реестр. Только чтение плюс один запрос имени mDNS новому устройству: ни
// правил ядра, ни раздачи адресов, ни пробного DHCP.
//
//	labdevices -iface <интерфейс> -duration 30m -out report.json
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"slices"
	"strings"
	"syscall"
	"time"

	coredevices "tross/core/devices"
	"tross/core/model"
	"tross/internal/devices"
	"tross/internal/store"
)

type row struct {
	model.Device
	Guess     model.DeviceType `json:"guess"`
	Suggested string           `json:"suggested_name,omitempty"`
}

func main() {
	iface := flag.String("iface", "", "interface to listen on")
	dur := flag.Duration("duration", 30*time.Minute, "how long (at most 1h)")
	out := flag.String("out", "labdevices.json", "report")
	flag.Parse()
	if *iface == "" || *dur <= 0 || *dur > time.Hour {
		fmt.Fprintln(os.Stderr, "usage: labdevices -iface IF -duration D (<= 1h) -out FILE")
		os.Exit(2)
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	nets, err := ifaceNets(*iface)
	if err != nil || len(nets) == 0 {
		log.Error("interface networks", "err", err)
		os.Exit(1)
	}
	st, err := store.Open("", store.DefaultRetention())
	if err != nil {
		log.Error("store", "err", err)
		os.Exit(1)
	}
	defer st.Close()
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	ctx, cancelT := context.WithTimeout(ctx, *dur)
	defer cancelT()
	var srcs *devices.Sources
	svc, err := devices.New(ctx, devices.Options{Store: st, Log: log, Probe: func(d model.Device) {
		if srcs != nil {
			srcs.Probe(d)
		}
	}})
	if err != nil {
		log.Error("registry", "err", err)
		os.Exit(1)
	}
	srcs, err = devices.NewSources(devices.SourceOptions{Interface: *iface, Networks: nets, Log: log,
		Observe: func(o devices.Observation) { _ = svc.Observe(ctx, o) }})
	if err != nil {
		log.Error("sources", "err", err)
		os.Exit(1)
	}
	log.Info("listening", "networks", nets, "for", *dur)
	srcs.Run(ctx)

	var rows []row
	for _, d := range svc.List() {
		rows = append(rows, row{Device: d, Guess: coredevices.GuessType(d.Hints), Suggested: coredevices.SuggestName(d.Hints)})
	}
	slices.SortFunc(rows, func(a, b row) int { return a.Addr.Compare(b.Addr) })
	b, _ := json.MarshalIndent(rows, "", "  ")
	if err := os.WriteFile(*out, b, 0o600); err != nil {
		log.Error("report", "err", err)
		os.Exit(1)
	}
	var types []string
	for _, r := range rows {
		types = append(types, string(r.Type))
	}
	log.Info("done", "devices", len(rows), "types", strings.Join(types, ","), "report", *out)
}

func ifaceNets(name string) ([]netip.Prefix, error) {
	ifc, err := net.InterfaceByName(name)
	if err != nil {
		return nil, err
	}
	as, err := ifc.Addrs()
	if err != nil {
		return nil, err
	}
	var out []netip.Prefix
	for _, a := range as {
		if n, ok := a.(*net.IPNet); ok {
			if p, err := netip.ParsePrefix(n.String()); err == nil && p.Addr().Is4() {
				out = append(out, p.Masked())
			}
		}
	}
	return out, nil
}
