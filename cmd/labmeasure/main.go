// Команда labmeasure — сборщик замеров ресурсов на стенде (только Linux):
// раз в interval пишет system.csv и net.csv, по завершении — summary.txt.
//
//	labmeasure -out ~/lab-results/2026-10-11-idle -duration 60s -proc trossd -netns tl-tross
package main

import (
	"context"
	"encoding/csv"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"tross/internal/lab/measure"
)

func main() {
	out := flag.String("out", "", "output directory (created)")
	interval := flag.Duration("interval", time.Second, "sampling interval")
	duration := flag.Duration("duration", 0, "stop after this long; 0 — until SIGINT/SIGTERM")
	proc := flag.String("proc", "trossd", "process name to track; empty — none")
	netns := flag.String("netns", "", "comma-separated network namespaces to count interfaces in")
	disk := flag.String("disk", "sda", "block device for write counter")
	flag.Parse()
	if *out == "" {
		fmt.Fprintln(os.Stderr, "labmeasure: -out is required")
		os.Exit(2)
	}
	if err := run(*out, *interval, *duration, measure.Options{Disk: *disk, Process: *proc, Netns: splitList(*netns)}); err != nil {
		fmt.Fprintln(os.Stderr, "labmeasure:", err)
		os.Exit(1)
	}
}

func splitList(s string) []string {
	var out []string
	for p := range strings.SplitSeq(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func run(dir string, interval, duration time.Duration, o measure.Options) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	sysF, err := os.Create(filepath.Join(dir, "system.csv"))
	if err != nil {
		return err
	}
	defer sysF.Close()
	netF, err := os.Create(filepath.Join(dir, "net.csv"))
	if err != nil {
		return err
	}
	defer netF.Close()
	sysW, netW := csv.NewWriter(sysF), csv.NewWriter(netF)
	_ = sysW.Write(measure.SystemHeader)
	_ = netW.Write(measure.NetHeader)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if duration > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, duration)
		defer cancel()
	}

	start, err := measure.Take(o)
	if err != nil {
		return err
	}
	prev := start
	var sum measure.Summary
	t := time.NewTicker(interval)
	defer t.Stop()
loop:
	for {
		select {
		case <-ctx.Done():
			break loop
		case <-t.C:
		}
		cur, err := measure.Take(o)
		if err != nil {
			return err
		}
		row, nets := measure.Diff(start, prev, cur)
		_ = sysW.Write(row.Record())
		for _, n := range nets {
			_ = netW.Write(n.Record())
		}
		// Сбрасываем каждую выборку: прогон могут прервать kill-ом.
		sysW.Flush()
		netW.Flush()
		sum.Add(row, nets)
		prev = cur
	}

	sf, err := os.Create(filepath.Join(dir, "summary.txt"))
	if err != nil {
		return err
	}
	defer sf.Close()
	fmt.Fprintf(sf, "started: %s\n", start.At.Format(time.RFC3339))
	sum.Write(sf, prev.At.Sub(start.At).Seconds())
	sum.Write(os.Stdout, prev.At.Sub(start.At).Seconds())
	return sysW.Error()
}
