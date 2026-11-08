// tross-keycheck-lab запускается только на изолированном Linux-стенде.
// По умолчанию команда делает лишь офлайн-предконтроль; -run обязателен
// для сетевых попыток с импортированными ключами.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"runtime"
	"sort"
	"strings"
	"time"

	"tross/core/keycheck"
	"tross/internal/keycheckprobe"
)

var targets = []keycheck.Target{
	{Name: "youtube", URL: "https://www.youtube.com/"},
	{Name: "discord", URL: "https://discord.com/"},
	{Name: "telegram", URL: "https://web.telegram.org/"},
	{Name: "twitch", URL: "https://www.twitch.tv/"},
	{Name: "duckduckgo", URL: "https://duckduckgo.com/"},
	{Name: "cloudflare_204", URL: "http://cp.cloudflare.com/generate_204"},
	{Name: "msft_connecttest", URL: "http://www.msftconnecttest.com/connecttest.txt"},
}

func main() {
	input := flag.String("input", "", "локальный файл с раскрытыми конечными ключами")
	stateDir := flag.String("state-dir", "", "закрытый каталог состояния")
	resultsDir := flag.String("results-dir", "", "закрытый каталог результатов")
	singBox := flag.String("sing-box", "", "путь к sing-box на стенде")
	run := flag.Bool("run", false, "разрешить ограниченные сетевые пробы")
	workers := flag.Int("workers", keycheck.MaxWorkers, "не более 10")
	timeout := flag.Duration("timeout", 10*time.Second, "строго 10 секунд на цель")
	flag.Parse()

	if err := execute(*input, *stateDir, *resultsDir, *singBox, *run, *workers, *timeout); err != nil {
		fmt.Fprintln(os.Stderr, "keycheck:", err)
		os.Exit(1)
	}
}

func execute(input, stateDir, resultsDir, singBox string, run bool, workers int, timeout time.Duration) error {
	if input == "" || stateDir == "" {
		return errors.New("input and state-dir are required")
	}
	if workers < 1 || workers > keycheck.MaxWorkers {
		return fmt.Errorf("workers must be within 1..%d", keycheck.MaxWorkers)
	}
	if timeout != 10*time.Second {
		return errors.New("timeout must be exactly 10s")
	}
	checkpoint, err := keycheck.LoadCheckpoint(stateDir)
	if err != nil {
		return err
	}
	records, skipped, err := loadRecords(input, checkpoint)
	if err != nil {
		return err
	}
	if !run {
		fmt.Printf("offline_ready=%d skipped=%d targets=%d workers=%d timeout=%s\n", len(records), skipped, len(targets), workers, timeout)
		return nil
	}
	if runtime.GOOS != "linux" {
		return errors.New("live run is permitted only on Linux tross-lab")
	}
	if resultsDir == "" || singBox == "" {
		return errors.New("results-dir and sing-box are required with -run")
	}
	prober := &keycheckprobe.SingBoxProber{Binary: singBox, WorkDir: stateDir}
	runner := keycheck.Runner{Workers: workers, Timeout: timeout, Targets: targets, Selector: proxySelector{}, Prober: prober}
	if _, err := runner.RunCheckpointed(context.Background(), checkpoint, stateDir, records); err != nil {
		return err
	}
	// Аварийно прерванная, но уже начатая запись не должна запускаться вновь.
	// Она получает честный промежуточный итог, чтобы сводка была полной.
	for _, record := range records {
		if checkpoint.Started[record.ID] && checkpoint.Results[record.ID].RecordID == "" {
			checkpoint.MarkCompleted(keycheck.Result{RecordID: record.ID, Status: "inconclusive", Attempts: []keycheck.Attempt{{Status: keycheck.Inconclusive, Reason: "interrupted"}}})
		}
	}
	if err := checkpoint.Save(stateDir); err != nil {
		return err
	}
	all := make([]keycheck.Result, 0, len(checkpoint.Results))
	for _, result := range checkpoint.Results {
		all = append(all, result)
	}
	sort.Slice(all, func(i, j int) bool { return all[i].RecordID < all[j].RecordID })
	if len(all) != len(records) {
		return errors.New("incomplete run: results are retained only in state")
	}
	return keycheck.WriteOutputs(resultsDir, records, all)
}

func loadRecords(path string, checkpoint *keycheck.Checkpoint) ([]keycheck.Record, int, error) {
	if len(checkpoint.Records) != 0 {
		records := make([]keycheck.Record, 0, len(checkpoint.Records))
		for _, record := range checkpoint.Records {
			records = append(records, record)
		}
		return records, 0, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, 0, err
	}
	records, invalid := keycheck.Parse(strings.Split(string(data), "\n"))
	accepted := make([]keycheck.Record, 0, len(records))
	skipped := len(invalid)
	for _, record := range records {
		spec, err := keycheck.ParseURI(record.Raw)
		if err != nil || spec.Type == "shadowsocks" {
			skipped++
			continue
		}
		accepted = append(accepted, record)
	}
	return accepted, skipped, nil
}

type proxySelector struct{}

func (proxySelector) Route(record keycheck.Record, target keycheck.Target) keycheck.Route {
	if record.Kind != keycheck.Outbound {
		return keycheck.RouteBlocked
	}
	for _, allowed := range targets {
		if target.URL == allowed.URL {
			return keycheck.RouteProxy
		}
	}
	return keycheck.RouteBlocked
}
