package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

	"tross/internal/config"
	"tross/internal/control"
	"tross/internal/store"
)

const debugUsage = `usage (as root, on the box itself):
  trossd debug dns-log [-for 2h]        start the DNS debug log (max 24h)
  trossd debug dns-log off              stop it
  trossd debug dns-log status           is it running and until when
  trossd debug dns-log export [-anonymize] > file.jsonl
                                        records as JSON lines (devices as device-N)
  trossd debug dns-log purge            delete all records now
records are deleted 48h after they were written; a daemon restart stops the log`

// runDebug — команды отладки работающему демону через сокет root.
func runDebug(args []string) int {
	if len(args) == 0 || args[0] != "dns-log" {
		fmt.Fprintln(os.Stderr, debugUsage)
		return 2
	}
	action := "start"
	rest := args[1:]
	if len(rest) > 0 && rest[0] != "" && rest[0][0] != '-' {
		action, rest = rest[0], rest[1:]
	}
	fs := flag.NewFlagSet("dns-log", flag.ContinueOnError)
	configPath := fs.String("config", "/etc/tross/config.yaml", "path to config file (for the control socket path)")
	dur := fs.Duration("for", 2*time.Hour, "how long the log runs (max 24h)")
	anonymize := fs.Bool("anonymize", false, "export: replace device addresses with device-N")
	if err := fs.Parse(rest); err != nil {
		return 2
	}
	cfg, err := config.Load(*configPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "trossd: config:", err)
		return 2
	}
	sock := cfg.Daemon.Control
	switch action {
	case "start":
		var st map[string]any
		if err := control.Call(sock, control.Request{Cmd: "dns-log-start", For: *dur}, &st); err != nil {
			return fail(err)
		}
		fmt.Printf("dns debug log is on until %v\n", st["until"])
	case "off":
		if err := control.Call(sock, control.Request{Cmd: "dns-log-stop"}, nil); err != nil {
			return fail(err)
		}
		fmt.Println("dns debug log is off")
	case "status":
		var st map[string]any
		if err := control.Call(sock, control.Request{Cmd: "dns-log-status"}, &st); err != nil {
			return fail(err)
		}
		fmt.Printf("active: %v, until: %v\n", st["active"], st["until"])
	case "export":
		var rows []store.DNSDebugRow
		if err := control.Call(sock, control.Request{Cmd: "dns-log-export", Anonymize: *anonymize}, &rows); err != nil {
			return fail(err)
		}
		enc := json.NewEncoder(os.Stdout)
		for _, r := range rows {
			_ = enc.Encode(r)
		}
		fmt.Fprintf(os.Stderr, "%d records\n", len(rows))
	case "purge":
		var n int64
		if err := control.Call(sock, control.Request{Cmd: "dns-log-purge"}, &n); err != nil {
			return fail(err)
		}
		fmt.Printf("%d records deleted\n", n)
	default:
		fmt.Fprintln(os.Stderr, debugUsage)
		return 2
	}
	return 0
}

func fail(err error) int {
	fmt.Fprintln(os.Stderr, "trossd debug:", err)
	return 1
}
