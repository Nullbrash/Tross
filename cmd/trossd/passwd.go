package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/term"

	"tross/internal/auth"
	"tross/internal/config"
	"tross/internal/store"
)

// runPasswd — пароль интерфейса: только на самом мини-ПК (root), не по
// сети. Закрывает все сессии входа.
func runPasswd(args []string) int {
	fs := flag.NewFlagSet("passwd", flag.ContinueOnError)
	configPath := fs.String("config", "/etc/tross/config.yaml", "path to config file")
	dataDir := fs.String("data-dir", "", "override daemon.data_dir from the config")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	cfg, err := config.Load(*configPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "trossd: config:", err)
		return 2
	}
	if *dataDir != "" {
		cfg.SetDataDir(*dataDir)
	}
	pw, err := readPassword()
	if err != nil {
		fmt.Fprintln(os.Stderr, "trossd:", err)
		return 2
	}
	st, err := store.Open(filepath.Join(cfg.Daemon.DataDir, "tross.db"), store.DefaultRetention())
	if err != nil {
		fmt.Fprintln(os.Stderr, "trossd: store:", err)
		return 1
	}
	defer st.Close()
	if err := auth.SetPassword(context.Background(), st, pw); err != nil {
		fmt.Fprintln(os.Stderr, "trossd:", err)
		return 1
	}
	fmt.Println("password set; all interface sessions are closed")
	return 0
}

// readPassword — дважды без отображения с терминала; не терминал — одна
// строка (сценарии установки).
func readPassword() (string, error) {
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		line, err := bufio.NewReader(os.Stdin).ReadString('\n')
		if err != nil && line == "" {
			return "", err
		}
		return strings.TrimRight(line, "\r\n"), nil
	}
	fmt.Fprint(os.Stderr, "new interface password (10+ characters): ")
	a, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return "", err
	}
	fmt.Fprint(os.Stderr, "again: ")
	b, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return "", err
	}
	if string(a) != string(b) {
		return "", fmt.Errorf("passwords differ")
	}
	return string(a), nil
}

// runCA — где корневой сертификат и его отпечаток (сверить на телефоне при
// установке).
func runCA(args []string) int {
	fs := flag.NewFlagSet("ca", flag.ContinueOnError)
	configPath := fs.String("config", "/etc/tross/config.yaml", "path to config file")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	cfg, err := config.Load(*configPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "trossd: config:", err)
		return 2
	}
	dir := cfg.API.TLSDir
	if dir == "" {
		dir = filepath.Join(cfg.Daemon.DataDir, "tls")
	}
	b, err := os.ReadFile(filepath.Join(dir, "ca.crt"))
	if err != nil {
		fmt.Fprintln(os.Stderr, "trossd: no root certificate yet (the daemon creates it on start):", err)
		return 1
	}
	fp, err := fingerprint(b)
	if err != nil {
		fmt.Fprintln(os.Stderr, "trossd:", err)
		return 1
	}
	fmt.Printf("root certificate: %s\nSHA-256: %s\ninstall it from http://%s/ca.crt (or this file) and compare the fingerprint\n", filepath.Join(dir, "ca.crt"), fp, cfg.API.Name)
	return 0
}
