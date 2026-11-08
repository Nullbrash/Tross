// Package keycheckprobe содержит транспорт живой проверки только для стенда.
// Он не подключается к сети, пока Runner не вызовет Probe.
package keycheckprobe

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"tross/core/keycheck"
)

const startupTimeout = 5 * time.Second

// SingBoxProber создаёт на стенде короткоживущий локальный proxy-процесс.
// Каталог конфигураций намеренно не очищается автоматически: его удаление
// с ключевыми данными требует отдельного подтверждения владельца.
type SingBoxProber struct {
	Binary  string
	WorkDir string

	mu sync.Mutex
}

// Probe запускает один процесс на ключ и выполняет ровно один HTTP HEAD через
// его loopback-вход. Тело ответа не скачивается.
func (p *SingBoxProber) Probe(ctx context.Context, record keycheck.Record, target keycheck.Target) keycheck.ProbeResult {
	if err := p.validate(); err != nil {
		return inconclusive("prober_configuration")
	}
	spec, err := keycheck.ParseURI(record.Raw)
	if err != nil {
		return inconclusive("unsupported_key")
	}
	if err := validateTarget(target.URL); err != nil {
		return inconclusive("invalid_target")
	}
	port, err := reservePort()
	if err != nil {
		return inconclusive("loopback_unavailable")
	}
	configPath, err := p.writeConfig(record.ID, spec, port)
	if err != nil {
		return inconclusive("config_prepare_failed")
	}
	cmd := exec.Command(p.Binary, "run", "-c", configPath)
	cmd.Stdout = nil
	cmd.Stderr = nil
	if err := cmd.Start(); err != nil {
		return inconclusive("client_start_failed")
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	defer stop(cmd, done)
	if !waitLoopback(ctx, done, port) {
		return inconclusive("client_not_ready")
	}
	started := time.Now()
	result := request(ctx, target.URL, port)
	result.Latency = time.Since(started)
	return result
}

func (p *SingBoxProber) validate() error {
	if p.Binary == "" || p.WorkDir == "" {
		return errors.New("keycheckprobe: binary and work directory are required")
	}
	return nil
}

func (p *SingBoxProber) writeConfig(recordID string, spec keycheck.OutboundSpec, port int) (string, error) {
	if !safeID(recordID) {
		return "", errors.New("keycheckprobe: invalid record id")
	}
	config, err := keycheck.SingBoxConfig(spec, port)
	if err != nil {
		return "", err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	dir := filepath.Join(p.WorkDir, "runs")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	path := filepath.Join(dir, recordID+".json")
	if info, err := os.Lstat(path); err == nil {
		if !info.Mode().IsRegular() || (runtime.GOOS != "windows" && info.Mode().Perm() != 0o600) {
			return "", errors.New("keycheckprobe: existing config is not private")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", err
	}
	// Для каждой цели резервируется новый loopback-порт, поэтому конфиг
	// обновляется тем же приватным файлом перед короткоживущим клиентом.
	if err := os.WriteFile(path, config, 0o600); err != nil {
		return "", err
	}
	if err := os.Chmod(path, 0o600); err != nil {
		return "", err
	}
	return path, nil
}

func reservePort() (int, error) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	defer listener.Close()
	return listener.Addr().(*net.TCPAddr).Port, nil
}

func waitLoopback(ctx context.Context, done <-chan error, port int) bool {
	deadline := time.NewTimer(startupTimeout)
	defer deadline.Stop()
	for {
		connection, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 100*time.Millisecond)
		if err == nil {
			connection.Close()
			return true
		}
		select {
		case <-ctx.Done():
			return false
		case <-done:
			return false
		case <-deadline.C:
			return false
		case <-time.After(50 * time.Millisecond):
		}
	}
}

func request(ctx context.Context, rawURL string, port int) keycheck.ProbeResult {
	proxyURL, _ := url.Parse(fmt.Sprintf("http://127.0.0.1:%d", port))
	transport := &http.Transport{Proxy: http.ProxyURL(proxyURL)}
	client := &http.Client{Transport: transport}
	request, err := http.NewRequestWithContext(ctx, http.MethodHead, rawURL, nil)
	if err != nil {
		return inconclusive("request_build_failed")
	}
	response, err := client.Do(request)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) || errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return inconclusive("timeout")
		}
		return inconclusive("connection_failed")
	}
	response.Body.Close()
	if response.StatusCode >= 200 && response.StatusCode < 500 {
		return keycheck.ProbeResult{Status: keycheck.Reachable, Reason: "http_response"}
	}
	return keycheck.ProbeResult{Status: keycheck.Unreachable, Reason: "http_5xx"}
}

func stop(cmd *exec.Cmd, done <-chan error) {
	_ = cmd.Process.Signal(os.Interrupt)
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		_ = cmd.Process.Kill()
		// Даже зависший Wait не должен удерживать весь прогон. Процесс уже
		// получил Kill; завершающая горутина будет освобождена ОС при выходе.
		select {
		case <-done:
		case <-time.After(2 * time.Second):
		}
	}
}

func validateTarget(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return errors.New("keycheckprobe: target must be http or https")
	}
	return nil
}

func safeID(value string) bool {
	return value != "" && !strings.ContainsAny(value, `\\/:*?"<>|`) && filepath.Base(value) == value
}

func inconclusive(reason string) keycheck.ProbeResult {
	return keycheck.ProbeResult{Status: keycheck.Inconclusive, Reason: reason}
}
