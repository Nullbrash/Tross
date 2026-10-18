// Package control — команды root на самом мини-ПК через unix-сокет: то, что
// нельзя позволять по сети (отладочный журнал DNS). Сокет — с правами 0600,
// и вдобавок проверяется, что собеседник — root.
package control

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"time"
)

// Request — команда.
type Request struct {
	Cmd       string        `json:"cmd"`
	For       time.Duration `json:"for,omitempty"`
	Anonymize bool          `json:"anonymize,omitempty"`
}

// Response — ответ: ошибка или данные команды.
type Response struct {
	Error string          `json:"error,omitempty"`
	Data  json.RawMessage `json:"data,omitempty"`
}

// Handler выполняет команду; результат кодируется в JSON.
type Handler func(ctx context.Context, req Request) (any, error)

// Listen — сокет только для root (прежний, оставшийся после аварии, —
// заменяется).
func Listen(path string) (net.Listener, error) {
	_ = os.Remove(path)
	l, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(path, 0o600); err != nil {
		l.Close()
		return nil, err
	}
	return l, nil
}

// Serve — до отмены ctx; по одной команде на соединение.
func Serve(ctx context.Context, l net.Listener, h Handler, log *slog.Logger) {
	go func() {
		<-ctx.Done()
		l.Close()
	}()
	for {
		c, err := l.Accept()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return
			}
			continue
		}
		go serveConn(ctx, c, h, log)
	}
}

func serveConn(ctx context.Context, c net.Conn, h Handler, log *slog.Logger) {
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(time.Minute))
	reply := func(r Response) { _ = json.NewEncoder(c).Encode(r) }
	if err := peerIsRoot(c); err != nil {
		log.Warn("control: refused", "err", err)
		reply(Response{Error: "refused: " + err.Error()})
		return
	}
	var req Request
	if err := json.NewDecoder(bufio.NewReader(c)).Decode(&req); err != nil {
		reply(Response{Error: "bad request: " + err.Error()})
		return
	}
	out, err := h(ctx, req)
	if err != nil {
		reply(Response{Error: err.Error()})
		return
	}
	data, err := json.Marshal(out)
	if err != nil {
		reply(Response{Error: err.Error()})
		return
	}
	reply(Response{Data: data})
}

// Call — команда работающему демону; out — куда разобрать данные (nil —
// не нужны).
func Call(path string, req Request, out any) error {
	c, err := net.DialTimeout("unix", path, 5*time.Second)
	if err != nil {
		return fmt.Errorf("daemon is not running or the socket is not accessible (run as root): %w", err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(time.Minute))
	if err := json.NewEncoder(c).Encode(req); err != nil {
		return err
	}
	var resp Response
	if err := json.NewDecoder(c).Decode(&resp); err != nil {
		return err
	}
	if resp.Error != "" {
		return errors.New(resp.Error)
	}
	if out != nil && len(resp.Data) > 0 {
		return json.Unmarshal(resp.Data, out)
	}
	return nil
}
