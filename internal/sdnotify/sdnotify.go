// Package sdnotify — уведомления systemd (протокол sd_notify) без libsystemd:
// «готов», «останавливаюсь», «жив» для сторожа WatchdogSec.
package sdnotify

import (
	"net"
	"os"
	"strconv"
	"time"
)

// Notify шлёт состояние менеджеру служб; вне systemd (NOTIFY_SOCKET пуст) —
// ничего не делает.
func Notify(state string) error {
	addr := os.Getenv("NOTIFY_SOCKET")
	if addr == "" {
		return nil
	}
	if addr[0] == '@' { // абстрактное пространство имён Linux
		addr = "\x00" + addr[1:]
	}
	conn, err := net.DialUnix("unixgram", nil, &net.UnixAddr{Name: addr, Net: "unixgram"})
	if err != nil {
		return err
	}
	defer conn.Close()
	_, err = conn.Write([]byte(state))
	return err
}

// WatchdogInterval — как часто подтверждать живость (половина WatchdogSec);
// 0 — сторож службы выключен или включён не для этого процесса.
func WatchdogInterval() time.Duration {
	usec, err := strconv.ParseInt(os.Getenv("WATCHDOG_USEC"), 10, 64)
	if err != nil || usec <= 0 {
		return 0
	}
	if pid := os.Getenv("WATCHDOG_PID"); pid != "" && pid != strconv.Itoa(os.Getpid()) {
		return 0
	}
	return time.Duration(usec) * time.Microsecond / 2
}
