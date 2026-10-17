//go:build linux

package resolver

import (
	"errors"
	"net"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"tross/core/model"
)

// LinkNet — интерфейс и метка канала.
type LinkNet struct {
	Interface string
	Mark      uint32
}

// LinkDialer — сокет через канал: метка выбирает таблицу маршрутизации
// канала, привязка к интерфейсу не даёт уйти в другой при ошибке маршрутов.
func LinkDialer(links map[model.LinkID]LinkNet, timeout time.Duration) Dialer {
	return func(link model.LinkID) *net.Dialer {
		l, ok := links[link]
		if !ok {
			return &net.Dialer{Timeout: timeout}
		}
		return &net.Dialer{Timeout: timeout, Control: func(_, _ string, c syscall.RawConn) error {
			var serr error
			err := c.Control(func(fd uintptr) {
				if serr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_MARK, int(l.Mark)); serr != nil {
					return
				}
				serr = unix.BindToDevice(int(fd), l.Interface)
			})
			return errors.Join(err, serr)
		}}
	}
}
