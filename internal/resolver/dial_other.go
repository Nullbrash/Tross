//go:build !linux

package resolver

import (
	"net"
	"time"

	"tross/core/model"
)

// LinkNet — интерфейс и метка канала.
type LinkNet struct {
	Interface string
	Mark      uint32
}

// LinkDialer — вне Linux каналов нет («сухой» режим): обычный сокет.
func LinkDialer(_ map[model.LinkID]LinkNet, timeout time.Duration) Dialer {
	return func(model.LinkID) *net.Dialer { return &net.Dialer{Timeout: timeout} }
}
