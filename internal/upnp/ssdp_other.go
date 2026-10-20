//go:build !linux

package upnp

import (
	"context"
	"errors"
	"log/slog"
	"net/netip"
)

func (g *IGD) ServeSSDP(context.Context, string, func(netip.Addr) bool, *slog.Logger) error {
	return errors.New("upnp: SSDP needs Linux")
}
