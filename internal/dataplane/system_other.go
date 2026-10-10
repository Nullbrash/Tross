//go:build !linux

package dataplane

import "log/slog"

func NewSystem(*slog.Logger) (Dataplane, error) { return nil, ErrUnsupportedOS }
