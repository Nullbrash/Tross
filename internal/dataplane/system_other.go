//go:build !linux

package dataplane

import (
	"context"
	"log/slog"
)

func NewSystem(*slog.Logger) (Dataplane, error) { return nil, ErrUnsupportedOS }

func Cleanup(context.Context, *slog.Logger, Spec, bool) error { return ErrUnsupportedOS }
