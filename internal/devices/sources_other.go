//go:build !linux

package devices

import (
	"context"
	"errors"

	"tross/core/model"
)

// Sources — слушатели LAN есть только в Linux.
type Sources struct{}

func NewSources(SourceOptions) (*Sources, error) {
	return nil, errors.New("devices: LAN sources need Linux")
}

func (*Sources) Run(context.Context) {}

func (*Sources) Probe(model.Device) {}
