//go:build !linux

package linkmon

import "errors"

func NewSystem(Options, []LinkProbe) (LinkMonitor, error) {
	return nil, errors.New("linkmon: real monitor is supported only on linux; use dry-run")
}
