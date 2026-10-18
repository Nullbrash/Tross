//go:build linux

package control

import (
	"errors"
	"fmt"
	"net"

	"golang.org/x/sys/unix"
)

// peerIsRoot — собеседник на сокете — root (права файла — первая защита,
// это — вторая, на случай неверных прав каталога).
func peerIsRoot(c net.Conn) error {
	uc, ok := c.(*net.UnixConn)
	if !ok {
		return errors.New("not a unix socket")
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		return err
	}
	var cred *unix.Ucred
	var serr error
	if err := raw.Control(func(fd uintptr) {
		cred, serr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	}); err != nil {
		return err
	}
	if serr != nil {
		return serr
	}
	if cred.Uid != 0 {
		return fmt.Errorf("uid %d is not root", cred.Uid)
	}
	return nil
}
