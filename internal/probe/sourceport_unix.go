//go:build !windows

package probe

import (
	"syscall"

	"golang.org/x/sys/unix"
)

func shareSourcePort(_, _ string, c syscall.RawConn) error {
	var err error
	if controlErr := c.Control(func(fd uintptr) {
		if err = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEADDR, 1); err == nil {
			err = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEPORT, 1)
		}
	}); controlErr != nil {
		return controlErr
	}
	return err
}
