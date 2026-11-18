//go:build windows

package probe

import "syscall"

func shareSourcePort(_, _ string, c syscall.RawConn) error {
	var err error
	if controlErr := c.Control(func(fd uintptr) {
		err = syscall.SetsockoptInt(syscall.Handle(fd), syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1)
	}); controlErr != nil {
		return controlErr
	}
	return err
}
