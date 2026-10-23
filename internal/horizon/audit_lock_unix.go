//go:build unix

package horizon

import (
	"fmt"
	"os"
	"syscall"
)

func lockAudit(f *os.File) error {
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		return fmt.Errorf("audit file %s is in use by another process: %w", f.Name(), err)
	}
	return nil
}
