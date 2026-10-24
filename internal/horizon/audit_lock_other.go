//go:build !unix

package horizon

import "os"

// lockAudit is advisory on Unix only; elsewhere one writer is the operator's
// responsibility.
func lockAudit(*os.File) error { return nil }
