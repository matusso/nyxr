//go:build !linux && !windows

package main

import "os"

// privileged describes raw-packet privilege held by this process, or "".
// On macOS and the BSDs, BPF device access is not a process capability, so
// only root is detected.
func privileged() string {
	if os.Geteuid() == 0 {
		return "root privileges"
	}
	return ""
}
