//go:build windows

package main

// privileged returns "" on Windows: Npcap access is granted per driver
// installation rather than per process, so there is nothing to detect.
func privileged() string { return "" }
