//go:build linux

package main

import (
	"os"
	"strconv"
	"strings"
)

// Linux capability bits from linux/capability.h.
const (
	capNetAdmin = 12
	capNetRaw   = 13
)

// privileged describes raw-packet privilege held by this process, or "".
func privileged() string {
	if os.Geteuid() == 0 {
		return "root privileges"
	}
	b, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return ""
	}
	return capabilityReason(string(b))
}

func capabilityReason(status string) string {
	for _, line := range strings.Split(status, "\n") {
		hex, ok := strings.CutPrefix(line, "CapEff:")
		if !ok {
			continue
		}
		caps, err := strconv.ParseUint(strings.TrimSpace(hex), 16, 64)
		if err != nil {
			return ""
		}
		var held []string
		if caps&(1<<capNetRaw) != 0 {
			held = append(held, "CAP_NET_RAW")
		}
		if caps&(1<<capNetAdmin) != 0 {
			held = append(held, "CAP_NET_ADMIN")
		}
		if len(held) > 0 {
			return strings.Join(held, " and ")
		}
	}
	return ""
}
