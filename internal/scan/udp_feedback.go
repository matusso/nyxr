package scan

import (
	"net/netip"
	"strings"
	"sync"
)

// UDP feedback is scoped to one scan. A retry that succeeds is evidence of
// loss or delay; an ICMP error followed by silence may indicate ICMP limiting.
// Either observation grants one extra attempt to later probes on that host.
type udpFeedback struct {
	mu    sync.Mutex
	hosts map[netip.Addr]udpHostFeedback
}

type udpHostFeedback struct{ delayed, icmp, silent int }

func newUDPFeedback() *udpFeedback { return &udpFeedback{hosts: make(map[netip.Addr]udpHostFeedback)} }

func (f *udpFeedback) retryBonus(target netip.Addr) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	h := f.hosts[target]
	if h.delayed > 0 || (h.icmp > 0 && h.silent > 0) {
		return 1
	}
	return 0
}

func (f *udpFeedback) record(o Observation) {
	f.mu.Lock()
	defer f.mu.Unlock()
	h := f.hosts[o.Target]
	if o.State == "open" && o.PacketsTX > 1 && o.PacketsRX > 0 {
		h.delayed++
	}
	if strings.Contains(o.Reason, "ICMP") && (o.State == "closed" || o.State == "filtered") {
		h.icmp++
	}
	if o.State == "open|filtered" {
		h.silent++
	}
	f.hosts[o.Target] = h
}
