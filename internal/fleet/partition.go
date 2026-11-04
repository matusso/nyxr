// Package fleet distributes ordinary Nyxr scans to remote agents over gRPC.
//
// The controller (nyxr serve --fleet-listen) partitions a resolved
// config.Request into units, leases units to connected agents whose
// advertised capabilities and operator-authorized vantage fit, and stores
// streamed results through the same storage path as local scans. Agents
// (nyxr agent) dial the controller, so they work from behind NAT and need no
// listening port. They run each lease through config.Request.Resolve and
// pipeline.Run exactly like the API, re-checking their own scope. No scanner
// engine is duplicated here. HORIZON experiments are not dispatched (#72/#73
// own their admission contracts).
package fleet

import (
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strings"

	"github.com/matusso/nyxr/internal/config"
)

// Unit is one partition of a job's targets.
type Unit struct {
	Targets     []string // IP or inclusive "first-last" tokens
	Count       int
	SubnetShare int
}

// MaxUnits bounds a job so one request cannot flood the controller database.
const MaxUnits = 65536

type addrRun struct{ first, last netip.Addr }

type subnetGroup struct {
	key   netip.Prefix
	runs  []addrRun
	count int
}

func subnetOf(a netip.Addr) netip.Prefix {
	bits := 24
	if a.Is6() {
		bits = 64
	}
	p, _ := a.Prefix(bits)
	return p
}

// Partition splits the resolved targets into units of at most unitSize
// addresses. Units are packed from whole IPv4 /24s and IPv6 /64s so a
// per-subnet rate budget stays with one agent. A subnet is split only when it
// alone exceeds unitSize; its units then record the split in SubnetShare.
func Partition(cfg config.Config, unitSize int) ([]Unit, error) {
	if unitSize < 1 {
		return nil, errors.New("unit size must be at least 1")
	}
	var groups []*subnetGroup
	add := func(a netip.Addr) {
		a = a.Unmap().WithZone("")
		key := subnetOf(a)
		n := len(groups)
		if n == 0 || groups[n-1].key != key {
			groups = append(groups, &subnetGroup{key: key})
			n++
		}
		g := groups[n-1]
		if r := len(g.runs); r > 0 {
			if g.runs[r-1].last == a {
				return // duplicate address in an explicit list
			}
			if g.runs[r-1].last.Next() == a {
				g.runs[r-1].last = a
				g.count++
				return
			}
		}
		g.runs = append(g.runs, addrRun{a, a})
		g.count++
	}
	if cfg.TargetStream != nil {
		cfg.EachTarget(func(a netip.Addr) bool { add(a); return true })
	} else {
		addrs := make([]netip.Addr, 0, len(cfg.Targets))
		for _, a := range cfg.Targets {
			addrs = append(addrs, a.Unmap().WithZone(""))
		}
		sort.Slice(addrs, func(i, j int) bool { return addrs[i].Less(addrs[j]) })
		for _, a := range addrs {
			add(a)
		}
	}
	var units []Unit
	cur := Unit{SubnetShare: 1}
	emit := func() error {
		if cur.Count == 0 {
			return nil
		}
		if len(units) >= MaxUnits {
			return fmt.Errorf("job needs more than %d units; raise unit_size", MaxUnits)
		}
		units = append(units, cur)
		cur = Unit{SubnetShare: 1}
		return nil
	}
	for _, g := range groups {
		if g.count > unitSize {
			// An oversized subnet is split into units of its own.
			if err := emit(); err != nil {
				return nil, err
			}
			share := (g.count + unitSize - 1) / unitSize
			for _, r := range g.runs {
				for first := r.first; ; {
					last := first
					for n := cur.Count + 1; n < unitSize && last != r.last; n++ {
						last = last.Next()
					}
					cur.Targets = append(cur.Targets, token(first, last))
					cur.Count += span(first, last)
					cur.SubnetShare = share
					if cur.Count >= unitSize {
						if err := emit(); err != nil {
							return nil, err
						}
					}
					if last == r.last {
						break
					}
					first = last.Next()
				}
			}
			if err := emit(); err != nil {
				return nil, err
			}
			continue
		}
		if cur.Count+g.count > unitSize {
			if err := emit(); err != nil {
				return nil, err
			}
		}
		for _, r := range g.runs {
			cur.Targets = append(cur.Targets, token(r.first, r.last))
		}
		cur.Count += g.count
	}
	if err := emit(); err != nil {
		return nil, err
	}
	if len(units) == 0 {
		return nil, errors.New("request has no targets")
	}
	return units, nil
}

func token(first, last netip.Addr) string {
	if first == last {
		return first.String()
	}
	return first.String() + "-" + last.String()
}

// span counts addresses in a run inside one /24 or /64, so the low 64 bits
// hold the whole difference.
func span(first, last netip.Addr) int {
	f, l := first.As16(), last.As16()
	var a, b uint64
	for i := 8; i < 16; i++ {
		a, b = a<<8|uint64(f[i]), b<<8|uint64(l[i])
	}
	return int(b-a) + 1
}

// unitRuns parses a unit's own target tokens back into address runs.
func unitRuns(targets []string) ([]addrRun, error) {
	out := make([]addrRun, 0, len(targets))
	for _, t := range targets {
		if a, err := netip.ParseAddr(t); err == nil {
			out = append(out, addrRun{a.Unmap(), a.Unmap()})
			continue
		}
		lo, hi, _ := strings.Cut(t, "-")
		f, err1 := netip.ParseAddr(lo)
		l, err2 := netip.ParseAddr(hi)
		if err1 != nil || err2 != nil || f.Is4() != l.Is4() || f.Compare(l) > 0 {
			return nil, fmt.Errorf("invalid unit target %q", t)
		}
		out = append(out, addrRun{f.Unmap(), l.Unmap()})
	}
	return out, nil
}

// runsContain reports whether a lies in one of the runs.
func runsContain(runs []addrRun, a netip.Addr) bool {
	a = a.Unmap().WithZone("")
	for _, r := range runs {
		if a.Is4() == r.first.Is4() && a.Compare(r.first) >= 0 && a.Compare(r.last) <= 0 {
			return true
		}
	}
	return false
}
