package config

import (
	"fmt"
	"net/netip"
	"strings"
)

// Scope matches addresses against IPs, CIDRs and inclusive A-B ranges
// without expanding them, so it can narrow stored assets to a /8 or an IPv6
// /64. It never performs DNS lookups. The zero Scope matches everything.
type Scope struct {
	ranges []addrRange
}

type addrRange struct{ first, last netip.Addr }

// ParseScope accepts the address forms of ParseTargets: an IP, a CIDR, or a
// full-address range such as 10.0.0.5-10.0.0.40. A short IPv4 range whose
// end is only the last octet (10.0.0.5-40) is also accepted.
func ParseScope(inputs []string) (Scope, error) {
	var s Scope
	for _, input := range inputs {
		for _, raw := range strings.Split(input, ",") {
			token := strings.TrimSpace(raw)
			if token == "" {
				continue
			}
			r, err := parseScopeToken(token)
			if err != nil {
				return Scope{}, err
			}
			s.ranges = append(s.ranges, r)
		}
	}
	return s, nil
}

func parseScopeToken(token string) (addrRange, error) {
	if prefix, err := netip.ParsePrefix(token); err == nil {
		prefix = prefix.Masked()
		return addrRange{prefix.Addr(), lastInPrefix(prefix)}, nil
	}
	if a, err := netip.ParseAddr(token); err == nil {
		a = a.Unmap()
		return addrRange{a, a}, nil
	}
	if lo, hi, ok := strings.Cut(token, "-"); ok {
		start, err := netip.ParseAddr(strings.TrimSpace(lo))
		if err != nil {
			return addrRange{}, fmt.Errorf("invalid address range %q", token)
		}
		start = start.Unmap()
		hi = strings.TrimSpace(hi)
		end, err := netip.ParseAddr(hi)
		if err != nil && start.Is4() {
			// 10.0.0.5-40: the end replaces the last octet.
			b := start.As4()
			end, err = netip.ParseAddr(fmt.Sprintf("%d.%d.%d.%s", b[0], b[1], b[2], hi))
		}
		if err != nil {
			return addrRange{}, fmt.Errorf("invalid address range %q", token)
		}
		end = end.Unmap()
		if start.Is4() != end.Is4() || start.Compare(end) > 0 {
			return addrRange{}, fmt.Errorf("invalid address range %q", token)
		}
		return addrRange{start, end}, nil
	}
	return addrRange{}, fmt.Errorf("scope %q is not an IP, CIDR or range", token)
}

func lastInPrefix(p netip.Prefix) netip.Addr {
	b := p.Addr().AsSlice()
	for i := range b {
		bits := p.Bits() - i*8
		switch {
		case bits >= 8:
		case bits <= 0:
			b[i] = 0xff
		default:
			b[i] |= byte(0xff >> bits)
		}
	}
	a, _ := netip.AddrFromSlice(b)
	return a
}

// Empty reports whether the scope has no entries and so matches everything.
func (s Scope) Empty() bool { return len(s.ranges) == 0 }

// Contains reports whether a lies in any entry of the scope.
func (s Scope) Contains(a netip.Addr) bool {
	if s.Empty() {
		return true
	}
	a = a.Unmap()
	for _, r := range s.ranges {
		if a.Is4() == r.first.Is4() && a.Compare(r.first) >= 0 && a.Compare(r.last) <= 0 {
			return true
		}
	}
	return false
}
