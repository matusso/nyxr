package config

import (
	"fmt"
	"math"
	"net"
	"net/netip"
	"sort"
	"strings"
)

// TargetStream stores merged IPv4 intervals, so a large SYN scan does not
// allocate one address per target. DNS names are resolved when the plan is
// built; iteration never performs network lookups.
type TargetStream struct {
	ranges []ipv4Range
	count  int
}

type ipv4Range struct{ first, last uint32 }

func ipv4Number(a netip.Addr) uint32 {
	b := a.As4()
	return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
}

func ipv4Address(n uint32) netip.Addr {
	return netip.AddrFrom4([4]byte{byte(n >> 24), byte(n >> 16), byte(n >> 8), byte(n)})
}

func ParseTargetStream(inputs []string) (*TargetStream, error) {
	var ranges []ipv4Range
	add := func(first, last netip.Addr) error {
		first, last = first.Unmap(), last.Unmap()
		if !first.Is4() || !last.Is4() || first.Compare(last) > 0 {
			return fmt.Errorf("TCP SYN mode currently supports IPv4 targets only")
		}
		a, b := ipv4Number(first), ipv4Number(last)
		if a == 0 || (a <= 0xefffffff && b >= 0xe0000000) {
			return fmt.Errorf("unsupported target range %s-%s", first, last)
		}
		ranges = append(ranges, ipv4Range{a, b})
		return nil
	}
	for _, input := range inputs {
		for _, raw := range strings.Split(input, ",") {
			token := strings.TrimSpace(raw)
			if token == "" {
				return nil, fmt.Errorf("empty target")
			}
			if prefix, err := netip.ParsePrefix(token); err == nil {
				prefix = prefix.Masked()
				if !prefix.Addr().Is4() {
					return nil, fmt.Errorf("TCP SYN mode currently supports IPv4 targets only")
				}
				first := ipv4Number(prefix.Addr())
				last := first | uint32((uint64(1)<<uint(32-prefix.Bits()))-1)
				if err := add(ipv4Address(first), ipv4Address(last)); err != nil {
					return nil, err
				}
				continue
			}
			if addr, err := netip.ParseAddr(token); err == nil {
				if err := add(addr, addr); err != nil {
					return nil, err
				}
				continue
			}
			if parts := strings.Split(token, "-"); len(parts) == 2 {
				first, e1 := netip.ParseAddr(parts[0])
				last, e2 := netip.ParseAddr(parts[1])
				if e1 == nil && e2 == nil {
					if err := add(first, last); err != nil {
						return nil, err
					}
					continue
				}
			}
			ips, err := net.LookupIP(token)
			if err != nil {
				return nil, fmt.Errorf("resolve %q: %w", token, err)
			}
			for _, ip := range ips {
				addr, ok := netip.AddrFromSlice(ip)
				if ok && addr.Unmap().Is4() {
					if err := add(addr, addr); err != nil {
						return nil, err
					}
				}
			}
		}
	}
	sort.Slice(ranges, func(i, j int) bool { return ranges[i].first < ranges[j].first })
	merged := make([]ipv4Range, 0, len(ranges))
	for _, r := range ranges {
		n := len(merged)
		if n > 0 && uint64(r.first) <= uint64(merged[n-1].last)+1 {
			if r.last > merged[n-1].last {
				merged[n-1].last = r.last
			}
		} else {
			merged = append(merged, r)
		}
	}
	var count uint64
	for _, r := range merged {
		count += uint64(r.last) - uint64(r.first) + 1
	}
	if count > uint64(math.MaxInt) {
		return nil, fmt.Errorf("target count exceeds platform limit")
	}
	return &TargetStream{ranges: merged, count: int(count)}, nil
}

func (s *TargetStream) Count() int {
	if s == nil {
		return 0
	}
	return s.count
}

func (s *TargetStream) Contains(addr netip.Addr) bool {
	if s == nil || !addr.Is4() {
		return false
	}
	n := ipv4Number(addr)
	i := sort.Search(len(s.ranges), func(i int) bool { return s.ranges[i].last >= n })
	return i < len(s.ranges) && s.ranges[i].first <= n
}

func (s *TargetStream) validateAllowed(prefixes []netip.Prefix) error {
	if s == nil || len(prefixes) == 0 {
		return nil
	}
	allowed := make([]ipv4Range, 0, len(prefixes))
	for _, prefix := range prefixes {
		if !prefix.Addr().Is4() {
			continue
		}
		first := ipv4Number(prefix.Masked().Addr())
		last := first | uint32((uint64(1)<<uint(32-prefix.Bits()))-1)
		allowed = append(allowed, ipv4Range{first, last})
	}
	sort.Slice(allowed, func(i, j int) bool { return allowed[i].first < allowed[j].first })
	for _, target := range s.ranges {
		cursor := uint64(target.first)
		for _, a := range allowed {
			if uint64(a.first) > cursor {
				break
			}
			if uint64(a.last) >= cursor {
				cursor = uint64(a.last) + 1
			}
			if cursor > uint64(target.last) {
				break
			}
		}
		if cursor <= uint64(target.last) {
			return fmt.Errorf("target %s is outside --allow-targets", ipv4Address(uint32(cursor)))
		}
	}
	return nil
}

func (s *TargetStream) Each(yield func(netip.Addr) bool) {
	if s == nil {
		return
	}
	for _, r := range s.ranges {
		for n := r.first; ; n++ {
			if !yield(ipv4Address(n)) || n == r.last {
				break
			}
		}
	}
}

func (c Config) TargetCount() int {
	if c.TargetStream != nil {
		return c.TargetStream.Count()
	}
	return len(c.Targets)
}

func (c Config) EachTarget(yield func(netip.Addr) bool) {
	if c.TargetStream != nil {
		c.TargetStream.Each(yield)
		return
	}
	for _, target := range c.Targets {
		if !yield(target) {
			return
		}
	}
}
