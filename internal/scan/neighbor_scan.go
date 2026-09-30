package scan

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"time"

	"github.com/matusso/nyxr/internal/config"
	"github.com/matusso/nyxr/internal/packet"
	"github.com/matusso/nyxr/internal/packetio"
)

func runNeighbor(parent context.Context, cfg config.Config, emit func(Observation) error) error {
	iface, lookupErr := net.InterfaceByName(cfg.Interface)
	var sourceMAC net.HardwareAddr
	if lookupErr == nil {
		sourceMAC = iface.HardwareAddr
		if len(sourceMAC) != 6 {
			return fmt.Errorf("interface %s is not Ethernet", cfg.Interface)
		}
		if len(cfg.SourceMAC) != 0 && string(cfg.SourceMAC) != string(sourceMAC) {
			return fmt.Errorf("source MAC does not match interface %s", cfg.Interface)
		}
	} else {
		if !cfg.SourceIP.IsValid() || len(cfg.SourceMAC) != 6 {
			return fmt.Errorf("interface %s not found by OS; specify source IP and MAC for an Npcap adapter", cfg.Interface)
		}
		sourceMAC = cfg.SourceMAC
	}
	io, err := packetio.OpenLive(cfg.Interface)
	if err != nil {
		return fmt.Errorf("raw packet I/O on %s: %w", cfg.Interface, err)
	}
	defer io.Close()
	limiter := newScopedProbeLimiter(cfg)
	var source4 netip.Addr
	var route4 func(netip.Addr) (netip.Addr, error)
	if cfg.ARP {
		if iface != nil {
			source4, err = selectIPv4Source(iface, cfg.SourceIP)
		} else {
			source4 = cfg.SourceIP
		}
		if err != nil || !source4.Is4() {
			return fmt.Errorf("ARP source IPv4: %v", err)
		}
		if iface != nil {
			route4, err = loadIPv4Routes(cfg.Interface)
			if err != nil {
				return err
			}
		}
	}
	for _, target := range cfg.Targets {
		if err := parent.Err(); err != nil {
			return err
		}
		transport := "arp"
		if target.Is6() {
			transport = "ndp"
		}
		o := base(task{target: target, transport: transport}, transport+"-solicitation")
		var source netip.Addr
		if target.Is4() {
			source = source4
			if route4 != nil {
				hop, err := route4(target)
				if err != nil {
					return err
				}
				if hop != target {
					o.State, o.Reason = "unsupported", "ARP target is off-link; use ICMP discovery"
					if err := emit(o); err != nil {
						return err
					}
					continue
				}
			}
		} else {
			source, err = selectIPv6NeighborSource(iface, cfg.SourceIP, target)
			if err != nil {
				o.State, o.Reason = "unsupported", err.Error()
				if err := emit(o); err != nil {
					return err
				}
				continue
			}
		}
		if err := limiter.WaitFor(parent, target); err != nil {
			return err
		}
		start := time.Now()
		var mac net.HardwareAddr
		if target.Is4() {
			mac, err = arpNeighbor(parent, io, sourceMAC, source, target, cfg.Timeout)
		} else {
			mac, err = ndpNeighbor(parent, io, sourceMAC, source, target, cfg.Timeout)
		}
		o.RTT = time.Since(start)
		if err != nil {
			if parent.Err() != nil {
				return parent.Err()
			}
			o.State, o.Reason = "error", err.Error()
		} else {
			o.PacketsTX = 1
			if len(mac) == 6 {
				o.State, o.Confidence, o.Reason, o.PacketsRX, o.MAC = "responsive", 100, "matching neighbor advertisement", 1, mac.String()
			} else {
				o.State, o.Confidence, o.Reason = "no-response", 40, "neighbor solicitation timed out"
			}
		}
		if err := emit(o); err != nil {
			return err
		}
	}
	return parent.Err()
}

func selectIPv6NeighborSource(iface *net.Interface, requested, target netip.Addr) (netip.Addr, error) {
	if !target.Is6() {
		return netip.Addr{}, errors.New("NDP target must be IPv6")
	}
	if iface != nil && target.Zone() != "" && target.Zone() != iface.Name {
		return netip.Addr{}, fmt.Errorf("NDP target zone %s differs from interface %s", target.Zone(), iface.Name)
	}
	target = target.WithZone("")
	if iface == nil {
		if requested.Is6() && !requested.IsUnspecified() {
			return requested, nil
		}
		return netip.Addr{}, errors.New("NDP needs an IPv6 source on the selected adapter")
	}
	addrs, err := iface.Addrs()
	if err != nil {
		return netip.Addr{}, err
	}
	for _, addr := range addrs {
		prefix, err := netip.ParsePrefix(addr.String())
		if err != nil || !prefix.Addr().Is6() {
			continue
		}
		if requested.IsValid() && prefix.Addr() != requested {
			continue
		}
		if prefix.Contains(target) {
			return prefix.Addr(), nil
		}
	}
	return netip.Addr{}, fmt.Errorf("NDP target %s is not on-link on %s", target, iface.Name)
}

func ndpNeighbor(parent context.Context, io packetio.PacketIO, sourceMAC net.HardwareAddr, sourceIP, target netip.Addr, timeout time.Duration) (net.HardwareAddr, error) {
	frame, err := packet.NeighborSolicitation(sourceMAC, sourceIP, target)
	if err != nil {
		return nil, err
	}
	if timeout < 200*time.Millisecond {
		timeout = 200 * time.Millisecond
	}
	if timeout > 2*time.Second {
		timeout = 2 * time.Second
	}
	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()
	if n, err := io.SendBatch(ctx, [][]byte{frame}); err != nil || n != 1 {
		return nil, fmt.Errorf("send NDP solicitation: %d/1 frames: %v", n, err)
	}
	var storage [65535]byte
	buf := [][]byte{storage[:]}
	for {
		buf[0] = storage[:]
		n, err := io.ReceiveBatch(ctx, buf)
		if n > 0 {
			if mac, ok := packet.NeighborAdvertisementMAC(buf[0], target, sourceIP); ok {
				return mac, nil
			}
		}
		if err != nil {
			if errors.Is(err, context.DeadlineExceeded) {
				return nil, nil
			}
			return nil, err
		}
	}
}
