package scan

import (
	"context"
	"encoding/hex"
	"errors"
	"net"
	"net/netip"
	"syscall"
	"time"

	"github.com/matusso/nyxr/internal/config"
	"github.com/matusso/nyxr/internal/probe"
)

type sentProbe struct {
	probe    probe.Probe
	request  []byte
	sent     time.Time
	length   uint16
	checksum uint16
}

func isBACnetMatcher(matcher string) bool {
	return matcher == "bacnet" || matcher == "bacnet-read" || matcher == "bacnet-fdt"
}

func isUntokenedMatcher(matcher string) bool {
	return matcher == "tftp" || matcher == "ssdp" || matcher == "bacnet" || matcher == "bacnet-fdt"
}

// BACnet I-Am may be broadcast to UDP/47808. One listener owns that port at a
// time so replies cannot be consumed by a concurrent target campaign.
var bacnetListenerSlot = func() chan struct{} {
	slot := make(chan struct{}, 1)
	slot <- struct{}{}
	return slot
}()

func matchRecent(recent []sentProbe, response []byte) (sentProbe, bool) {
	// Transaction-bearing matchers take precedence over the socket-scoped
	// fallback. A late DNS response must not be attributed to a later generic
	// probe that happened to use the same UDP socket.
	for i := len(recent) - 1; i >= 0; i-- {
		sent := recent[i]
		if !sent.sent.IsZero() && time.Since(sent.sent) > 5*time.Second {
			continue
		}
		if isUntokenedMatcher(sent.probe.Matcher) && i != len(recent)-1 {
			continue
		}
		if sent.probe.Matcher != "any" && probe.Match(sent.probe, sent.request, response) {
			return recent[i], true
		}
	}
	if len(recent) > 0 {
		last := recent[len(recent)-1]
		if last.probe.Matcher == "any" && (last.sent.IsZero() || time.Since(last.sent) <= 2*time.Second) {
			return last, true
		}
	}
	return sentProbe{}, false
}

func probeUDPCampaign(ctx context.Context, t task, timeout time.Duration, all []probe.Probe, extraRetries int, secret []byte, limiter *probeLimiter) Observation {
	return probeUDPCampaignWithICMPMode(ctx, t, timeout, all, extraRetries, secret, limiter, nil, config.UDPDeep)
}

func probeUDPCampaignWithICMP(ctx context.Context, t task, timeout time.Duration, all []probe.Probe, extraRetries int, secret []byte, limiter *probeLimiter, observer *udpICMPObserver) Observation {
	return probeUDPCampaignWithICMPMode(ctx, t, timeout, all, extraRetries, secret, limiter, observer, config.UDPDeep)
}

func probeUDPCampaignWithICMPMode(ctx context.Context, t task, timeout time.Duration, all []probe.Probe, extraRetries int, secret []byte, limiter *probeLimiter, observer *udpICMPObserver, mode config.UDPMode) Observation {
	var selected []probe.Probe
	switch mode {
	case config.UDPBasic:
		selected = []probe.Probe{{Name: "udp-empty", Matcher: "any"}}
	case config.UDPDeep:
		selected = probe.ForEveryPort(all, t.port)
	default:
		selected = probe.ForPort(all, t.port)
	}
	if !t.target.Is4() {
		// BACnet/IP payloads in this catalog use IPv4 BVLC addressing.
		filtered := selected[:0]
		for _, p := range selected {
			if !isBACnetMatcher(p.Matcher) {
				filtered = append(filtered, p)
			}
		}
		selected = filtered
	}
	if len(selected) == 0 {
		selected = probe.ForPort(nil, t.port)
	}
	o := base(t, selected[0].Name)
	addr := &net.UDPAddr{IP: net.IP(t.target.AsSlice()), Port: int(t.port), Zone: t.target.Zone()}
	var conn *net.UDPConn
	var err error
	unconnected, bacnet := false, false
	for _, p := range selected {
		bacnet = bacnet || isBACnetMatcher(p.Matcher)
		unconnected = unconnected || p.Matcher == "tftp" || isBACnetMatcher(p.Matcher)
	}
	if bacnet && t.port == 47808 {
		select {
		case <-bacnetListenerSlot:
			defer func() { bacnetListenerSlot <- struct{}{} }()
		case <-ctx.Done():
			o.State, o.Reason = "error", ctx.Err().Error()
			return o
		}
	}
	if unconnected {
		network := "udp4"
		if t.target.Is6() {
			network = "udp6"
		}
		listenAddr := &net.UDPAddr{}
		if bacnet && t.port == 47808 {
			listenAddr.Port = int(t.port)
		}
		conn, err = net.ListenUDP(network, listenAddr)
		if err != nil && bacnet && listenAddr.Port != 0 && errors.Is(err, syscall.EADDRINUSE) {
			listenAddr.Port = 0
			conn, err = net.ListenUDP(network, listenAddr)
		}
	} else {
		conn, err = net.DialUDP("udp", nil, addr)
	}
	if err != nil {
		o.State, o.Reason = "error", err.Error()
		return o
	}
	defer conn.Close()
	local := conn.LocalAddr().(*net.UDPAddr)
	localIP, _ := netip.AddrFromSlice(local.IP)
	if unconnected {
		// An unconnected socket accepts TFTP's reply from a new transfer ID.
		// A temporary dial asks the OS which source IP it will use.
		route, routeErr := net.DialUDP("udp", nil, addr)
		if routeErr == nil {
			localIP, _ = netip.AddrFromSlice(route.LocalAddr().(*net.UDPAddr).IP)
			_ = route.Close()
		}
	}
	flow := udpFlow{source: localIP.Unmap().WithZone(""), target: t.target.Unmap().WithZone(""), sourcePort: uint16(local.Port), targetPort: t.port}
	icmp := observer.register(flow)
	defer observer.unregister(flow)
	stop := context.AfterFunc(ctx, func() { _ = conn.SetDeadline(time.Now()) })
	defer stop()
	var buf [4096]byte
	var socketResponseProbe, socketResponseHex string
	var socketResponseRTT time.Duration
	var attempt uint32
	recent := make([]sentProbe, 0, 32)
	checkICMP := func() bool {
		for i := 0; i < 8; i++ {
			select {
			case event := <-icmp:
				for j := len(recent) - 1; j >= 0; j-- {
					sent := recent[j]
					if event.length == sent.length && event.checksum == sent.checksum {
						if o.State == "open" {
							o.PacketsRX++
							break
						}
						o.State, o.Confidence, o.Reason = event.state, 95, event.reason
						if event.state == "filtered" {
							o.Confidence = 85
						}
						o.Probe, o.RTT, o.PacketsRX = sent.probe.Name, time.Since(sent.sent), o.PacketsRX+1
						return true
					}
				}
			default:
				return false
			}
		}
		return false
	}
probeLoop:
	for _, p := range selected {
		probeTimeout := timeout
		if p.Timeout > 0 && p.Timeout < probeTimeout {
			probeTimeout = p.Timeout
		}
		retries := p.Retries + extraRetries
		if retries > 5 {
			retries = 5
		}
		for retry := 0; retry <= retries; retry++ {
			if err := limiter.WaitFor(ctx, t.target); err != nil {
				o.State, o.Reason = "error", err.Error()
				return o
			}
			o.Probe = p.Name
			o.ProbesAttempted = append(o.ProbesAttempted, p.Name)
			attempt++
			request := probe.Prepare(p, probe.Token(secret, t.target.String(), t.port, p.Name, attempt))
			deadline := time.Now().Add(probeTimeout)
			if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
				deadline = d
			}
			if err := conn.SetWriteDeadline(deadline); err != nil {
				o.State, o.Reason = "error", err.Error()
				return o
			}
			start := time.Now()
			var writeErr error
			if unconnected {
				_, writeErr = conn.WriteToUDP(request, addr)
			} else {
				_, writeErr = conn.Write(request)
			}
			if err := writeErr; err != nil {
				if o.State == "open" && (isUDPPortUnreachable(err) || isUDPFiltered(err)) {
					continue probeLoop
				}
				if isUDPPortUnreachable(err) {
					o.State, o.Confidence, o.Reason = "closed", 95, "ICMP port unreachable"
				} else if isUDPFiltered(err) {
					o.State, o.Confidence, o.Reason = "filtered", 85, "network/host unreachable (socket ICMP error)"
				} else {
					o.State, o.Reason = "error", err.Error()
				}
				return o
			}
			o.PacketsTX++
			if len(recent) == 32 {
				copy(recent, recent[1:])
				recent = recent[:31]
			}
			recent = append(recent, sentProbe{probe: p, request: request, sent: start,
				length: uint16(len(request) + 8), checksum: udpChecksum(flow, request)})
			// A late response to a previous attempt must not be mistaken for this
			// attempt. Continue reading until a matching token or the deadline.
			for received := 0; received < 16 && time.Now().Before(deadline); {
				if ctx.Err() != nil {
					o.State, o.Reason = "error", ctx.Err().Error()
					return o
				}
				if checkICMP() {
					return o
				}
				readDeadline := time.Now().Add(50 * time.Millisecond)
				if readDeadline.After(deadline) {
					readDeadline = deadline
				}
				if err := conn.SetReadDeadline(readDeadline); err != nil {
					o.State, o.Reason = "error", err.Error()
					return o
				}
				var n int
				var peer *net.UDPAddr
				if unconnected {
					n, peer, err = conn.ReadFromUDP(buf[:])
				} else {
					n, err = conn.Read(buf[:])
				}
				if isUDPPortUnreachable(err) {
					if o.State == "open" {
						o.PacketsRX++
						continue probeLoop
					}
					o.State, o.Confidence, o.Reason, o.PacketsRX = "closed", 95, "ICMP port unreachable", o.PacketsRX+1
					return o
				}
				if isUDPFiltered(err) {
					if o.State == "open" {
						o.PacketsRX++
						continue probeLoop
					}
					o.State, o.Confidence, o.Reason, o.PacketsRX = "filtered", 85, "network/host unreachable (socket ICMP error)", o.PacketsRX+1
					return o
				}
				if isTimeout(err) {
					continue
				}
				if err != nil {
					o.State, o.Reason = "error", err.Error()
					return o
				}
				if unconnected && (peer == nil || !peer.IP.Equal(addr.IP) ||
					(peer.Port != addr.Port && p.Matcher != "tftp")) {
					continue
				}
				o.PacketsRX++
				received++
				if n > 128 {
					o.ResponseHex = hex.EncodeToString(buf[:128])
				} else {
					o.ResponseHex = hex.EncodeToString(buf[:n])
				}
				if matched, ok := matchRecent(recent, buf[:n]); ok {
					if matched.probe.Matcher == "any" {
						if o.Confidence < 80 {
							o.State, o.Confidence, o.Reason = "open", 80, "socket-scoped UDP response; probe identity unconfirmed"
							o.Probe, o.RTT = matched.probe.Name, time.Since(matched.sent)
							socketResponseProbe, socketResponseRTT, socketResponseHex = o.Probe, o.RTT, o.ResponseHex
						}
						continue probeLoop
					}
					confidence, reason := 100, "validated "+matched.probe.Matcher+" response"
					if isUntokenedMatcher(matched.probe.Matcher) {
						confidence, reason = 85, "protocol-shaped UDP response from target; no transaction token"
					} else {
						o.Service = matched.probe.Matcher
					}
					if len(matched.probe.Tags) > 0 {
						o.Service = matched.probe.Tags[0]
					}
					if isBACnetMatcher(matched.probe.Matcher) {
						o.Service = "bacnet"
					} else if matched.probe.Matcher == "tftp" || matched.probe.Matcher == "ssdp" {
						o.Service = matched.probe.Matcher
					}
					o.Probe = matched.probe.Name
					o.Fields = probe.Extract(matched.probe, buf[:n])
					o.State, o.Confidence, o.Reason, o.RTT = "open", confidence, reason, time.Since(matched.sent)
					if isBACnetMatcher(matched.probe.Matcher) {
						enrichBACnet(ctx, conn, addr, t.target, t.port, timeout, secret, limiter, &o)
					}
					return o
				}
				if o.State != "open" {
					o.State, o.Confidence, o.Reason = "open", 75, "UDP response with unknown fingerprint"
					o.RTT = time.Since(start)
					socketResponseProbe, socketResponseRTT, socketResponseHex = p.Name, o.RTT, o.ResponseHex
				}
			}
			if checkICMP() {
				return o
			}
		}
	}
	if o.State == "open" {
		o.Probe, o.RTT, o.ResponseHex = socketResponseProbe, socketResponseRTT, socketResponseHex
		return o
	}
	o.State, o.Confidence, o.Reason = "open|filtered", 30, "no UDP or ICMP response"
	if !observer.available(t.target) {
		o.Reason += " (raw ICMP unavailable; socket errors only)"
	}
	return o
}

func isUDPPortUnreachable(err error) bool {
	// Windows reports an ICMP port unreachable as WSAECONNRESET (10054).
	return errors.Is(err, syscall.ECONNREFUSED) || errors.Is(err, syscall.Errno(10054))
}

func isUDPFiltered(err error) bool {
	// Windows uses WSAEHOSTUNREACH (10065) and WSAENETUNREACH (10051).
	return errors.Is(err, syscall.EHOSTUNREACH) || errors.Is(err, syscall.ENETUNREACH) ||
		errors.Is(err, syscall.Errno(10065)) || errors.Is(err, syscall.Errno(10051))
}
