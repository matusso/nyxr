package scan

import (
	"context"
	"net"
	"net/netip"
	"time"

	"github.com/matusso/nyxr/internal/probe"
)

// enrichBACnet uses the same source socket after discovery. Each request is a
// read-only Device property query or BBMD table read. Missing properties do not
// change the already validated open-port result.
func enrichBACnet(ctx context.Context, conn *net.UDPConn, target *net.UDPAddr,
	addr netip.Addr, port uint16, timeout time.Duration, secret []byte,
	limiter *probeLimiter, o *Observation) {
	probeTimeout := timeout
	if probeTimeout > 750*time.Millisecond {
		probeTimeout = 750 * time.Millisecond
	}
	var buf [65507]byte
	query := func(name string, request []byte, parse func([]byte) (map[string]string, bool)) map[string]string {
		if err := limiter.WaitFor(ctx, addr); err != nil {
			return nil
		}
		deadline := time.Now().Add(probeTimeout)
		if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
			deadline = d
		}
		if err := conn.SetWriteDeadline(deadline); err != nil {
			return nil
		}
		started := time.Now()
		if _, err := conn.WriteToUDP(request, target); err != nil {
			return nil
		}
		o.ProbesAttempted = append(o.ProbesAttempted, name)
		o.PacketsTX++
		for time.Now().Before(deadline) && ctx.Err() == nil {
			if err := conn.SetReadDeadline(deadline); err != nil {
				return nil
			}
			n, peer, err := conn.ReadFromUDP(buf[:])
			if err != nil {
				return nil
			}
			if peer == nil || !peer.IP.Equal(target.IP) || peer.Port != target.Port {
				continue
			}
			o.PacketsRX++
			fields, done := parse(buf[:n])
			matcher := ""
			if done {
				matcher = name
			}
			retainUDPExchange(o, sentProbe{probe: probe.Probe{Name: name}, request: request, sent: started}, buf[:n], matcher)
			if done {
				return fields
			}
		}
		return nil
	}
	if o.Fields == nil {
		o.Fields = make(map[string]string)
	}
	if _, exists := o.Fields["bacnet.device_id"]; !exists {
		name := "bacnet-read-device"
		invoke := byte(probe.Token(secret, addr.String(), port, name, 75))
		request := probe.BACnetReadPropertyRequest(75, invoke)
		fields := query(name, request, func(response []byte) (map[string]string, bool) {
			if !probe.Match(probe.Probe{Matcher: "bacnet-read"}, request, response) {
				return nil, false
			}
			return probe.Extract(probe.Probe{Matcher: "bacnet-read", ExtractFields: []string{"bacnet.device_id"}}, response), true
		})
		for key, value := range fields {
			o.Fields[key] = value
		}
	}
	for _, property := range probe.BACnetDeviceProperties {
		if _, exists := o.Fields[property.Field]; exists {
			continue
		}
		name := "bacnet-read-" + property.Field[len("bacnet."):]
		invoke := byte(probe.Token(secret, addr.String(), port, name, uint32(property.ID)))
		request := probe.BACnetReadPropertyRequest(property.ID, invoke)
		fields := query(name, request, func(response []byte) (map[string]string, bool) {
			if value, ok := probe.BACnetPropertyValue(request, response); ok {
				return map[string]string{property.Field: value}, true
			}
			return nil, probe.Match(probe.Probe{Matcher: "bacnet-read"}, request, response)
		})
		for key, value := range fields {
			o.Fields[key] = value
		}
		if ctx.Err() != nil {
			return
		}
	}
	if _, exists := o.Fields["bacnet.fdt_entries"]; !exists && ctx.Err() == nil {
		request := probe.BACnetFDTRequest()
		fields := query("bacnet-fdt", request, func(response []byte) (map[string]string, bool) {
			fields := probe.BACnetFDTFields(response)
			return fields, fields != nil || probe.Match(probe.Probe{Matcher: "bacnet-fdt"}, request, response)
		})
		for key, value := range fields {
			o.Fields[key] = value
		}
	}
	if len(o.Fields) == 0 {
		o.Fields = nil
	}
}
