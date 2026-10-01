// Package netmon reads network interface traffic counters from the operating
// system, so a scan can show the packet and byte rates it puts on the wire.
package netmon

import (
	"errors"
	"net"
)

// ErrUnsupported is returned where the platform exposes no counters.
var ErrUnsupported = errors.New("interface counters unavailable on this platform")

// Counters are cumulative totals since the interface came up.
type Counters struct {
	RxPackets, TxPackets uint64
	RxBytes, TxBytes     uint64
}

func (c *Counters) add(o Counters) {
	c.RxPackets += o.RxPackets
	c.TxPackets += o.TxPackets
	c.RxBytes += o.RxBytes
	c.TxBytes += o.TxBytes
}

// Read returns the counters of device, or the sum over every interface that
// is up and not a loopback when device is empty.
func Read(device string) (Counters, error) {
	all, err := readAll()
	if err != nil {
		return Counters{}, err
	}
	if device != "" {
		c, ok := all[device]
		if !ok {
			return Counters{}, errors.New("no counters for interface " + device)
		}
		return c, nil
	}
	ifaces, err := net.Interfaces()
	if err != nil {
		return Counters{}, err
	}
	var sum Counters
	for _, ifc := range ifaces {
		if ifc.Flags&net.FlagUp == 0 || ifc.Flags&net.FlagLoopback != 0 {
			continue
		}
		if c, ok := all[ifc.Name]; ok {
			sum.add(c)
		}
	}
	return sum, nil
}
