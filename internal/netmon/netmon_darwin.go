//go:build darwin

package netmon

import (
	"net"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

// readAll dumps the interface list with 64-bit counters (NET_RT_IFLIST2);
// the plain IFLIST variant carries 32-bit counters that wrap at 4 GiB.
func readAll() (map[string]Counters, error) {
	rib, err := syscall.RouteRIB(unix.NET_RT_IFLIST2, 0)
	if err != nil {
		return nil, err
	}
	names := map[int]string{}
	if ifaces, err := net.Interfaces(); err == nil {
		for _, ifc := range ifaces {
			names[ifc.Index] = ifc.Name
		}
	}
	out := map[string]Counters{}
	for len(rib) >= 4 {
		n := int(*(*uint16)(unsafe.Pointer(&rib[0])))
		if n < 4 || n > len(rib) {
			break
		}
		if rib[3] == unix.RTM_IFINFO2 && n >= unix.SizeofIfMsghdr2 {
			m := (*unix.IfMsghdr2)(unsafe.Pointer(&rib[0]))
			if name, ok := names[int(m.Index)]; ok {
				d := m.Data
				out[name] = Counters{RxPackets: d.Ipackets, TxPackets: d.Opackets, RxBytes: d.Ibytes, TxBytes: d.Obytes}
			}
		}
		rib = rib[n:]
	}
	return out, nil
}
