//go:build darwin

package scan

import (
	"encoding/binary"
	"net/netip"
	"testing"
)

func TestKernelProbeFrame(t *testing.T) {
	local := netip.MustParseAddr("192.0.2.10")
	frame := make([]byte, 42)
	copy(frame[:6], []byte{2, 0, 0, 0, 0, 1})   // next hop
	copy(frame[6:12], []byte{2, 0, 0, 0, 0, 2}) // transmitted source
	binary.BigEndian.PutUint16(frame[12:14], 0x0800)
	ip := frame[14:]
	ip[0], ip[9] = 0x45, 17
	copy(ip[12:16], []byte{192, 0, 2, 10})
	binary.BigEndian.PutUint16(ip[20:22], 50000)
	port, src, dst, ok := kernelProbeFrame(frame, local)
	if !ok || port != 50000 || src.String() != "02:00:00:00:00:02" || dst.String() != "02:00:00:00:00:01" {
		t.Fatalf("port=%d src=%v dst=%v ok=%t", port, src, dst, ok)
	}
	if _, _, _, ok := kernelProbeFrame(frame, netip.MustParseAddr("192.0.2.11")); ok {
		t.Fatal("matched another source address")
	}
	frame[0] = 0xff // broadcast is not a neighbor MAC
	if _, _, _, ok := kernelProbeFrame(frame, local); ok {
		t.Fatal("accepted broadcast destination")
	}
}
