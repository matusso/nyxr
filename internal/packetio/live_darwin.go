//go:build darwin

package packetio

// The connect and UDP engines work without BPF. Live Ethernet I/O is an
// explicit backend boundary until a BPF implementation is added.
func OpenLive(device string) (PacketIO, error) { return nil, ErrUnavailable }
