//go:build windows

package packetio

// A future Npcap backend can implement PacketIO without changing decoders.
func OpenLive(device string) (PacketIO, error) { return nil, ErrUnavailable }
