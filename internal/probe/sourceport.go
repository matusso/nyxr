package probe

import (
	"context"
	"net"
)

// DialUDP connects a UDP socket to addr from sourcePort, or from an ephemeral
// port when sourcePort is 0 or cannot be bound (a privileged port without
// root, or a local daemon owning it). The bool reports whether sourcePort was
// granted. Shared binding lets concurrent targets use the same source port;
// connected sockets are demultiplexed by their peer.
func DialUDP(ctx context.Context, addr *net.UDPAddr, sourcePort uint16) (*net.UDPConn, bool, error) {
	if sourcePort != 0 {
		d := net.Dialer{LocalAddr: &net.UDPAddr{Port: int(sourcePort)}, Control: shareSourcePort}
		if conn, err := d.DialContext(ctx, "udp", addr.String()); err == nil {
			// Probing this host on the same port would connect the socket to
			// itself and read back its own request.
			if conn.LocalAddr().String() != conn.RemoteAddr().String() {
				return conn.(*net.UDPConn), true, nil
			}
			_ = conn.Close()
		}
	}
	conn, err := net.DialUDP("udp", nil, addr)
	return conn, false, err
}
