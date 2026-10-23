package packetio

import "testing"

// OpenLive fails closed on every platform: without raw-socket privileges
// (Linux CAP_NET_RAW), BPF device access (macOS) or Npcap (Windows), and for
// unknown interfaces. It must return an error, never panic or fall back.
func TestOpenLiveFailsClosedOnUnknownInterface(t *testing.T) {
	io, err := OpenLive("nyxr-noif0")
	if err == nil {
		io.Close()
		t.Fatal("opened a nonexistent interface")
	}
	if io != nil {
		t.Fatal("returned a transport alongside an error")
	}
	if _, err := OpenLive(""); err == nil {
		t.Fatal("opened an empty interface name")
	}
}
