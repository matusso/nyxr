package service

import (
	"bytes"
	"context"
	"encoding/binary"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/matusso/nyxr/internal/observe"
)

// ikeResponder answers each datagram with reply(request); nil stays silent.
func ikeResponder(t *testing.T, reply func([]byte) []byte) (uint16, <-chan []byte) {
	t.Helper()
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Skipf("loopback unavailable: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	seen := make(chan []byte, 16)
	go func() {
		buf := make([]byte, 4096)
		for {
			n, from, err := conn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			request := append([]byte(nil), buf[:n]...)
			select {
			case seen <- request:
			default:
			}
			if r := reply(request); r != nil {
				_, _ = conn.WriteToUDP(r, from)
			}
		}
	}()
	return uint16(conn.LocalAddr().(*net.UDPAddr).Port), seen
}

func payload(next byte, body []byte) []byte {
	p := []byte{next, 0, 0, 0}
	binary.BigEndian.PutUint16(p[2:], uint16(4+len(body)))
	return append(p, body...)
}

func ikeReplyTo(request []byte, responder []byte, next, version, exchange, flags byte, body []byte) []byte {
	msg := append(append([]byte(nil), request[:8]...), responder...)
	msg = append(msg, next, version, exchange, flags, 0x76, 0xb5, 0xdf, 0x1e, 0, 0, 0, 0)
	binary.BigEndian.PutUint32(msg[24:28], uint32(len(msg)+len(body)))
	return append(msg, body...)
}

var responderSPI = []byte{0xb9, 0x69, 0x54, 0x5c, 0x24, 0xa0, 0x05, 0xca}

// The gateway from the Shodan banner: IKEv1 over NAT-T only, answering with
// an Informational NO-PROPOSAL-CHOSEN notify and ignoring IKEv2.
func TestIKEDecodesNATTReplyOnHintedPort(t *testing.T) {
	port, seen := ikeResponder(t, func(q []byte) []byte {
		if !bytes.HasPrefix(q, nonESPMarker) || len(q) < 32 || q[4+17] != 0x10 {
			return nil
		}
		notify := payload(0, []byte{0, 0, 0, 1, 1, 0, 0, 14})
		return append(append([]byte(nil), nonESPMarker...), ikeReplyTo(q[4:], responderSPI, 11, 0x10, 5, 0, notify)...)
	})
	e := &Engine{cfg: Config{Timeout: 5 * time.Second}, pacer: newPacer(0), enabled: map[string]bool{ProbeIKE: true}}
	target := Target{Addr: netip.MustParseAddr("127.0.0.1"), Port: port, Transport: "udp", State: "open"}

	if o := e.Interrogate(context.Background(), target); o.Service == ProbeIKE {
		t.Fatalf("IKE probe ran on an unhinted, non-IKE port: %+v", o)
	}
	for len(seen) > 0 {
		<-seen
	}
	target.Service = ProbeIKE // discovery validated IKE here
	o := e.Interrogate(context.Background(), target)
	if o.Service != ProbeIKE || o.Fingerprint != observe.FingerprintMatched {
		t.Fatalf("IKE identity: %+v", o)
	}
	want := map[string]string{
		"banner": "VPN (IKE NAT-T)", "ike.nat_t": "true", "ike.responder_spi": "b969545c24a005ca",
		"ike.next_payload": "Notification (N)", "ike.version": "1.0", "ike.exchange_type": "Informational",
		"ike.flags.encryption": "false", "ike.flags.commit": "false", "ike.flags.authentication": "false",
		"ike.message_id": "76b5df1e", "ike.length": "40", "ike.notify": "NO-PROPOSAL-CHOSEN", "ike.versions": "1",
	}
	for k, v := range want {
		if o.Attributes[k] != v {
			t.Errorf("%s = %q, want %q", k, o.Attributes[k], v)
		}
	}
	var matched *observe.Evidence
	for i := range o.Evidence {
		if o.Evidence[i].Matched == ProbeIKE {
			matched = &o.Evidence[i]
			break
		}
	}
	if matched == nil || len(matched.Decoded) < 8 || matched.Decoded[0].Value != o.Attributes["ike.initiator_spi"] {
		t.Fatalf("IKE evidence: %+v", o.Evidence)
	}
	// A non-4500 port tries plain v1, plain v2, then NAT-T v1, then NAT-T v2.
	var order []string
	for len(seen) > 0 {
		q := <-seen
		framing, body := "plain", q
		if bytes.HasPrefix(q, nonESPMarker) {
			framing, body = "natt", q[4:]
		}
		order = append(order, framing+"/"+map[byte]string{0x10: "v1", 0x20: "v2"}[body[17]])
	}
	if got := strings.Join(order, ","); got != "plain/v1,plain/v2,natt/v1,natt/v2" {
		t.Fatalf("attempt order %s", got)
	}
	if !strings.Contains(o.Reason, "notify NO-PROPOSAL-CHOSEN") {
		t.Fatalf("summary: %s", o.Reason)
	}
}

// An IKEv2-only strongSwan answers IKE_SA_INIT with its chosen proposal and a
// versioned vendor ID, after ignoring the IKEv1 offer.
func TestIKEv2OnlyGatewayDecodesProposalAndVendor(t *testing.T) {
	port, _ := ikeResponder(t, func(q []byte) []byte {
		if len(q) < 28 || q[17] != 0x20 {
			return nil
		}
		proposal := []byte{0, 0, 0, 0, 1, 1, 0, 4}
		proposal = append(proposal, 3, 0, 0, 12, 1, 0, 0, 12, 0x80, 14, 1, 0) // AES-CBC-256
		proposal = append(proposal, 3, 0, 0, 8, 2, 0, 0, 5)                   // HMAC-SHA2-256
		proposal = append(proposal, 3, 0, 0, 8, 3, 0, 0, 12)                  // HMAC-SHA2-256-128
		proposal = append(proposal, 0, 0, 0, 8, 4, 0, 0, 14)                  // MODP-2048
		binary.BigEndian.PutUint16(proposal[2:4], uint16(len(proposal)))
		body := payload(34, proposal)
		body = append(body, payload(40, append([]byte{0, 14, 0, 0}, make([]byte, 256)...))...)
		body = append(body, payload(43, make([]byte, 32))...)
		body = append(body, payload(41, md5Of("strongSwan 5.9.1"))...)
		body = append(body, payload(0, []byte{0, 0, 0x40, 0x2e})...) // IKEV2_FRAGMENTATION_SUPPORTED
		return ikeReplyTo(q, responderSPI, 33, 0x20, 34, 0x20, body)
	})
	e := &Engine{cfg: Config{Timeout: 5 * time.Second}, pacer: newPacer(0), enabled: map[string]bool{ProbeIKE: true}}
	o := e.Interrogate(context.Background(), Target{Addr: netip.MustParseAddr("127.0.0.1"), Port: port, Transport: "udp", State: "open", Service: ProbeIKE})
	want := map[string]string{
		"ike.versions": "2", "ike.version": "2.0", "ike.exchange_type": "IKE_SA_INIT", "ike.flags.response": "true",
		"ike.transform": "AES-CBC-256/HMAC-SHA2-256/HMAC-SHA2-256-128/MODP-2048", "ike.ke_group": "MODP-2048",
		"ike.vendors": "strongSwan 5.9.1", "ike.product": "strongSwan 5.9.1", "ike.notify": "IKEV2_FRAGMENTATION_SUPPORTED",
		"banner": "VPN (IKE)",
	}
	for k, v := range want {
		if o.Attributes[k] != v {
			t.Errorf("%s = %q, want %q", k, o.Attributes[k], v)
		}
	}
	if o.Product != "strongSwan" || o.Version != "5.9.1" {
		t.Fatalf("product %q version %q", o.Product, o.Version)
	}
	if strings.Contains(o.Reason, "notify") {
		t.Fatalf("status notifies are not errors: %s", o.Reason)
	}
}

func TestIKEv1MainModeReplyDecodesTransformAndWindows(t *testing.T) {
	request := ikeMainMode([]byte{1, 2, 3, 4, 5, 6, 7, 8})
	transform := []byte{0, 0, 0, 0, 1, 1, 0, 0,
		0x80, 1, 0, 5, 0x80, 2, 0, 2, 0x80, 3, 0, 1, 0x80, 4, 0, 2, 0x80, 11, 0, 1, 0, 12, 0, 4, 0, 0, 0x70, 0x80}
	binary.BigEndian.PutUint16(transform[2:4], uint16(len(transform)))
	proposal := append([]byte{0, 0, 0, 0, 1, 1, 0, 1}, transform...)
	binary.BigEndian.PutUint16(proposal[2:4], uint16(len(proposal)))
	sa := payload(13, append([]byte{0, 0, 0, 1, 0, 0, 0, 1}, proposal...))
	sa = append(sa, payload(13, append(md5Of("MS NT5 ISAKMPOAKLEY"), 0, 0, 0, 9))...)
	sa = append(sa, payload(0, mustHex("afcad71368a1f1c96b8696fc77570100"))...)
	msg := ikeReplyTo(request, responderSPI, 1, 0x10, 2, 0, sa)
	if !validIKEReply(request[:8], msg, false) {
		t.Fatal("constructed reply rejected")
	}
	r := decodeIKE(msg, false, netip.AddrPort{}, netip.AddrPort{})
	want := map[string]string{
		"ike.transform": "3DES/SHA1/PSK/MODP-1024", "ike.lifetime": "28800s",
		"ike.vendors": "Microsoft Windows 10/Server 2016 or later,Dead Peer Detection",
		"ike.product": "Microsoft Windows 10/Server 2016 or later", "ike.exchange_type": "Identity Protection (Main Mode)",
	}
	for k, v := range want {
		if r.attrs[k] != v {
			t.Errorf("%s = %q, want %q", k, r.attrs[k], v)
		}
	}
}

func TestIKEVendorIDs(t *testing.T) {
	for vid, want := range map[string]ikeVendor{
		string(md5Of("RFC 3947")):                       {label: "RFC 3947 NAT-T"},
		string(md5Of("strongSwan")):                     {label: "strongSwan", product: "strongSwan"},
		string(md5Of("strongSwan 6.0.1")):               {label: "strongSwan 6.0.1", product: "strongSwan", version: "6.0.1"},
		string(append(md5Of("CISCO-UNITY")[:14], 1, 0)): {label: "Cisco Unity", product: "Cisco"},
		"FLEXVPN-SUPPORTED":                             {label: "FLEXVPN-SUPPORTED", product: "Cisco"},
		"OEu\\d\\jy\\\\ap":                              {label: "Openswan/Libreswan", product: "Openswan/Libreswan"},
		string(mustHex("f4ed19e0c114eb516faaac0ee37daf2807b4381f000000010000138d")): {
			label: "Check Point Firewall-1 version code 5005", product: "Check Point Firewall-1", version: "version code 5005"},
		"\x01\x02\x03\x04": {label: "unknown 01020304"},
	} {
		if got := identifyVendor([]byte(vid)); got != want {
			t.Errorf("%x: got %+v, want %+v", vid, got, want)
		}
	}
}

func TestIKERequestsAreWellFormed(t *testing.T) {
	spi := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	src, dst := netip.MustParseAddrPort("192.0.2.1:500"), netip.MustParseAddrPort("198.51.100.7:500")
	v2 := ikeSAInit(spi, make([]byte, 256), make([]byte, 32), src, dst)
	if int(binary.BigEndian.Uint32(v2[24:28])) != len(v2) || v2[17] != 0x20 || v2[18] != 34 || v2[19] != 0x08 {
		t.Fatalf("IKEv2 header: % x", v2[:28])
	}
	// SA, KE and Nonce lengths must chain exactly to the end of the message.
	off, next, kinds := 28, v2[16], []byte{}
	for next != 0 {
		kinds = append(kinds, next)
		next, off = v2[off], off+int(binary.BigEndian.Uint16(v2[off+2:off+4]))
	}
	if off != len(v2) || !bytes.Equal(kinds, []byte{33, 34, 40, 41, 41}) {
		t.Fatalf("IKEv2 payload chain %v ends at %d of %d", kinds, off, len(v2))
	}
	if got := ikev2Chosen(v2[32:]); got != "AES-CBC-128/HMAC-SHA2-256/HMAC-SHA2-256-128/MODP-2048" {
		t.Fatalf("first offered transforms: %s", got)
	}
	if group := binary.BigEndian.Uint16(v2[28+int(binary.BigEndian.Uint16(v2[30:32]))+4:]); group != ikev2KEGroup {
		t.Fatalf("KE payload group %d", group)
	}
	// RFC 7296 2.23: SHA-1(SPIi | SPIr=0 | IP | port), source then destination.
	spis := append(append([]byte(nil), spi...), make([]byte, 8)...)
	if !bytes.HasSuffix(v2, append([]byte{0, 0, 0, 28, 0, 0, 0x40, 0x05}, natDetection(spis, dst)...)) ||
		!bytes.Contains(v2, append([]byte{0, 0, 0x40, 0x04}, natDetection(spis, src)...)) {
		t.Fatal("NAT detection notifies missing or wrong")
	}
	v1 := ikeMainMode(spi)
	if int(binary.BigEndian.Uint32(v1[24:28])) != len(v1) {
		t.Fatal("IKEv1 length")
	}
	off, next, kinds = 28, v1[16], nil
	for next != 0 {
		kinds = append(kinds, next)
		next, off = v1[off], off+int(binary.BigEndian.Uint16(v1[off+2:off+4]))
	}
	if off != len(v1) || !bytes.Equal(kinds, []byte{1, 13, 13, 13, 13}) || !bytes.Contains(v1, md5Of("RFC 3947")) {
		t.Fatalf("IKEv1 must announce NAT-T after the SA: %v", kinds)
	}
	if chosen, _ := ikev1Chosen(v1[28+12:]); chosen != "3DES/SHA1/PSK/MODP-1024" {
		t.Fatalf("first offered IKEv1 transform: %s", chosen)
	}
}

func TestIKERejectsForeignReplies(t *testing.T) {
	spi := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	reply := append(append([]byte(nil), spi...), make([]byte, 8)...)
	reply = append(reply, 0, 0x10, 5, 0, 0, 0, 0, 0, 0, 0, 0, 28)
	if !validIKEReply(spi, reply, false) {
		t.Fatal("rejected a valid plain reply")
	}
	if validIKEReply(spi, reply, true) {
		t.Fatal("accepted a NAT-T reply without the non-ESP marker")
	}
	if validIKEReply([]byte{8, 7, 6, 5, 4, 3, 2, 1}, reply, false) {
		t.Fatal("accepted a reply to another initiator SPI")
	}
	reply[27] = 99
	if validIKEReply(spi, reply, false) {
		t.Fatal("accepted a length field that disagrees with the datagram")
	}
	request := ikeSAInit(spi, make([]byte, 256), make([]byte, 32), netip.AddrPort{}, netip.AddrPort{})
	if validIKEReply(spi, request, false) {
		t.Fatal("accepted an IKEv2 request without the response flag")
	}
	// Truncated payloads must not panic the decoder.
	for n := 28; n < 60; n++ {
		msg := append(append([]byte(nil), spi...), make([]byte, 8)...)
		msg = append(msg, 33, 0x20, 34, 0x20, 0, 0, 0, 0, 0, 0, 0, 0)
		msg = append(msg, bytes.Repeat([]byte{0xff}, n-28)...)
		binary.BigEndian.PutUint32(msg[24:28], uint32(len(msg)))
		_ = decodeIKE(msg, false, netip.AddrPort{}, netip.AddrPort{})
	}
}

// The responder hashes the address it saw the scanner at and its own address.
func TestIKEv2NATDetectionVerdicts(t *testing.T) {
	local, remote := netip.MustParseAddrPort("192.0.2.1:500"), netip.MustParseAddrPort("198.51.100.7:500")
	for _, tc := range []struct {
		name              string
		seenAt, gatewayIs netip.AddrPort
		scanner, gateway  string
		summary           string
	}{
		{"direct", local, remote, "direct", "direct", ""},
		{"gateway port-forwarded", local, netip.MustParseAddrPort("10.0.0.5:500"), "direct", "behind NAT", "(gateway behind NAT)"},
		{"scanner NATed", netip.MustParseAddrPort("203.0.113.9:31337"), remote, "behind NAT", "direct", "(scanner behind NAT)"},
	} {
		request := ikeSAInit([]byte{1, 2, 3, 4, 5, 6, 7, 8}, make([]byte, 256), make([]byte, 32), local, remote)
		spis := append(append([]byte(nil), request[:8]...), responderSPI...)
		body := payload(41, append([]byte{0, 14, 0, 0}, make([]byte, 256)...))
		body = append(body, payload(41, ikeNotify(16388, natDetection(spis, tc.gatewayIs)))...)
		body = append(body, payload(0, ikeNotify(16389, natDetection(spis, tc.seenAt)))...)
		r := decodeIKE(ikeReplyTo(request, responderSPI, 34, 0x20, 34, 0x20, body), false, local, remote)
		if r.attrs["ike.nat.scanner"] != tc.scanner || r.attrs["ike.nat.gateway"] != tc.gateway ||
			r.attrs["ike.nat_t_support"] != "RFC 7296 NAT detection" || !strings.Contains(r.summary, tc.summary) {
			t.Errorf("%s: %v / %s", tc.name, r.attrs, r.summary)
		}
	}
}

func TestIKEv1NATTSupportFromVendorID(t *testing.T) {
	request := ikeMainMode([]byte{1, 2, 3, 4, 5, 6, 7, 8})
	body := payload(0, md5Of("RFC 3947"))
	r := decodeIKE(ikeReplyTo(request, responderSPI, 13, 0x10, 2, 0, body), false, netip.AddrPort{}, netip.AddrPort{})
	if r.attrs["ike.nat_t_support"] != "RFC 3947 NAT-T" {
		t.Fatalf("NAT-T support: %v", r.attrs)
	}
}
