package service

import (
	"bytes"
	"context"
	"crypto/md5" //nolint:gosec // IKEv1 NAT-D uses the negotiated hash
	"crypto/rand"
	"crypto/sha1" //nolint:gosec // RFC 7296 2.23 defines NAT detection as SHA-1
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"hash"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/matusso/nyxr/internal/observe"
	"github.com/matusso/nyxr/internal/probe"
)

// IKEPort covers ISAKMP and its RFC 3948 NAT-T port. Other ports are probed
// when UDP discovery already validated an IKE reply there.
func IKEPort(port uint16) bool { return port == 500 || port == 4500 }

// nonESPMarker prefixes IKE messages that share the NAT-T port with ESP.
var nonESPMarker = []byte{0, 0, 0, 0}

// ikeTransforms is an ike-scan style offer: 3DES/DES x SHA1/MD5 x MODP-1024/768
// plus AES-128/SHA1/MODP-1024 and AES-256/SHA2-256/MODP-2048. A broad offer
// makes a gateway answer with a Main Mode SA or a NO-PROPOSAL-CHOSEN notify
// instead of silently dropping a proposal it does not like.
var ikeTransforms = func() [][][2]uint16 {
	var out [][][2]uint16
	for _, enc := range []uint16{5, 1} {
		for _, hash := range []uint16{2, 1} {
			for _, group := range []uint16{2, 1} {
				out = append(out, [][2]uint16{{1, enc}, {2, hash}, {3, 1}, {4, group}})
			}
		}
	}
	return append(out,
		[][2]uint16{{1, 7}, {14, 128}, {2, 2}, {3, 1}, {4, 2}},
		[][2]uint16{{1, 7}, {14, 256}, {2, 4}, {3, 1}, {4, 14}})
}()

// natTVendorIDs announce NAT traversal. RFC 3947 3.1: its vendor ID MUST be
// sent in the first two Phase 1 messages; the drafts are what older peers know.
var natTVendorIDs = [][]byte{
	md5Of("RFC 3947"), md5Of("draft-ietf-ipsec-nat-t-ike-03"),
	md5Of("draft-ietf-ipsec-nat-t-ike-02\n"), md5Of("draft-ietf-ipsec-nat-t-ike-02"),
}

// ikev1SA is an IKEv1 SA payload offering transforms in one proposal; next
// is the type of the payload after it.
func ikev1SA(next byte, offer [][][2]uint16) []byte {
	var transforms []byte
	for i, attrs := range offer {
		var a []byte
		for _, kv := range attrs {
			a = binary.BigEndian.AppendUint16(a, 0x8000|kv[0])
			a = binary.BigEndian.AppendUint16(a, kv[1])
		}
		// Life type seconds, life duration 28800 as a 4-byte variable attribute.
		a = append(a, 0x80, 11, 0, 1, 0, 12, 0, 4, 0, 0, 0x70, 0x80)
		more := byte(3)
		if i == len(offer)-1 {
			more = 0
		}
		transforms = append(transforms, more, 0, 0, 0, byte(i+1), 1, 0, 0)
		binary.BigEndian.PutUint16(transforms[len(transforms)-6:], uint16(8+len(a)))
		transforms = append(transforms, a...)
	}
	proposal := append([]byte{0, 0, 0, 0, 1, 1, 0, byte(len(offer))}, transforms...)
	binary.BigEndian.PutUint16(proposal[2:4], uint16(len(proposal)))
	sa := append([]byte{next, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1}, proposal...)
	binary.BigEndian.PutUint16(sa[2:4], uint16(len(sa)))
	return sa
}

// natTVendorPayloads are the NAT-T vendor IDs as the last payloads of a message.
func natTVendorPayloads() []byte {
	var out []byte
	for i, vid := range natTVendorIDs {
		next := byte(13)
		if i == len(natTVendorIDs)-1 {
			next = 0
		}
		out = append(out, ikePayload(next, vid)...)
	}
	return out
}

// ikeMainMode builds an IKEv1 Main Mode SA request (RFC 2409) for spi,
// announcing NAT traversal support (RFC 3947).
func ikeMainMode(spi []byte) []byte {
	return ikeMessage(spi, 1, 0x10, 2, 0, append(ikev1SA(13, ikeTransforms), natTVendorPayloads()...))
}

// ikeAggressiveTransforms offers AES and 3DES with SHA2-256, SHA1 and MD5 for
// pre-shared key and XAUTH. Aggressive Mode sends its key exchange with the
// offer, so every transform names the same group.
func ikeAggressiveTransforms(group uint16) [][][2]uint16 {
	var out [][][2]uint16
	for _, auth := range []uint16{1, 65001} {
		for _, enc := range [][2]uint16{{7, 256}, {7, 128}, {5, 0}} {
			for _, hash := range []uint16{4, 2, 1} {
				t := [][2]uint16{{1, enc[0]}, {2, hash}, {3, auth}, {4, group}}
				if enc[1] != 0 {
					t = append(t, [2]uint16{14, enc[1]})
				}
				out = append(out, t)
			}
		}
	}
	return out
}

// ikeAggressive builds Aggressive Mode message 1 (RFC 2409 5.4): SA, KE,
// nonce and an identity. A gateway that accepts answers with its identity
// and, under pre-shared key authentication, a hash computed from the key.
func ikeAggressive(spi []byte, group uint16, ke, nonce []byte) []byte {
	body := ikev1SA(4, ikeAggressiveTransforms(group))
	body = append(body, ikePayload(10, ke)...)
	body = append(body, ikePayload(5, nonce)...)
	// ID_KEY_ID "vpn": an opaque name, as group-based remote access uses.
	body = append(body, ikePayload(13, append([]byte{11, 0, 0, 0}, "vpn"...))...)
	return ikeMessage(spi, 1, 0x10, 4, 0, append(body, natTVendorPayloads()...))
}

// ikev1HashSizes are the digest sizes by IKEv1 hash ID.
var ikev1HashSizes = map[uint32]int{1: 16, 2: 20, 4: 32, 5: 48, 6: 64}

// ikeMainModeKE builds Main Mode message 3 for spis (both cookies): KE, nonce
// and, when the peer announced NAT traversal, the NAT-D payloads of RFC 3947
// 3.2 (type natD, remote end first) so it answers with its own.
func ikeMainModeKE(spis, ke, nonce []byte, natD byte, hashSize int, local, remote netip.AddrPort) []byte {
	body := append(ikePayload(10, ke), ikePayload(natD, nonce)...)
	if natD != 0 {
		body = append(body, ikePayload(natD, natHash(hashSize, spis, remote))...)
		body = append(body, ikePayload(0, natHash(hashSize, spis, local))...)
	}
	msg := ikeMessage(spis[:8], 4, 0x10, 2, 0, body)
	copy(msg[8:16], spis[8:])
	return msg
}

// ikev2Transforms is one non-AEAD IKE proposal (RFC 7296 3.3): AES-CBC and
// 3DES, SHA1/SHA2 PRFs and integrity, and common MODP and ECP groups.
var ikev2Transforms = [][3]uint16{
	{1, 12, 128}, {1, 12, 256}, {1, 3, 0},
	{2, 5, 0}, {2, 6, 0}, {2, 7, 0}, {2, 2, 0},
	{3, 12, 0}, {3, 13, 0}, {3, 14, 0}, {3, 2, 0},
	{4, 14, 0}, {4, 19, 0}, {4, 20, 0}, {4, 31, 0}, {4, 2, 0}, {4, 15, 0},
}

// ikev2KEGroup is the group of the first KE payload. A responder preferring
// another offered group answers INVALID_KE_PAYLOAD naming it, and the probe
// retries with that group.
const ikev2KEGroup = 14

// ikev2ESPTransforms is the Child SA offer IKE_AUTH must carry: AES-CBC,
// SHA2-256/SHA1 integrity, no extended sequence numbers.
var ikev2ESPTransforms = [][3]uint16{{1, 12, 256}, {1, 12, 128}, {3, 12, 0}, {3, 2, 0}, {5, 0, 0}}

// ikev2Proposal is an SA payload body with one proposal (RFC 7296 3.3).
func ikev2Proposal(protocol byte, spi []byte, offer [][3]uint16) []byte {
	proposal := append([]byte{0, 0, 0, 0, 1, protocol, byte(len(spi)), byte(len(offer))}, spi...)
	for i, tr := range offer {
		last := byte(3)
		if i == len(offer)-1 {
			last = 0
		}
		t := []byte{last, 0, 0, 8, byte(tr[0]), 0, byte(tr[1] >> 8), byte(tr[1])}
		if tr[2] != 0 {
			t = append(t, 0x80, 14, byte(tr[2]>>8), byte(tr[2]))
			t[3] = 12
		}
		proposal = append(proposal, t...)
	}
	binary.BigEndian.PutUint16(proposal[2:4], uint16(len(proposal)))
	return proposal
}

// ikeSAInit builds an IKEv2 IKE_SA_INIT request with a public value ke of
// group, nonce, and the NAT detection notifies of RFC 7296 2.23 for the
// socket's source and destination. cookie, when the responder demanded one
// (RFC 7296 2.6), is returned in a leading notify.
func ikeSAInit(spi []byte, group uint16, ke, nonce, cookie []byte, source, destination netip.AddrPort) []byte {
	var body []byte
	first := byte(33)
	if cookie != nil {
		body, first = ikePayload(33, ikeNotify(16390, cookie)), 41
	}
	body = append(body, ikePayload(34, ikev2Proposal(1, nil, ikev2Transforms))...)
	body = append(body, ikePayload(40, append([]byte{byte(group >> 8), byte(group), 0, 0}, ke...))...)
	body = append(body, ikePayload(41, nonce)...)
	body = append(body, ikePayload(41, ikeNotify(16430, nil))...) // IKEV2_FRAGMENTATION_SUPPORTED
	// The request's SPIr is zero; the NAT notifies come last.
	spis := append(append([]byte(nil), spi...), make([]byte, 8)...)
	body = append(body, ikePayload(41, ikeNotify(16388, natDetection(spis, source)))...)
	body = append(body, ikePayload(0, ikeNotify(16389, natDetection(spis, destination)))...)
	return ikeMessage(spi, first, 0x20, 34, 0x08, body)
}

// ikeAuthPayloads is the body of the first IKE_AUTH request. It carries no
// AUTH payload, which asks for EAP (RFC 7296 2.16): the gateway then
// identifies itself with IDr, its certificate and an EAP method, or refuses.
// No credential is offered. The empty CERTREQ asks for the certificate.
func ikeAuthPayloads(local netip.AddrPort) (first byte, inner []byte, err error) {
	espSPI := make([]byte, 4)
	if _, err := rand.Read(espSPI); err != nil {
		return 0, nil, err
	}
	id := []byte{1, 0, 0, 0} // ID_IPV4_ADDR, as a Windows client sends
	if !local.Addr().Unmap().Is4() {
		id[0] = 5
	}
	id = append(id, local.Addr().Unmap().AsSlice()...)
	// One IPv4 traffic selector: any protocol, port and address.
	ts := []byte{1, 0, 0, 0, 7, 0, 0, 16, 0, 0, 0xff, 0xff, 0, 0, 0, 0, 255, 255, 255, 255}
	// Each payload names the type of the one after it.
	inner = ikePayload(38, id)                                                             // IDi
	inner = append(inner, ikePayload(33, []byte{4})...)                                    // CERTREQ, X.509
	inner = append(inner, ikePayload(44, ikev2Proposal(3, espSPI, ikev2ESPTransforms))...) // SAi2
	inner = append(inner, ikePayload(45, ts)...)                                           // TSi
	inner = append(inner, ikePayload(41, ts)...)                                           // TSr
	return 35, append(inner, ikePayload(0, ikeNotify(16396, nil))...), nil                 // MOBIKE_SUPPORTED
}

func ikePayload(next byte, body []byte) []byte {
	p := []byte{next, 0, 0, 0}
	binary.BigEndian.PutUint16(p[2:4], uint16(4+len(body)))
	return append(p, body...)
}

// ikeNotify is an IKEv2 Notify body for the IKE SA: protocol 0, no SPI.
func ikeNotify(kind uint16, data []byte) []byte {
	return append([]byte{0, 0, byte(kind >> 8), byte(kind)}, data...)
}

// natHashes are the NAT detection digests by size: SHA-1 in IKEv2, the
// negotiated hash in IKEv1.
var natHashes = map[int]func() hash.Hash{16: md5.New, 20: sha1.New, 32: sha256.New, 48: sha512.New384, 64: sha512.New}

// natHash is HASH(SPIi | SPIr | IP | port) of RFC 3947 3.2 and RFC 7296 2.23
// with the digest of that size. An unknown address yields zeros, which a
// responder reads as "NAT present".
func natHash(size int, spis []byte, ap netip.AddrPort) []byte {
	if natHashes[size] == nil || !ap.IsValid() {
		return make([]byte, size)
	}
	h := natHashes[size]()
	h.Write(spis)
	h.Write(ap.Addr().Unmap().AsSlice())
	h.Write([]byte{byte(ap.Port() >> 8), byte(ap.Port())})
	return h.Sum(nil)
}

func natDetection(spis []byte, ap netip.AddrPort) []byte { return natHash(sha1.Size, spis, ap) }

// natInternalRanges are where a NATed gateway's own address usually lives,
// smallest first.
var natInternalRanges = []netip.Prefix{
	netip.MustParsePrefix("192.168.0.0/16"), netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("100.64.0.0/10"), netip.MustParsePrefix("10.0.0.0/8"),
}

// natInternal recovers the address a NATed gateway hashed into its NAT
// detection payload. The hash is unsalted beyond the SPIs, so private IPv4
// space is searched on the scanned port and the IKE ports: about 44 million
// digests (a second or two of CPU) when nothing matches. An IPv6 target is
// first tried against the guessable part of IPv6: see natInternal6.
func natInternal(ctx context.Context, hashes [][]byte, spis []byte, remote netip.AddrPort) (netip.AddrPort, bool) {
	if len(hashes) == 0 || natHashes[len(hashes[0])] == nil {
		return netip.AddrPort{}, false
	}
	h, sum := natHashes[len(hashes[0])](), make([]byte, 0, 64)
	buf := append(append(make([]byte, 0, 34), spis...), make([]byte, 18)...)
	ports := []uint16{remote.Port()}
	for _, port := range []uint16{500, 4500} {
		if port != remote.Port() {
			ports = append(ports, port)
		}
	}
	// match hashes the n-byte address at buf[16:] with each port.
	match := func(n int) (netip.AddrPort, bool) {
		for _, port := range ports {
			binary.BigEndian.PutUint16(buf[16+n:], port)
			h.Reset()
			h.Write(buf[:18+n])
			got := h.Sum(sum[:0])
			for _, want := range hashes {
				if bytes.Equal(got, want) {
					addr, _ := netip.AddrFromSlice(buf[16 : 16+n])
					return netip.AddrPortFrom(addr, port), true
				}
			}
		}
		return netip.AddrPort{}, false
	}
	if target := remote.Addr().Unmap(); target.Is6() {
		if found, ok := natInternal6(ctx, target, buf[16:32], func() (netip.AddrPort, bool) { return match(16) }); ok {
			return found, true
		}
	}
	// Small ranges first; a gateway reached over IPv6 may still be an IPv4
	// host behind NAT64 or a dual-stack load balancer.
	for _, prefix := range natInternalRanges {
		first := binary.BigEndian.Uint32(prefix.Addr().AsSlice())
		for i := range uint32(1) << (32 - prefix.Bits()) {
			if i&0xffff == 0 && ctx.Err() != nil {
				return netip.AddrPort{}, false
			}
			binary.BigEndian.PutUint32(buf[16:], first+i)
			if found, ok := match(4); ok {
				return found, true
			}
		}
	}
	return netip.AddrPort{}, false
}

// natInternal6 writes candidate IPv6 addresses into addr and asks match.
// shortcut: a properly random ULA prefix (RFC 4193, 40 random bits) cannot be
// searched, so only the prefixes people type by hand are tried: fd00:0:0:S::/64
// for S up to 0xff, fc00::/64 and fec0::/64, each with the target's interface
// ID (NPTv6 keeps it) and the interface IDs ::1 to ::ffff. About 50 million
// digests on a miss; widen the lists when real deployments show other habits.
func natInternal6(ctx context.Context, target netip.Addr, addr []byte, match func() (netip.AddrPort, bool)) (netip.AddrPort, bool) {
	iid := target.As16()
	for s := range 258 {
		if ctx.Err() != nil {
			break
		}
		clear(addr)
		switch {
		case s < 256:
			addr[0], addr[7] = 0xfd, byte(s)
		case s == 256:
			addr[0] = 0xfc
		default:
			addr[0], addr[1] = 0xfe, 0xc0
		}
		copy(addr[8:], iid[8:])
		if found, ok := match(); ok {
			return found, true
		}
		clear(addr[8:])
		for i := 1; i <= 0xffff; i++ {
			binary.BigEndian.PutUint16(addr[14:], uint16(i))
			if found, ok := match(); ok {
				return found, true
			}
		}
	}
	return netip.AddrPort{}, false
}

func ikeMessage(spi []byte, next, version, exchange, flags byte, body []byte) []byte {
	msg := append(append([]byte(nil), spi...), make([]byte, 8)...)
	msg = append(msg, next, version, exchange, flags, 0, 0, 0, 0, 0, 0, 0, 0)
	binary.BigEndian.PutUint32(msg[24:28], uint32(28+len(body)))
	return append(msg, body...)
}

// probeIKE tries IKEv1 Main Mode, then IKEv2 IKE_SA_INIT, framed for NAT-T
// first on 4500 and plain first elsewhere. When IKEv1 answers, IKEv2 is tried
// on the same framing too so the observation states both versions. An
// accepted offer is followed up: Main Mode messages 3 and 4, or the IKEv2 key
// exchange and a first IKE_AUTH.
func (e *Engine) probeIKE(ctx context.Context, t Target, o *observe.Observation) bool {
	framings := []bool{false, true}
	if t.Port == 4500 {
		framings = []bool{true, false}
	}
	// Up to four attempts, the IKEv2 follow-up and the follow-up exchanges.
	r := &ikeRun{e: e, ctx: ctx, o: o, per: e.timeout(ProbeIKE) / 7,
		addr: &net.UDPAddr{IP: net.IP(t.Addr.AsSlice()), Port: int(t.Port), Zone: t.Addr.Zone()}}
	attempt := map[int]func(bool) (ikeReply, bool){1: r.v1, 2: r.v2}
	for _, natT := range framings {
		for _, version := range []int{1, 2} {
			if ctx.Err() != nil {
				return false
			}
			reply, ok := attempt[version](natT)
			if !ok {
				continue
			}
			versions, summary := strconv.Itoa(version), reply.summary
			product, productVersion := reply.product, reply.productVersion
			if version == 1 && ctx.Err() == nil {
				if v2, ok := r.v2(natT); ok {
					versions, summary = "1,2", summary+"; "+v2.summary
					for k, v := range v2.attrs {
						if k != "banner" {
							reply.attrs["ike.v2."+strings.TrimPrefix(k, "ike.")] = v
						}
					}
					if product == "" {
						product, productVersion = v2.product, v2.productVersion
					}
				}
			}
			reply.attrs["ike.versions"] = versions
			o.Probe, o.Service, o.Attributes = ProbeIKE, ProbeIKE, reply.attrs
			o.Reason = reply.label + " " + summary
			o.Product, o.Version = product, productVersion
			return true
		}
	}
	return false
}

// ikeRun is one probeIKE call: every exchange lands in o.Evidence.
type ikeRun struct {
	e    *Engine
	ctx  context.Context
	o    *observe.Observation
	addr *net.UDPAddr
	per  time.Duration // reply timeout of one exchange
}

// ikeSession is one UDP socket and the initiator SPI its replies must echo.
type ikeSession struct {
	conn          *net.UDPConn
	natT          bool
	local, remote netip.AddrPort
	spi           []byte
	seen          [][]byte // datagrams sent or accepted; retransmits of them are skipped
}

func (r *ikeRun) fail(err error) (ikeReply, bool) {
	r.o.Evidence = append(r.o.Evidence, observe.Evidence{Probe: ProbeIKE, Layer: "udp", Started: time.Now().UTC(), Error: err.Error()})
	return ikeReply{}, false
}

// dial opens a session to addr with a fresh SPI when spi is nil.
func (r *ikeRun) dial(addr *net.UDPAddr, natT bool, spi []byte) (*ikeSession, error) {
	if spi == nil {
		spi = make([]byte, 8)
		if _, err := rand.Read(spi); err != nil {
			return nil, err
		}
	}
	// RFC 3947 and 7296 make responders answer any source port, so this works
	// through NAT; some gateways still only answer peers on the IKE ports,
	// which root can bind.
	source := uint16(500)
	if natT {
		source = 4500
	}
	conn, _, err := probe.DialUDP(r.ctx, addr, source)
	if err != nil {
		return nil, err
	}
	return &ikeSession{conn: conn, natT: natT, spi: spi, local: conn.LocalAddr().(*net.UDPAddr).AddrPort(), remote: addr.AddrPort()}, nil
}

// roundTrip sends msg and returns the next validated reply, both as the
// datagrams on the wire (with the non-ESP marker under NAT-T).
func (r *ikeRun) roundTrip(s *ikeSession, msg []byte) (response, request []byte, err error) {
	if err := r.e.pacer.wait(r.ctx); err != nil {
		return nil, nil, err
	}
	request = msg
	if s.natT {
		request = append(append([]byte(nil), nonESPMarker...), msg...)
	}
	s.seen = append(s.seen, request)
	deadline := time.Now().Add(r.per)
	if d, ok := r.ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	if err := s.conn.SetDeadline(deadline); err != nil {
		return nil, request, err
	}
	if _, err := s.conn.Write(request); err != nil {
		return nil, request, err
	}
	response, err = r.recv(s)
	return response, request, err
}

// recv returns the next validated datagram that is not a retransmit, within
// the deadline roundTrip set.
func (r *ikeRun) recv(s *ikeSession) ([]byte, error) {
	stop := context.AfterFunc(r.ctx, func() { _ = s.conn.SetDeadline(time.Now()) })
	defer stop()
	buf := make([]byte, 65507)
	for {
		n, err := s.conn.Read(buf)
		if err != nil {
			return nil, err
		}
		if validIKEReply(s.spi, buf[:n], s.natT) && !slices.ContainsFunc(s.seen, func(d []byte) bool { return bytes.Equal(d, buf[:n]) }) {
			response := append([]byte(nil), buf[:n]...)
			s.seen = append(s.seen, response)
			return response, nil
		}
	}
}

// plaintext decrypts an encrypted reply. One split into RFC 7383 fragments is
// completed from the datagrams that follow; marker is the length of their
// non-ESP prefix. It also returns the number of fragments.
func (r *ikeRun) plaintext(s *ikeSession, keys *ikev2Keys, msg []byte, marker int) ([]byte, int, error) {
	header, first, parts := msg, byte(0), map[int][]byte{}
	for {
		plain, num, total, err := keys.decrypt(msg)
		if err != nil {
			return nil, 0, err
		}
		if num == 1 {
			first = msg[28] // only the first fragment names the inner payload
		}
		parts[num] = plain
		if len(parts) >= total {
			ordered := make([][]byte, total)
			for i := range ordered {
				ordered[i] = parts[i+1]
			}
			return ikePlain(header, first, ordered...), total, nil
		}
		raw, err := r.recv(s)
		if err != nil {
			return nil, 0, err
		}
		msg = raw[marker:]
	}
}

// exchange is one request and its decoded reply, recorded as evidence. keys,
// when set, decrypt an IKEv2 Encrypted payload.
func (r *ikeRun) exchange(s *ikeSession, msg []byte, keys *ikev2Keys) (ikeReply, bool) {
	started := time.Now()
	ev := observe.Evidence{Probe: ProbeIKE, Layer: "udp", Started: started.UTC()}
	response, request, err := r.roundTrip(s, msg)
	ev.Request, ev.Response, ev.Duration = request, response, time.Since(started)
	decrypted, fragments := false, 0
	var wire []byte
	if err == nil {
		marker := len(request) - len(msg) // the non-ESP marker, if any
		response = response[marker:]
		wire = response
		if keys != nil && (response[16] == 46 || response[16] == 53) {
			response, fragments, err = r.plaintext(s, keys, response, marker)
			decrypted = true
		}
	}
	if err != nil {
		ev.Error = err.Error()
		r.o.Evidence = append(r.o.Evidence, ev)
		return ikeReply{}, false
	}
	reply := decodeIKE(response, s.natT, s.local, s.remote)
	reply.decrypted, reply.wire = decrypted, wire
	if fragments > 1 {
		reply.attrs["ike.fragments"] = strconv.Itoa(fragments)
	}
	if decrypted {
		reply.decoded = append([]observe.ByteField{{Field: "encrypted payload", Value: "decrypted", Note: "offsets below index the decrypted message"}}, reply.decoded...)
	}
	if internal, ok := natInternal(r.ctx, reply.gatewayHashes, reply.spis, s.remote); ok {
		reply.attrs["ike.nat.gateway_internal"] = internal.String()
		reply.summary += ", gateway internal address " + internal.String()
	}
	ev.Matched, ev.Decoded = ProbeIKE, reply.decoded
	r.o.Evidence = append(r.o.Evidence, ev)
	r.o.RTT = ev.Duration
	return reply, true
}

// v1 offers Main Mode and, when the gateway accepts a transform, continues to
// messages 3 and 4, where it sends its key exchange, NAT-D payloads and often
// more vendor IDs. Message 5 needs the credential, so the probe stops there
// and asks for Aggressive Mode instead.
func (r *ikeRun) v1(natT bool) (ikeReply, bool) {
	s, err := r.dial(r.addr, natT, nil)
	if err != nil {
		return r.fail(err)
	}
	defer s.conn.Close()
	reply, ok := r.exchange(s, ikeMainMode(s.spi), nil)
	if !ok {
		return reply, false
	}
	r.mainModeKE(s, &reply)
	r.aggressive(natT, &reply)
	return reply, true
}

func (r *ikeRun) mainModeKE(s *ikeSession, reply *ikeReply) {
	if reply.v1Group == 0 || r.ctx.Err() != nil {
		return
	}
	random := make([]byte, 96+20)
	if _, err := rand.Read(random); err != nil {
		return
	}
	// shortcut: MODP-768 has no prime in modpPrimes, so its value is random
	// bytes below the prime and strict responders refuse half of them; add
	// the prime if that matters.
	ke, nonce := random[:96], random[96:]
	ke[0] &= 0x7f
	if dh, err := newIKEDH(uint16(reply.v1Group)); err == nil {
		ke = dh.public
	} else if reply.v1Group != 1 {
		return
	}
	msg := ikeMainModeKE(reply.spis, ke, nonce, reply.v1NATD, ikev1HashSizes[reply.v1Hash], s.local, s.remote)
	if more, ok := r.exchange(s, msg, nil); ok {
		if mainMode := "IKEv1 " + ikeExchanges[2]; strings.HasPrefix(more.summary, mainMode) {
			more.summary = "message 4" + strings.TrimPrefix(more.summary, mainMode)
			reply.attrs["ike.main_mode_message"] = "4"
		}
		reply.follow(more, "ke")
	}
}

// aggressive asks a gateway that speaks IKEv1 for Aggressive Mode, as a new
// negotiation in the group Main Mode settled on (MODP-1024 otherwise). Its
// answer lands under ike.aggressive.*.
func (r *ikeRun) aggressive(natT bool, reply *ikeReply) {
	dh, err := newIKEDH(uint16(reply.v1Group))
	if err != nil {
		dh, err = newIKEDH(2)
	}
	nonce := make([]byte, 20)
	if _, rerr := rand.Read(nonce); err != nil || rerr != nil || r.ctx.Err() != nil {
		return
	}
	s, err := r.dial(r.addr, natT, nil)
	if err != nil {
		return
	}
	defer s.conn.Close()
	more, ok := r.exchange(s, ikeAggressive(s.spi, dh.group, dh.public, nonce), nil)
	if !ok {
		return
	}
	for _, k := range []string{"transform", "lifetime", "id", "hash"} {
		if v, ok := more.attrs["ike."+k]; ok {
			more.attrs["ike.aggressive."+k] = v
			delete(more.attrs, "ike."+k)
		}
	}
	status := "refused"
	if more.attrs["ike.exchange_type"] == ikeExchanges[4] && more.attrs["ike.aggressive.transform"] != "" {
		status = "accepted"
	}
	reply.attrs["ike.aggressive"] = status
	more.summary = "Aggressive Mode " + status + ": " + more.summary
	if more.attrs["ike.aggressive.hash"] != "" {
		more.summary += " (pre-shared key hash exposed)"
	}
	reply.follow(more, "aggressive")
}

// v2 sends IKE_SA_INIT, again with the cookie or the group the responder asks
// for, and then completes the key exchange with a first IKE_AUTH.
func (r *ikeRun) v2(natT bool) (ikeReply, bool) {
	s, err := r.dial(r.addr, natT, nil)
	if err != nil {
		return r.fail(err)
	}
	defer s.conn.Close()
	dh, err := newIKEDH(ikev2KEGroup)
	if err != nil {
		return r.fail(err)
	}
	// The nonce stays the same across retries: a cookie is bound to it.
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		return r.fail(err)
	}
	var reply ikeReply
	var cookie []byte
	for try := 0; ; try++ {
		next, ok := r.exchange(s, ikeSAInit(s.spi, dh.group, dh.public, nonce, cookie, s.local, s.remote), nil)
		if !ok {
			return reply, try > 0
		}
		reply = next
		if try < 2 && r.ctx.Err() == nil {
			if cookie == nil && reply.cookie != nil {
				cookie = reply.cookie
				continue
			}
			if retry, err := newIKEDH(reply.wantGroup); reply.wantGroup != dh.group && err == nil {
				dh = retry
				continue
			}
		}
		r.auth(s, &reply, dh, nonce)
		return reply, true
	}
}

// auth derives the IKE SA keys and sends IKE_AUTH. RFC 7296 2.23 moves the
// exchange to UDP/4500 once both ends support NAT traversal, so a gateway
// probed on 500 is asked there first and on 500 again if 4500 stays silent.
func (r *ikeRun) auth(s *ikeSession, reply *ikeReply, dh *ikeDH, nonce []byte) {
	if reply.picked == nil || reply.peerKE == nil || reply.peerNonce == nil || r.ctx.Err() != nil {
		return
	}
	shared, err := dh.shared(reply.peerKE)
	if err != nil {
		r.fail(err)
		return
	}
	keys, err := ikev2Derive(reply.picked, shared, nonce, reply.peerNonce, reply.spis)
	if err != nil {
		r.fail(err)
		return
	}
	first, inner, err := ikeAuthPayloads(s.local)
	if err != nil {
		return
	}
	request, err := keys.seal(reply.spis, 35, 0x08, 1, first, inner)
	if err != nil {
		r.fail(err)
		return
	}
	sessions := []*ikeSession{s}
	if reply.natDetection && !s.natT && s.remote.Port() == 500 {
		addr := *r.addr
		addr.Port = 4500
		if float, err := r.dial(&addr, true, s.spi); err == nil {
			defer float.conn.Close()
			sessions = []*ikeSession{float, s}
		}
	}
	for _, via := range sessions {
		more, ok := r.exchange(via, request, keys)
		if !ok {
			continue
		}
		if more.cert != nil && more.authData != nil {
			// RFC 7296 2.15: the responder signs its IKE_SA_INIT message, our
			// nonce and prf(SK_pr, its ID payload body).
			signed := append(append(slices.Clone(reply.wire), nonce...), hmacSum(keys.prf, keys.pr, more.idBody)...)
			more.attrs["ike.auth.signature"] = ikev2VerifyAuth(more.cert, more.authMethod, more.authData, signed)
			more.summary += " signature " + more.attrs["ike.auth.signature"]
		}
		reply.follow(more, "auth")
		reply.attrs["ike.auth.port"] = strconv.Itoa(int(via.remote.Port()))
		if more.decrypted {
			reply.attrs["ike.key_exchange"] = "completed"
			// Ask the gateway to drop the half-open SA instead of holding it
			// until its timeout; the answer does not matter.
			if del, err := keys.seal(reply.spis, 37, 0x08, 2, 42, ikePayload(0, []byte{1, 0, 0, 0})); err == nil {
				r.exchange(via, del, keys)
			}
		}
		return
	}
}

// validIKEReply requires the echoed initiator SPI, a known major version and
// a header length equal to the datagram, so stray traffic is not decoded.
func validIKEReply(spi, response []byte, natT bool) bool {
	if natT {
		if !bytes.HasPrefix(response, nonESPMarker) {
			return false
		}
		response = response[len(nonESPMarker):]
	}
	if len(response) < 28 {
		return false
	}
	major := response[17] >> 4
	if major == 2 && response[19]&0x20 == 0 {
		return false // an IKEv2 request, not a response
	}
	return bytes.Equal(response[:8], spi) && (major == 1 || major == 2) &&
		int(binary.BigEndian.Uint32(response[24:28])) == len(response)
}

var ikePayloads = map[byte]string{
	0: "None", 1: "Security Association (SA)", 2: "Proposal (P)", 3: "Transform (T)",
	4: "Key Exchange (KE)", 5: "Identification (ID)", 6: "Certificate (CERT)",
	7: "Certificate Request (CR)", 8: "Hash (HASH)", 9: "Signature (SIG)", 10: "Nonce (NONCE)",
	11: "Notification (N)", 12: "Delete (D)", 13: "Vendor ID (VID)", 20: "NAT Discovery (NAT-D)",
	21: "NAT Original Address (NAT-OA)", 130: "NAT Discovery (NAT-D, draft)",
	33: "Security Association (SA)", 34: "Key Exchange (KE)", 35: "Identification - Initiator (IDi)",
	36: "Identification - Responder (IDr)", 37: "Certificate (CERT)", 38: "Certificate Request (CERTREQ)",
	39: "Authentication (AUTH)", 40: "Nonce (Ni, Nr)", 41: "Notify (N)", 42: "Delete (D)",
	43: "Vendor ID (V)", 44: "Traffic Selector - Initiator (TSi)", 45: "Traffic Selector - Responder (TSr)",
	46: "Encrypted and Authenticated (SK)", 47: "Configuration (CP)", 48: "Extensible Authentication (EAP)",
}

var ikeExchanges = map[byte]string{
	1: "Base", 2: "Identity Protection (Main Mode)", 4: "Aggressive", 5: "Informational",
	32: "Quick Mode", 33: "New Group Mode",
	34: "IKE_SA_INIT", 35: "IKE_AUTH", 36: "CREATE_CHILD_SA", 37: "INFORMATIONAL",
}

// RFC 2408 3.14.1 notify message types.
var ikeNotifies = map[uint16]string{
	1: "INVALID-PAYLOAD-TYPE", 4: "INVALID-COOKIE", 5: "INVALID-MAJOR-VERSION", 7: "INVALID-EXCHANGE-TYPE",
	8: "INVALID-FLAGS", 9: "INVALID-MESSAGE-ID", 12: "INVALID-TRANSFORM-ID", 13: "ATTRIBUTES-NOT-SUPPORTED",
	14: "NO-PROPOSAL-CHOSEN", 15: "BAD-PROPOSAL-SYNTAX", 16: "PAYLOAD-MALFORMED", 17: "INVALID-KEY-INFORMATION",
	24: "AUTHENTICATION-FAILED", 29: "UNSUPPORTED-EXCHANGE-TYPE", 30: "UNEQUAL-PAYLOAD-LENGTHS",
}

// RFC 7296 3.10.1 and extension notify types. Types from 16384 are status
// notifications rather than errors.
var ikev2Notifies = map[uint16]string{
	1: "UNSUPPORTED_CRITICAL_PAYLOAD", 4: "INVALID_IKE_SPI", 5: "INVALID_MAJOR_VERSION", 7: "INVALID_SYNTAX",
	9: "INVALID_MESSAGE_ID", 11: "INVALID_SPI", 14: "NO_PROPOSAL_CHOSEN", 17: "INVALID_KE_PAYLOAD",
	24: "AUTHENTICATION_FAILED", 34: "SINGLE_PAIR_REQUIRED", 35: "NO_ADDITIONAL_SAS", 36: "INTERNAL_ADDRESS_FAILURE",
	37: "FAILED_CP_REQUIRED", 38: "TS_UNACCEPTABLE", 39: "INVALID_SELECTORS", 43: "TEMPORARY_FAILURE",
	16384: "INITIAL_CONTACT", 16388: "NAT_DETECTION_SOURCE_IP", 16389: "NAT_DETECTION_DESTINATION_IP",
	16390: "COOKIE", 16396: "MOBIKE_SUPPORTED", 16397: "ADDITIONAL_IP4_ADDRESS", 16398: "ADDITIONAL_IP6_ADDRESS",
	16403: "AUTH_LIFETIME", 16404: "MULTIPLE_AUTH_SUPPORTED", 16406: "REDIRECT_SUPPORTED", 16417: "EAP_ONLY_AUTHENTICATION",
	16418: "CHILDLESS_IKEV2_SUPPORTED",
	16430: "IKEV2_FRAGMENTATION_SUPPORTED", 16431: "SIGNATURE_HASH_ALGORITHMS",
}

// Transform names for an IKEv1 SA attribute (RFC 2409 appendix A) and an
// IKEv2 transform (RFC 7296 3.3.2), keyed by attribute or transform type.
var (
	ikeGroups = map[uint16]string{1: "MODP-768", 2: "MODP-1024", 5: "MODP-1536", 14: "MODP-2048",
		15: "MODP-3072", 16: "MODP-4096", 17: "MODP-6144", 18: "MODP-8192", 19: "ECP-256", 20: "ECP-384",
		21: "ECP-521", 31: "Curve25519", 32: "Curve448"}
	ikev1Attrs = map[uint16]map[uint16]string{
		1: {1: "DES", 2: "IDEA", 3: "Blowfish", 4: "RC5", 5: "3DES", 6: "CAST", 7: "AES"},
		2: {1: "MD5", 2: "SHA1", 3: "Tiger", 4: "SHA2-256", 5: "SHA2-384", 6: "SHA2-512"},
		3: {1: "PSK", 2: "DSS", 3: "RSA-Sig", 4: "RSA-Enc", 5: "RSA-RevEnc", 64221: "Hybrid-RSA",
			65001: "XAUTH-PSK", 65005: "XAUTH-RSA"},
		4: ikeGroups,
	}
	ikev2Ids = map[uint16]map[uint16]string{
		1: {3: "3DES", 12: "AES-CBC", 13: "AES-CTR", 18: "AES-CCM-16", 20: "AES-GCM-16", 23: "CAMELLIA-CBC", 28: "CHACHA20-POLY1305"},
		2: {1: "HMAC-MD5", 2: "HMAC-SHA1", 4: "AES128-XCBC", 5: "HMAC-SHA2-256", 6: "HMAC-SHA2-384", 7: "HMAC-SHA2-512"},
		3: {1: "HMAC-MD5-96", 2: "HMAC-SHA1-96", 5: "AES-XCBC-96", 12: "HMAC-SHA2-256-128", 13: "HMAC-SHA2-384-192", 14: "HMAC-SHA2-512-256"},
		4: ikeGroups,
	}
)

// Names for the payloads only later exchanges carry: ID types (RFC 7296 3.5),
// AUTH methods (3.8), certificate encodings (3.6) and EAP types.
var (
	ikeIDTypes     = map[byte]string{1: "IPv4", 2: "FQDN", 3: "RFC822", 5: "IPv6", 9: "DN", 10: "GN", 11: "KEY_ID"}
	ikeAuthMethods = map[byte]string{1: "RSA signature", 2: "shared key", 3: "DSS signature", 9: "ECDSA-256",
		10: "ECDSA-384", 11: "ECDSA-521", 12: "generic secure password", 13: "NULL", 14: "digital signature"}
	ikeCertTypes = map[byte]string{1: "PKCS #7", 4: "X.509", 7: "CRL", 12: "hash and URL of X.509", 13: "hash and URL of X.509 bundle"}
	ikeEAPCodes  = map[byte]string{1: "Request", 2: "Response", 3: "Success", 4: "Failure"}
	ikeEAPTypes  = map[byte]string{1: "Identity", 4: "MD5-Challenge", 6: "GTC", 13: "TLS", 18: "SIM", 21: "TTLS",
		23: "AKA", 25: "PEAP", 26: "MSCHAPv2", 43: "FAST", 50: "AKA'"}
)

type ikeReply struct {
	attrs                   map[string]string
	decoded                 []observe.ByteField
	label, summary          string
	product, productVersion string

	// What a follow-up exchange needs from this reply.
	spis              []byte             // SPIi | SPIr
	v1Hash, v1Group   uint32             // accepted IKEv1 hash and group
	v1NATD            byte               // NAT-D payload type the peer's vendor ID implies, 0 without NAT-T
	picked            map[byte][2]uint16 // accepted IKEv2 transforms
	peerKE, peerNonce []byte
	wantGroup         uint16   // from INVALID_KE_PAYLOAD
	cookie            []byte   // from a COOKIE notify
	natDetection      bool     // IKEv2 NAT detection notifies present
	gatewayHashes     [][]byte // the gateway's own NAT hashes when it is behind NAT
	decrypted         bool
	wire              []byte // the message as received, without non-ESP marker

	// What verifying the responder's AUTH payload needs.
	idBody, authData []byte
	authMethod       byte
	cert             *x509.Certificate
}

// ikeMessageAttrs describe one message rather than the gateway.
var ikeMessageAttrs = []string{"banner", "ike.nat_t", "ike.initiator_spi", "ike.responder_spi", "ike.next_payload",
	"ike.version", "ike.exchange_type", "ike.message_id", "ike.length"}

// follow merges a later exchange of the same negotiation into r. Its notifies
// become ike.<stage>.notify and its vendor IDs extend the list.
func (r *ikeReply) follow(more ikeReply, stage string) {
	for k, v := range more.attrs {
		switch {
		case slices.Contains(ikeMessageAttrs, k) || strings.HasPrefix(k, "ike.flags."):
		case k == "ike.notify":
			r.attrs["ike."+stage+".notify"] = v
		case (k == "ike.vendor_ids" || k == "ike.vendors") && r.attrs[k] != "":
			have := strings.Split(r.attrs[k], ",")
			for _, item := range strings.Split(v, ",") {
				if !slices.Contains(have, item) {
					have = append(have, item)
				}
			}
			r.attrs[k] = strings.Join(have, ",")
		default:
			r.attrs[k] = v
		}
	}
	if r.product == "" {
		r.product, r.productVersion = more.product, more.productVersion
	}
	r.summary += "; " + more.summary
}

// decodeIKE breaks a validated ISAKMP/IKEv2 reply (without NAT-T marker)
// into attributes, byte fields, a summary and any vendor product. local and
// remote are the probe socket's addresses, used to check NAT detection.
func decodeIKE(msg []byte, natT bool, local, remote netip.AddrPort) ikeReply {
	major, minor := msg[17]>>4, msg[17]&15
	flags, exchange, next := msg[19], msg[18], msg[16]
	exchangeName := lookupName(ikeExchanges, exchange)
	attrs := map[string]string{
		"ike.nat_t":         strconv.FormatBool(natT),
		"ike.initiator_spi": hex.EncodeToString(msg[:8]),
		"ike.responder_spi": hex.EncodeToString(msg[8:16]),
		"ike.next_payload":  lookupName(ikePayloads, next),
		"ike.version":       fmt.Sprintf("%d.%d", major, minor),
		"ike.exchange_type": exchangeName,
		"ike.message_id":    hex.EncodeToString(msg[20:24]),
		"ike.length":        strconv.Itoa(len(msg)),
	}
	flagBits := []struct {
		bit  byte
		name string
	}{{1, "encryption"}, {2, "commit"}, {4, "authentication"}}
	if major == 2 {
		flagBits = []struct {
			bit  byte
			name string
		}{{0x08, "initiator"}, {0x10, "version"}, {0x20, "response"}}
	}
	var set []string
	for _, f := range flagBits {
		attrs["ike.flags."+f.name] = strconv.FormatBool(flags&f.bit != 0)
		if flags&f.bit != 0 {
			set = append(set, f.name)
		}
	}
	field := func(off, n int, name, value, note string) observe.ByteField {
		return observe.ByteField{Offset: off, Length: n, Bytes: spacedHex(msg[off : off+n]), Field: name, Value: value, Note: note}
	}
	decoded := []observe.ByteField{
		field(0, 8, "initiator SPI", attrs["ike.initiator_spi"], "echo of the probe's random cookie"),
		field(8, 8, "responder SPI", attrs["ike.responder_spi"], "responder cookie"),
		field(16, 1, "next payload", attrs["ike.next_payload"], ""),
		field(17, 1, "version", attrs["ike.version"], "major.minor"),
		field(18, 1, "exchange type", exchangeName, ""),
		field(19, 1, "flags", strings.Join(set, ","), fmt.Sprintf("0x%02x", flags)),
		field(20, 4, "message ID", attrs["ike.message_id"], ""),
		field(24, 4, "length", attrs["ike.length"], "whole ISAKMP message"),
	}

	// Walk the payload chain. Payloads are unencrypted in these first-exchange
	// replies.
	var notifies, errors, vendorHex, vendorNames []string
	var natSources, natDestinations, natD [][]byte
	var additional []string
	var product, productVersion string
	reply := ikeReply{spis: append([]byte(nil), msg[:16]...)}
	for off, seen := 28, 0; next != 0 && off+4 <= len(msg) && seen < 32; seen++ {
		length := int(binary.BigEndian.Uint16(msg[off+2 : off+4]))
		if length < 4 || off+length > len(msg) {
			break
		}
		body := msg[off+4 : off+length]
		value := lookupName(ikePayloads, next)
		switch {
		case next == 1 && len(body) >= 8: // IKEv1 SA: DOI(4) situation(4) proposal
			if chosen, life, hashID, group := ikev1Chosen(body[8:]); chosen != "" {
				attrs["ike.transform"], value = chosen, chosen
				reply.v1Hash, reply.v1Group = hashID, group
				if life != "" {
					attrs["ike.lifetime"] = life
				}
			}
		case next == 33:
			if chosen := ikev2Chosen(body); chosen != "" {
				attrs["ike.transform"], value = chosen, chosen
				reply.picked = ikev2Picked(body)
			}
		case next == 34 && len(body) >= 4:
			attrs["ike.ke_group"] = lookupGroup(binary.BigEndian.Uint16(body[:2]))
			reply.peerKE = body[4:]
		case next == 40:
			reply.peerNonce = body
		case major == 1 && (next == 20 || next == 130):
			natD = append(natD, body)
		case next == 7 && len(body) >= 1: // IKEv1: certificate type, CA distinguished name
			value = lookupName(ikeCertTypes, body[0])
			var dn pkix.RDNSequence
			if _, err := asn1.Unmarshal(body[1:], &dn); err == nil {
				value += " from " + dn.String()
			}
			attrs["ike.certreq"] = value
		case next == 38 && len(body) >= 1: // IKEv2: encoding, SHA-1 of each trusted CA key
			value = fmt.Sprintf("%s, %d CA", lookupName(ikeCertTypes, body[0]), (len(body)-1)/sha1.Size)
			attrs["ike.certreq"] = value
			if len(body) > 1 {
				attrs["ike.certreq.ca_key_hashes"] = hex.EncodeToString(body[1:])
			}
		case (next == 5 || next == 36) && len(body) >= 4:
			value = ikeID(body[0], body[4:])
			attrs["ike.id"], reply.idBody = value, body
		case next == 8: // IKEv1 HASH: in Aggressive Mode, HASH_R of the pre-shared key
			attrs["ike.hash"] = hex.EncodeToString(body)
		case next == 37 && len(body) >= 1:
			value = lookupName(ikeCertTypes, body[0])
			if cert, err := x509.ParseCertificate(body[1:]); body[0] == 4 && err == nil && attrs["ike.cert.subject"] == "" {
				c := summarizeCertificate(cert)
				value, reply.cert = c.Subject, cert
				attrs["ike.cert.subject"], attrs["ike.cert.issuer"], attrs["ike.cert.sha256"] = c.Subject, c.Issuer, c.SHA256
				attrs["ike.cert.not_after"] = c.NotAfter.Format(time.RFC3339)
				if names := append(slices.Clone(c.DNSNames), c.IPAddresses...); len(names) > 0 {
					attrs["ike.cert.names"] = strings.Join(names, ",")
				}
			}
		case next == 39 && len(body) >= 4:
			value = lookupName(ikeAuthMethods, body[0])
			attrs["ike.auth_method"] = value
			reply.authMethod, reply.authData = body[0], body[4:]
		case next == 48 && len(body) >= 4: // code, identifier, length(2), type
			value = lookupName(ikeEAPCodes, body[0])
			if len(body) >= 5 {
				value += " " + lookupName(ikeEAPTypes, body[4])
			}
			attrs["ike.eap"] = value
		case next == 11 && len(body) >= 8: // IKEv1: DOI(4) protocol spi-size type(2)
			name := lookupNotify(ikeNotifies, binary.BigEndian.Uint16(body[6:8]))
			notifies, errors, value = append(notifies, name), append(errors, name), name
		case next == 41 && len(body) >= 4: // IKEv2: protocol spi-size type(2) spi data
			kind := binary.BigEndian.Uint16(body[2:4])
			name := lookupNotify(ikev2Notifies, kind)
			if data := body[min(len(body), 4+int(body[1])):]; kind == 17 && len(data) >= 2 {
				reply.wantGroup = binary.BigEndian.Uint16(data[:2])
				name += " (wants " + lookupGroup(reply.wantGroup) + ")"
			} else if addr, ok := netip.AddrFromSlice(data); ok && (kind == 16397 || kind == 16398) {
				additional = append(additional, addr.String())
			} else if kind == 16390 {
				reply.cookie = data
			}
			notifies, value = append(notifies, name), name
			if data := body[min(len(body), 4+int(body[1])):]; kind == 16388 {
				natSources = append(natSources, data)
			} else if kind == 16389 {
				natDestinations = append(natDestinations, data)
			}
			if kind < 16384 {
				errors = append(errors, name)
			}
		case next == 13 || next == 43:
			v := identifyVendor(body)
			vendorHex, vendorNames, value = append(vendorHex, hex.EncodeToString(body)), append(vendorNames, v.label), v.label
			if product == "" && v.product != "" {
				product, productVersion = v.product, v.version
			}
			if attrs["ike.nat_t_support"] == "" && (v.label == "RFC 3947 NAT-T" || strings.HasPrefix(v.label, "NAT-T draft")) {
				attrs["ike.nat_t_support"] = v.label
			}
			// RFC 3947 moved NAT-D to payload 20; drafts 02 and 03 use 130.
			if v.label == "RFC 3947 NAT-T" {
				reply.v1NATD = 20
			} else if reply.v1NATD == 0 && (strings.HasPrefix(v.label, "NAT-T draft 02") || v.label == "NAT-T draft 03") {
				reply.v1NATD = 130
			}
		}
		decoded = append(decoded, field(off, 4, "payload header", value, fmt.Sprintf("%s, %d bytes", lookupName(ikePayloads, next), length)))
		next = msg[off]
		off += length
	}
	if len(notifies) > 0 {
		attrs["ike.notify"] = strings.Join(notifies, ",")
	}
	if len(additional) > 0 {
		attrs["ike.additional_addresses"] = strings.Join(additional, ",")
	}
	// RFC 7296 2.23: the responder hashes the address it saw us at (its
	// DESTINATION_IP) and its own address(es) (SOURCE_IP), with the reply's
	// SPIs. RFC 3947 3.2 sends the same pair as NAT-D payloads, remote end first.
	reply.natDetection = len(natSources)+len(natDestinations) > 0
	if reply.natDetection {
		attrs["ike.nat_t_support"] = "RFC 7296 NAT detection"
	} else if len(natD) >= 2 {
		natDestinations, natSources = natD[:1], natD[1:]
	}
	var natNotes []string
	if len(natDestinations) > 0 && local.IsValid() {
		attrs["ike.nat.scanner"] = natVerdict(natDestinations, msg[:16], local)
		if attrs["ike.nat.scanner"] == "behind NAT" {
			natNotes = append(natNotes, "scanner behind NAT")
		}
	}
	if len(natSources) > 0 && remote.IsValid() {
		attrs["ike.nat.gateway"] = natVerdict(natSources, msg[:16], remote)
		if attrs["ike.nat.gateway"] == "behind NAT" {
			natNotes = append(natNotes, "gateway behind NAT")
			reply.gatewayHashes = natSources
		}
	}
	if len(vendorHex) > 0 {
		attrs["ike.vendor_ids"] = strings.Join(vendorHex, ",")
		attrs["ike.vendors"] = strings.Join(vendorNames, ",")
	}
	// strongSwan is the one common stack announcing RFC 4739 multiple
	// authentication by default, so it names gateways that send no vendor IDs.
	if product == "" && slices.Contains(notifies, "MULTIPLE_AUTH_SUPPORTED") {
		product = "strongSwan"
		attrs["ike.product.basis"] = "MULTIPLE_AUTH_SUPPORTED notify"
	}
	if product != "" {
		attrs["ike.product"] = strings.TrimSpace(product + " " + productVersion)
	}
	label := "VPN (IKE)"
	if natT {
		label = "VPN (IKE NAT-T)"
	}
	attrs["banner"] = label
	summary := fmt.Sprintf("IKEv%d %s", major, exchangeName)
	if t := attrs["ike.transform"]; t != "" {
		summary += " chose " + t
	}
	if len(errors) > 0 {
		summary += " notify " + strings.Join(errors, ",")
	}
	for _, k := range []string{"ike.id", "ike.eap", "ike.cert.subject"} {
		if attrs[k] != "" {
			summary += fmt.Sprintf(" %s %s", strings.TrimPrefix(k, "ike."), attrs[k])
		}
	}
	if len(natNotes) > 0 {
		summary += " (" + strings.Join(natNotes, ", ") + ")"
	}
	reply.attrs, reply.decoded, reply.label, reply.summary = attrs, decoded, label, summary
	reply.product, reply.productVersion = product, productVersion
	return reply
}

// natVerdict is "direct" when any received hash matches the address we know,
// else "behind NAT": the address was rewritten on the way.
func natVerdict(received [][]byte, spis []byte, known netip.AddrPort) string {
	for _, h := range received {
		if bytes.Equal(h, natHash(len(h), spis, known)) {
			return "direct"
		}
	}
	return "behind NAT"
}

// ikeID renders an Identification payload by its type.
func ikeID(kind byte, data []byte) string {
	value := hex.EncodeToString(data)
	switch kind {
	case 1, 5:
		if addr, ok := netip.AddrFromSlice(data); ok {
			value = addr.String()
		}
	case 2, 3:
		value = strconv.QuoteToASCII(string(data))
		value = value[1 : len(value)-1]
	case 9:
		var dn pkix.RDNSequence
		if _, err := asn1.Unmarshal(data, &dn); err == nil {
			value = dn.String()
		}
	}
	return lookupName(ikeIDTypes, kind) + " " + value
}

// ikev1Chosen names the first transform of an IKEv1 proposal payload, which
// in a responder's SA is the one it accepted.
func ikev1Chosen(p []byte) (name, life string, hashID, groupID uint32) {
	if len(p) < 8 || len(p) < 8+int(p[6]) {
		return
	}
	t := p[8+int(p[6]):] // proposal header(8) + SPI
	if len(t) < 8 {
		return
	}
	tLen := int(binary.BigEndian.Uint16(t[2:4]))
	if tLen < 8 || tLen > len(t) {
		return
	}
	var enc, keyLen, hash, auth, group string
	for a := t[8:tLen]; len(a) >= 4; {
		kind, value, n := ikeAttr(a)
		names := ikev1Attrs[kind]
		switch kind {
		case 1:
			enc = lookupID(names, value)
		case 2:
			hash, hashID = lookupID(names, value), value
		case 3:
			auth = lookupID(names, value)
		case 4:
			group, groupID = lookupGroup(value), value
		case 12:
			life = strconv.Itoa(int(value)) + "s"
		case 14:
			keyLen = "-" + strconv.Itoa(int(value))
		}
		a = a[n:]
	}
	if enc == "" {
		return "", "", 0, 0
	}
	return strings.Join([]string{enc + keyLen, hash, auth, group}, "/"), life, hashID, groupID
}

// ikeAttr reads one data attribute: TV when the high bit is set, else TLV
// with a big-endian value of up to four bytes.
func ikeAttr(a []byte) (kind uint16, value uint32, n int) {
	kind, word := binary.BigEndian.Uint16(a[:2])&0x7fff, binary.BigEndian.Uint16(a[2:4])
	if a[0]&0x80 != 0 {
		return kind, uint32(word), 4
	}
	n = min(len(a), 4+int(word))
	for _, b := range a[4:n] {
		value = value<<8 | uint32(b)
	}
	return kind, value, n
}

// ikev2Picked returns {ID, key bits} of the first transform of each type in
// the first proposal of an IKEv2 SA.
func ikev2Picked(sa []byte) map[byte][2]uint16 {
	picked := map[byte][2]uint16{}
	if len(sa) < 8 {
		return picked
	}
	pLen := min(len(sa), int(binary.BigEndian.Uint16(sa[2:4])))
	t := sa[min(pLen, 8+int(sa[6])):pLen]
	for len(t) >= 8 {
		tLen := int(binary.BigEndian.Uint16(t[2:4]))
		if tLen < 8 || tLen > len(t) {
			break
		}
		tr := [2]uint16{binary.BigEndian.Uint16(t[6:8])}
		for a := t[8:tLen]; len(a) >= 4; {
			kind, value, n := ikeAttr(a)
			if kind == 14 {
				tr[1] = uint16(value)
			}
			a = a[n:]
		}
		if _, dup := picked[t[4]]; !dup {
			picked[t[4]] = tr
		}
		t = t[tLen:]
	}
	return picked
}

// ikev2Chosen names the transforms of the first proposal in an IKEv2 SA.
func ikev2Chosen(sa []byte) string {
	picked := ikev2Picked(sa)
	var parts []string
	for kind := byte(1); kind <= 4; kind++ {
		tr, ok := picked[kind]
		if !ok {
			continue
		}
		name := lookupID(ikev2Ids[uint16(kind)], uint32(tr[0]))
		if kind == 4 {
			name = lookupGroup(tr[0])
		}
		if tr[1] != 0 {
			name += "-" + strconv.Itoa(int(tr[1]))
		}
		parts = append(parts, name)
	}
	return strings.Join(parts, "/")
}

func lookupName(names map[byte]string, v byte) string {
	if name, ok := names[v]; ok {
		return name
	}
	return "type " + strconv.Itoa(int(v))
}

func lookupID(names map[uint16]string, v uint32) string {
	if name, ok := names[uint16(v)]; ok && v <= 0xffff {
		return name
	}
	return strconv.Itoa(int(v))
}

func lookupGroup[T uint16 | uint32](v T) string { return lookupID(ikeGroups, uint32(v)) }

func lookupNotify(names map[uint16]string, v uint16) string {
	if name, ok := names[v]; ok {
		return name
	}
	return "type " + strconv.Itoa(int(v))
}

func spacedHex(b []byte) string {
	parts := make([]string, len(b))
	for i, c := range b {
		parts[i] = fmt.Sprintf("%02x", c)
	}
	return strings.Join(parts, " ")
}
