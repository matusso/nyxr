package service

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha1" //nolint:gosec // RFC 7296 2.23 defines NAT detection as SHA-1
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"net/netip"
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

// ikeMainMode builds an IKEv1 Main Mode SA request (RFC 2409) for spi,
// announcing NAT traversal support (RFC 3947).
func ikeMainMode(spi []byte) []byte {
	var transforms []byte
	for i, attrs := range ikeTransforms {
		var a []byte
		for _, kv := range attrs {
			a = binary.BigEndian.AppendUint16(a, 0x8000|kv[0])
			a = binary.BigEndian.AppendUint16(a, kv[1])
		}
		// Life type seconds, life duration 28800 as a 4-byte variable attribute.
		a = append(a, 0x80, 11, 0, 1, 0, 12, 0, 4, 0, 0, 0x70, 0x80)
		next := byte(3)
		if i == len(ikeTransforms)-1 {
			next = 0
		}
		transforms = append(transforms, next, 0, 0, 0, byte(i+1), 1, 0, 0)
		binary.BigEndian.PutUint16(transforms[len(transforms)-6:], uint16(8+len(a)))
		transforms = append(transforms, a...)
	}
	proposal := append([]byte{0, 0, 0, 0, 1, 1, 0, byte(len(ikeTransforms))}, transforms...)
	binary.BigEndian.PutUint16(proposal[2:4], uint16(len(proposal)))
	sa := append([]byte{13, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1}, proposal...)
	binary.BigEndian.PutUint16(sa[2:4], uint16(len(sa)))
	for i, vid := range natTVendorIDs {
		next := byte(13)
		if i == len(natTVendorIDs)-1 {
			next = 0
		}
		sa = append(sa, ikePayload(next, vid)...)
	}
	return ikeMessage(spi, 1, 0x10, 2, 0, sa)
}

// ikev2Transforms is one non-AEAD IKE proposal (RFC 7296 3.3): AES-CBC and
// 3DES, SHA1/SHA2 PRFs and integrity, and common MODP and ECP groups.
var ikev2Transforms = [][3]uint16{
	{1, 12, 128}, {1, 12, 256}, {1, 3, 0},
	{2, 5, 0}, {2, 6, 0}, {2, 7, 0}, {2, 2, 0},
	{3, 12, 0}, {3, 13, 0}, {3, 14, 0}, {3, 2, 0},
	{4, 14, 0}, {4, 19, 0}, {4, 20, 0}, {4, 31, 0}, {4, 2, 0}, {4, 15, 0},
}

// ikev2KEGroup is the group of the KE payload. A responder preferring another
// offered group answers INVALID_KE_PAYLOAD naming it, which still identifies
// the gateway.
const ikev2KEGroup = 14

// ikeSAInit builds an IKEv2 IKE_SA_INIT request with a MODP-2048 public value
// ke (256 bytes), nonce, and the NAT detection notifies of RFC 7296 2.23 for
// the socket's source and destination. The probe never completes the exchange.
func ikeSAInit(spi, ke, nonce []byte, source, destination netip.AddrPort) []byte {
	var transforms []byte
	for i, tr := range ikev2Transforms {
		last := byte(3)
		if i == len(ikev2Transforms)-1 {
			last = 0
		}
		t := []byte{last, 0, 0, 8, byte(tr[0]), 0, byte(tr[1] >> 8), byte(tr[1])}
		if tr[2] != 0 {
			t = append(t, 0x80, 14, byte(tr[2]>>8), byte(tr[2]))
			t[3] = 12
		}
		transforms = append(transforms, t...)
	}
	proposal := append([]byte{0, 0, 0, 0, 1, 1, 0, byte(len(ikev2Transforms))}, transforms...)
	binary.BigEndian.PutUint16(proposal[2:4], uint16(len(proposal)))
	sa := append([]byte{34, 0, 0, 0}, proposal...)
	binary.BigEndian.PutUint16(sa[2:4], uint16(len(sa)))
	kePayload := append([]byte{40, 0, 0, 0, 0, ikev2KEGroup, 0, 0}, ke...)
	binary.BigEndian.PutUint16(kePayload[2:4], uint16(len(kePayload)))
	body := append(append(sa, kePayload...), ikePayload(41, nonce)...)
	// The request's SPIr is zero; the notifies follow the nonce.
	spis := append(append([]byte(nil), spi...), make([]byte, 8)...)
	body = append(body, ikePayload(41, ikeNotify(16388, natDetection(spis, source)))...)
	body = append(body, ikePayload(0, ikeNotify(16389, natDetection(spis, destination)))...)
	return ikeMessage(spi, 33, 0x20, 34, 0x08, body)
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

// natDetection is SHA-1(SPIi | SPIr | IP | port) of RFC 7296 2.23. An
// unknown address yields zeros, which a responder reads as "NAT present".
func natDetection(spis []byte, ap netip.AddrPort) []byte {
	if !ap.IsValid() {
		return make([]byte, sha1.Size)
	}
	h := sha1.New() //nolint:gosec
	h.Write(spis)
	h.Write(ap.Addr().Unmap().AsSlice())
	h.Write([]byte{byte(ap.Port() >> 8), byte(ap.Port())})
	return h.Sum(nil)
}

func ikeMessage(spi []byte, next, version, exchange, flags byte, body []byte) []byte {
	msg := append(append([]byte(nil), spi...), make([]byte, 8)...)
	msg = append(msg, next, version, exchange, flags, 0, 0, 0, 0, 0, 0, 0, 0)
	binary.BigEndian.PutUint32(msg[24:28], uint32(28+len(body)))
	return append(msg, body...)
}

// probeIKE tries IKEv1 Main Mode, then IKEv2 IKE_SA_INIT, framed for NAT-T
// first on 4500 and plain first elsewhere. When IKEv1 answers, IKEv2 is tried
// on the same framing too so the observation states both versions.
func (e *Engine) probeIKE(ctx context.Context, t Target, o *observe.Observation) bool {
	framings := []bool{false, true}
	if t.Port == 4500 {
		framings = []bool{true, false}
	}
	addr := &net.UDPAddr{IP: net.IP(t.Addr.AsSlice()), Port: int(t.Port), Zone: t.Addr.Zone()}
	per := e.timeout(ProbeIKE) / 5 // up to four attempts plus the IKEv2 follow-up
	attempt := func(natT bool, version int) (ikeReply, bool) {
		started := time.Now()
		ev := observe.Evidence{Probe: ProbeIKE, Layer: "udp", Started: started.UTC()}
		response, request, local, err := e.ikeExchange(ctx, addr, natT, version, per)
		ev.Request, ev.Response, ev.Duration = request, response, time.Since(started)
		if err != nil {
			ev.Error = err.Error()
			o.Evidence = append(o.Evidence, ev)
			return ikeReply{}, false
		}
		if natT {
			response = response[len(nonESPMarker):]
		}
		reply := decodeIKE(response, natT, local, addr.AddrPort())
		ev.Matched, ev.Decoded = ProbeIKE, reply.decoded
		o.Evidence = append(o.Evidence, ev)
		o.RTT = ev.Duration
		return reply, true
	}
	for _, natT := range framings {
		for _, version := range []int{1, 2} {
			if ctx.Err() != nil {
				return false
			}
			reply, ok := attempt(natT, version)
			if !ok {
				continue
			}
			versions, summary := strconv.Itoa(version), reply.summary
			product, productVersion := reply.product, reply.productVersion
			if version == 1 && ctx.Err() == nil {
				if v2, ok := attempt(natT, 2); ok {
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

// ikeExchange sends one request and returns the validated reply, the request
// and the socket's local address (for NAT detection).
func (e *Engine) ikeExchange(ctx context.Context, addr *net.UDPAddr, natT bool, version int, timeout time.Duration) (response, request []byte, local netip.AddrPort, err error) {
	if err := e.pacer.wait(ctx); err != nil {
		return nil, nil, local, err
	}
	random := make([]byte, 8+256+32) // SPI, IKEv2 KE value, IKEv2 nonce
	if _, err := rand.Read(random); err != nil {
		return nil, nil, local, err
	}
	// RFC 3947 and 7296 make responders answer any source port, so this works
	// through NAT; some gateways still only answer peers on the IKE ports,
	// which root can bind.
	source := uint16(500)
	if natT {
		source = 4500
	}
	conn, _, err := probe.DialUDP(ctx, addr, source)
	if err != nil {
		return nil, nil, local, err
	}
	defer conn.Close()
	local = conn.LocalAddr().(*net.UDPAddr).AddrPort()
	spi := random[:8]
	if version == 2 {
		ke := random[8:264]
		ke[0] = ke[0]&0x3f | 0x40 // a MODP-2048 public value must stay below p
		request = ikeSAInit(spi, ke, random[264:], local, addr.AddrPort())
	} else {
		request = ikeMainMode(spi)
	}
	if natT {
		request = append(append([]byte(nil), nonESPMarker...), request...)
	}
	deadline := time.Now().Add(timeout)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	stop := context.AfterFunc(ctx, func() { _ = conn.SetDeadline(time.Now()) })
	defer stop()
	if err := conn.SetDeadline(deadline); err != nil {
		return nil, request, local, err
	}
	if _, err := conn.Write(request); err != nil {
		return nil, request, local, err
	}
	buf := make([]byte, 65507)
	for {
		n, err := conn.Read(buf)
		if err != nil {
			return nil, request, local, err
		}
		if validIKEReply(spi, buf[:n], natT) && !bytes.Equal(buf[:n], request) {
			return append([]byte(nil), buf[:n]...), request, local, nil
		}
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
	21: "NAT Original Address (NAT-OA)",
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
	24: "AUTHENTICATION_FAILED", 43: "TEMPORARY_FAILURE",
	16384: "INITIAL_CONTACT", 16388: "NAT_DETECTION_SOURCE_IP", 16389: "NAT_DETECTION_DESTINATION_IP",
	16390: "COOKIE", 16396: "MOBIKE_SUPPORTED", 16404: "MULTIPLE_AUTH_SUPPORTED", 16406: "REDIRECT_SUPPORTED",
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

type ikeReply struct {
	attrs                   map[string]string
	decoded                 []observe.ByteField
	label, summary          string
	product, productVersion string
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
	var natSources, natDestinations [][]byte
	var product, productVersion string
	for off, seen := 28, 0; next != 0 && off+4 <= len(msg) && seen < 32; seen++ {
		length := int(binary.BigEndian.Uint16(msg[off+2 : off+4]))
		if length < 4 || off+length > len(msg) {
			break
		}
		body := msg[off+4 : off+length]
		value := lookupName(ikePayloads, next)
		switch {
		case next == 1 && len(body) >= 8: // IKEv1 SA: DOI(4) situation(4) proposal
			if chosen, life := ikev1Chosen(body[8:]); chosen != "" {
				attrs["ike.transform"], value = chosen, chosen
				if life != "" {
					attrs["ike.lifetime"] = life
				}
			}
		case next == 33:
			if chosen := ikev2Chosen(body); chosen != "" {
				attrs["ike.transform"], value = chosen, chosen
			}
		case next == 34 && len(body) >= 2:
			attrs["ike.ke_group"] = lookupGroup(binary.BigEndian.Uint16(body[:2]))
		case next == 11 && len(body) >= 8: // IKEv1: DOI(4) protocol spi-size type(2)
			name := lookupNotify(ikeNotifies, binary.BigEndian.Uint16(body[6:8]))
			notifies, errors, value = append(notifies, name), append(errors, name), name
		case next == 41 && len(body) >= 4: // IKEv2: protocol spi-size type(2) spi data
			kind := binary.BigEndian.Uint16(body[2:4])
			name := lookupNotify(ikev2Notifies, kind)
			if data := body[min(len(body), 4+int(body[1])):]; kind == 17 && len(data) >= 2 {
				name += " (wants " + lookupGroup(binary.BigEndian.Uint16(data[:2])) + ")"
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
		}
		decoded = append(decoded, field(off, 4, "payload header", value, fmt.Sprintf("%s, %d bytes", lookupName(ikePayloads, next), length)))
		next = msg[off]
		off += length
	}
	if len(notifies) > 0 {
		attrs["ike.notify"] = strings.Join(notifies, ",")
	}
	// RFC 7296 2.23: the responder hashes the address it saw us at (its
	// DESTINATION_IP) and its own address(es) (SOURCE_IP), with the reply's SPIs.
	var natNotes []string
	if len(natDestinations) > 0 && local.IsValid() {
		attrs["ike.nat_t_support"] = "RFC 7296 NAT detection"
		attrs["ike.nat.scanner"] = natVerdict(natDestinations, natDetection(msg[:16], local))
		if attrs["ike.nat.scanner"] == "behind NAT" {
			natNotes = append(natNotes, "scanner behind NAT")
		}
	}
	if len(natSources) > 0 && remote.IsValid() {
		attrs["ike.nat_t_support"] = "RFC 7296 NAT detection"
		attrs["ike.nat.gateway"] = natVerdict(natSources, natDetection(msg[:16], remote))
		if attrs["ike.nat.gateway"] == "behind NAT" {
			natNotes = append(natNotes, "gateway behind NAT")
		}
	}
	if len(vendorHex) > 0 {
		attrs["ike.vendor_ids"] = strings.Join(vendorHex, ",")
		attrs["ike.vendors"] = strings.Join(vendorNames, ",")
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
	if len(natNotes) > 0 {
		summary += " (" + strings.Join(natNotes, ", ") + ")"
	}
	return ikeReply{attrs: attrs, decoded: decoded, label: label, summary: summary, product: product, productVersion: productVersion}
}

// natVerdict is "direct" when any received hash matches the address we know,
// else "behind NAT": the address was rewritten on the way.
func natVerdict(received [][]byte, expected []byte) string {
	for _, h := range received {
		if bytes.Equal(h, expected) {
			return "direct"
		}
	}
	return "behind NAT"
}

// ikev1Chosen names the first transform of an IKEv1 proposal payload, which
// in a responder's SA is the one it accepted.
func ikev1Chosen(p []byte) (string, string) {
	if len(p) < 8 {
		return "", ""
	}
	t := p[8+int(p[6]):] // proposal header(8) + SPI
	if len(t) < 8 {
		return "", ""
	}
	tLen := int(binary.BigEndian.Uint16(t[2:4]))
	if tLen < 8 || tLen > len(t) {
		return "", ""
	}
	var enc, keyLen, hash, auth, group, life string
	for a := t[8:tLen]; len(a) >= 4; {
		kind, value, n := ikeAttr(a)
		names := ikev1Attrs[kind]
		switch kind {
		case 1:
			enc = lookupID(names, value)
		case 2:
			hash = lookupID(names, value)
		case 3:
			auth = lookupID(names, value)
		case 4:
			group = lookupGroup(value)
		case 12:
			life = strconv.Itoa(int(value)) + "s"
		case 14:
			keyLen = "-" + strconv.Itoa(int(value))
		}
		a = a[n:]
	}
	if enc == "" {
		return "", ""
	}
	return strings.Join([]string{enc + keyLen, hash, auth, group}, "/"), life
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

// ikev2Chosen names the transforms of the first proposal in an IKEv2 SA.
func ikev2Chosen(sa []byte) string {
	if len(sa) < 8 {
		return ""
	}
	pLen := min(len(sa), int(binary.BigEndian.Uint16(sa[2:4])))
	t := sa[min(pLen, 8+int(sa[6])):pLen]
	byType := map[byte]string{}
	for len(t) >= 8 {
		tLen := int(binary.BigEndian.Uint16(t[2:4]))
		if tLen < 8 || tLen > len(t) {
			break
		}
		name := lookupID(ikev2Ids[uint16(t[4])], uint32(binary.BigEndian.Uint16(t[6:8])))
		if t[4] == 4 {
			name = lookupGroup(uint32(binary.BigEndian.Uint16(t[6:8])))
		}
		for a := t[8:tLen]; len(a) >= 4; {
			kind, value, n := ikeAttr(a)
			if kind == 14 {
				name += "-" + strconv.Itoa(int(value))
			}
			a = a[n:]
		}
		if t[4] >= 1 && t[4] <= 4 && byType[t[4]] == "" {
			byType[t[4]] = name
		}
		t = t[tLen:]
	}
	var parts []string
	for kind := byte(1); kind <= 4; kind++ {
		if byType[kind] != "" {
			parts = append(parts, byType[kind])
		}
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
