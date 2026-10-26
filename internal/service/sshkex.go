package service

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"slices"
	"strings"

	"github.com/matusso/nyxr/internal/observe"
)

// Bounds for parsing a KEXINIT from retained bytes. RFC 4253 §6.1 caps a
// packet at 35000 bytes; real name-lists are far shorter.
const (
	maxSSHPacket   = 35000
	maxSSHNameList = 4096
	maxSSHNames    = 64
)

// kexInit holds the ten name-lists of an SSH_MSG_KEXINIT in wire order:
// kex, host key, ciphers c→s and s→c, MACs c→s and s→c, compression c→s and
// s→c, languages c→s and s→c.
type kexInit [10][]string

// parseKexInit reads the first KEXINIT after the identification line(s) of
// one direction of an SSH exchange. complete is false when the retained bytes
// end inside the packet.
func parseKexInit(stream []byte) (k kexInit, ok, complete bool) {
	rest := stream
	for {
		line, after, found := bytes.Cut(rest, []byte("\n"))
		if !found {
			return k, false, false
		}
		rest = after
		if bytes.HasPrefix(line, []byte("SSH-")) {
			break
		}
	}
	if len(rest) < 6 {
		return k, false, false
	}
	length := int(binary.BigEndian.Uint32(rest))
	padding := int(rest[4])
	if length < 2 || length > maxSSHPacket || padding >= length {
		return k, false, true
	}
	if len(rest) < 4+length {
		return k, false, false
	}
	payload := rest[5 : 4+length-padding]
	if len(payload) < 17 || payload[0] != 20 { // SSH_MSG_KEXINIT and its cookie
		return k, false, true
	}
	p := payload[17:]
	for i := range k {
		if len(p) < 4 {
			return k, false, true
		}
		n := int(binary.BigEndian.Uint32(p))
		if n > maxSSHNameList || n > len(p)-4 {
			return k, false, true
		}
		if n > 0 {
			names := strings.Split(string(p[4:4+n]), ",")
			if len(names) > maxSSHNames {
				names = names[:maxSSHNames]
			}
			k[i] = names
		}
		p = p[4+n:]
	}
	return k, len(p) >= 5, true // first_kex_packet_follows and reserved
}

// sshPseudoAlgorithm reports names that signal extensions rather than
// algorithms; RFC 8308 and the OpenSSH strict-KEX marker are never selected.
func sshPseudoAlgorithm(name string) bool {
	return strings.HasPrefix(name, "ext-info-") || strings.HasPrefix(name, "kex-strict-")
}

// negotiateSSH applies RFC 4253 §7.1: the first client algorithm the server
// also offers. It simplifies the kex rule by not checking host-key
// compatibility, which is why the result is labeled inferred.
func negotiateSSH(client, server kexInit) *observe.SSHNegotiated {
	pick := func(i int) string {
		for _, c := range client[i] {
			if !sshPseudoAlgorithm(c) && slices.Contains(server[i], c) {
				return c
			}
		}
		return ""
	}
	return &observe.SSHNegotiated{ClaimStatus: "inferred", KEX: pick(0), HostKey: pick(1), Cipher: pick(3), MAC: pick(5), Compression: pick(7)}
}

// sshFingerprint normalizes the server's offer: kex, host-key, and the
// server-to-client cipher, MAC and compression lists, each in wire order.
func sshFingerprint(k kexInit) (normalized, value string) {
	parts := []string{strings.Join(k[0], ","), strings.Join(k[1], ","), strings.Join(k[3], ","), strings.Join(k[5], ","), strings.Join(k[7], ",")}
	normalized = strings.Join(parts, ";")
	sum := sha256.Sum256([]byte(observe.FingerprintSSHServer + "|" + normalized))
	return normalized, hex.EncodeToString(sum[:])
}

// recordSSHNegotiation fills o.SSH and an application fingerprint from the
// exchange retained in evidence index idx. It does nothing when the server
// sent no parsable KEXINIT.
func recordSSHNegotiation(o *observe.Observation, idx int, negotiationErr string) {
	ev := o.Evidence[idx]
	server, ok, _ := parseKexInit(ev.Response)
	if !ok {
		return
	}
	info := &observe.SSH{
		KEX: server[0], HostKey: server[1], CiphersClientServer: server[2], CiphersServerClient: server[3],
		MACsClientServer: server[4], MACsServerClient: server[5], CompressionServer: server[7],
		NegotiationError: negotiationErr, Evidence: idx, Truncated: ev.Truncated,
	}
	if client, ok, _ := parseKexInit(ev.Request); ok {
		info.Negotiated = negotiateSSH(client, server)
	}
	o.SSH = info
	normalized, value := sshFingerprint(server)
	status := "observed"
	if info.Truncated {
		status = "partial"
	}
	o.AppFingerprints = append(o.AppFingerprints, observe.AppFingerprint{
		Method: observe.FingerprintSSHServer, Value: value, Normalized: normalized, Evidence: idx, Status: status,
	})
}
