package service

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"io"
	"net"
	"strings"
	"testing"

	"github.com/matusso/nyxr/internal/observe"
	"golang.org/x/crypto/ssh"
)

// kexInitPacket encodes an unencrypted SSH_MSG_KEXINIT binary packet.
func kexInitPacket(lists [10]string) []byte {
	payload := append([]byte{20}, make([]byte, 16)...)
	for _, l := range lists {
		payload = binary.BigEndian.AppendUint32(payload, uint32(len(l)))
		payload = append(payload, l...)
	}
	payload = append(payload, 0, 0, 0, 0, 0)
	padding := 8 - (len(payload)+5)%8
	if padding < 4 {
		padding += 8
	}
	packet := binary.BigEndian.AppendUint32(nil, uint32(1+len(payload)+padding))
	packet = append(packet, byte(padding))
	packet = append(packet, payload...)
	return append(packet, make([]byte, padding)...)
}

func TestParseKexInitAndNegotiate(t *testing.T) {
	server := "SSH-2.0-test\r\n" + string(kexInitPacket([10]string{
		"curve25519-sha256,kex-strict-s-v00@openssh.com", "ssh-ed25519,rsa-sha2-512",
		"aes128-ctr", "chacha20-poly1305@openssh.com,aes128-ctr", "hmac-sha2-256", "hmac-sha2-512,hmac-sha2-256", "none", "none,zlib@openssh.com",
	}))
	client := "SSH-2.0-Go\r\n" + string(kexInitPacket([10]string{
		"kex-strict-c-v00@openssh.com,ext-info-c,curve25519-sha256", "rsa-sha2-512,ssh-ed25519",
		"aes128-ctr", "aes128-ctr,chacha20-poly1305@openssh.com", "hmac-sha2-256", "hmac-sha2-256", "none", "none",
	}))
	s, ok, complete := parseKexInit([]byte(server))
	c, cok, _ := parseKexInit([]byte(client))
	if !ok || !complete || !cok || len(s[0]) != 2 || s[3][0] != "chacha20-poly1305@openssh.com" || len(s[8]) != 0 {
		t.Fatalf("server KEXINIT = %v %v %v", s, ok, complete)
	}
	n := negotiateSSH(c, s)
	if n.ClaimStatus != "inferred" || n.KEX != "curve25519-sha256" || n.HostKey != "rsa-sha2-512" || n.Cipher != "aes128-ctr" ||
		n.MAC != "hmac-sha2-256" || n.Compression != "none" {
		t.Fatalf("negotiation must follow the client's order and skip pseudo-algorithms: %+v", n)
	}
	normalized, value := sshFingerprint(s)
	if normalized != "curve25519-sha256,kex-strict-s-v00@openssh.com;ssh-ed25519,rsa-sha2-512;chacha20-poly1305@openssh.com,aes128-ctr;hmac-sha2-512,hmac-sha2-256;none,zlib@openssh.com" || len(value) != 64 {
		t.Fatalf("fingerprint %q %q", normalized, value)
	}
	// Banner lines before the identification string are skipped.
	if _, ok, _ := parseKexInit([]byte("Welcome\r\n" + server)); !ok {
		t.Fatal("pre-identification lines must be skipped")
	}
	for name, data := range map[string]string{
		"truncated":       server[:len(server)-20],
		"no packet":       "SSH-2.0-test\r\n",
		"no banner":       server[14:],
		"not KEXINIT":     "SSH-2.0-test\r\n\x00\x00\x00\x0c\x0a\x05" + strings.Repeat("\x00", 11),
		"oversized":       "SSH-2.0-test\r\n\x7f\xff\xff\xff\x04" + strings.Repeat("\x00", 40),
		"name-list bound": "SSH-2.0-test\r\n" + string(kexInitPacket([10]string{strings.Repeat("a", maxSSHNameList+1)})),
	} {
		if k, ok, _ := parseKexInit([]byte(data)); ok {
			t.Errorf("%s parsed as %v", name, k)
		}
	}
	many := strings.TrimSuffix(strings.Repeat("x,", 200), ",")
	if k, ok, _ := parseKexInit([]byte("SSH-2.0-t\n" + string(kexInitPacket([10]string{many})))); !ok || len(k[0]) != maxSSHNames {
		t.Fatalf("name count must be bounded: %d", len(k[0]))
	}
}

func TestSSHNegotiationRecordedFromVerifiedExchange(t *testing.T) {
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(key)
	if err != nil {
		t.Fatal(err)
	}
	target := serve(t, func(conn net.Conn) {
		config := &ssh.ServerConfig{NoClientAuth: true}
		config.AddHostKey(signer)
		_, _, _, _ = ssh.NewServerConn(conn, config)
	})
	o := testEngine(t).Interrogate(context.Background(), target)
	if o.Service != "ssh" || o.Attributes["ssh.host_key_type"] != ssh.KeyAlgoED25519 || o.SSH == nil {
		t.Fatalf("SSH identity: %+v", o)
	}
	if o.SSH.Evidence != 1 || o.Evidence[1].Probe != probeSSHHostKey || len(o.SSH.KEX) == 0 || o.SSH.NegotiationError != "" ||
		o.SSH.Negotiated == nil || o.SSH.Negotiated.KEX == "" || o.SSH.Negotiated.HostKey != ssh.KeyAlgoED25519 || o.SSH.Negotiated.ClaimStatus != "inferred" {
		t.Fatalf("SSH negotiation metadata: %+v %+v", o.SSH, o.SSH.Negotiated)
	}
	if len(o.AppFingerprints) != 1 || o.AppFingerprints[0].Method != observe.FingerprintSSHServer || o.AppFingerprints[0].Evidence != 1 ||
		o.AppFingerprints[0].Status != "observed" || o.AppFingerprints[0].Value == o.Attributes["ssh.host_key_sha256"] {
		t.Fatalf("SSH fingerprint: %+v", o.AppFingerprints)
	}
}

func TestSSHUnsupportedAlgorithmsKeepServerOffer(t *testing.T) {
	offer := kexInitPacket([10]string{"nyxr-test-kex", "nyxr-test-hostkey", "nyxr-test-cipher", "nyxr-test-cipher", "nyxr-test-mac", "nyxr-test-mac", "none", "none"})
	target := serve(t, func(conn net.Conn) {
		_, _ = io.WriteString(conn, "SSH-2.0-legacy_1.0\r\n")
		_, _ = conn.Write(offer)
		_, _ = io.Copy(io.Discard, conn)
	})
	o := testEngine(t).Interrogate(context.Background(), target)
	if o.Service != "ssh" || o.Product != "legacy" || o.SSH == nil || o.Attributes["ssh.host_key_sha256"] != "" {
		t.Fatalf("unsupported algorithms must not yield a host key: %+v", o)
	}
	if !strings.Contains(o.SSH.NegotiationError, "no common algorithm") || o.SSH.Negotiated == nil || o.SSH.Negotiated.KEX != "" ||
		o.SSH.KEX[0] != "nyxr-test-kex" || len(o.AppFingerprints) != 1 {
		t.Fatalf("server offer must be kept with the negotiation failure: %+v", o.SSH)
	}
}

func FuzzParseKexInit(f *testing.F) {
	f.Add([]byte("SSH-2.0-t\r\n" + string(kexInitPacket([10]string{"a", "b", "c", "d", "e", "f", "g", "h"}))))
	f.Add([]byte("SSH-2.0-t\r\n\x00\x00\x00\x05\x04\x14"))
	f.Fuzz(func(t *testing.T, data []byte) {
		k, ok, _ := parseKexInit(data)
		for _, l := range k {
			if len(l) > maxSSHNames {
				t.Fatalf("unbounded list %d", len(l))
			}
		}
		if ok {
			sshFingerprint(k)
		}
	})
}
