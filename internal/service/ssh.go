package service

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/matusso/nyxr/internal/observe"
)

const probeSSHHostKey = "ssh-host-key"

var errHostKeyCaptured = errors.New("SSH host key captured")

// probeSSHHostKey completes key exchange and stops before authentication.
// x/crypto/ssh verifies the server's key-exchange signature before invoking
// HostKeyCallback, so only a proven key becomes an identity signal.
func (e *Engine) probeSSHHostKey(ctx context.Context, target Target, o *observe.Observation) observe.Evidence {
	ev := observe.Evidence{Probe: probeSSHHostKey, Layer: "tcp", Started: time.Now().UTC()}
	timeout := e.timeout(ProbeSSH)
	conn, err := e.dial(ctx, target, timeout)
	if err != nil {
		ev.Error, ev.Duration = err.Error(), time.Since(ev.Started)
		return ev
	}
	defer conn.Close()
	rc := e.record(conn)
	stop := deadline(ctx, rc, timeout)
	defer stop()
	var digest, keyType string
	config := &ssh.ClientConfig{User: "nyxr", HostKeyCallback: func(_ string, _ net.Addr, key ssh.PublicKey) error {
		value := sha256.Sum256(key.Marshal())
		digest, keyType = hex.EncodeToString(value[:]), key.Type()
		return errHostKeyCaptured
	}}
	_, _, _, err = ssh.NewClientConn(rc, net.JoinHostPort(target.Addr.String(), "ssh"), config)
	if errors.Is(err, errHostKeyCaptured) && digest != "" {
		if o.Attributes == nil {
			o.Attributes = map[string]string{}
		}
		o.Attributes["ssh.host_key_sha256"] = digest
		o.Attributes["ssh.host_key_type"] = keyType
		ev.Matched = probeSSHHostKey
		e.finish(&ev, rc, nil)
	} else {
		e.finish(&ev, rc, err)
	}
	return ev
}

// matchSSH recognizes an RFC 4253 identification string. Servers may send
// other lines first, so each line of the banner is checked.
func matchSSH(o *observe.Observation, banner []byte) bool {
	for _, line := range bytes.Split(banner, []byte("\n")) {
		line = bytes.TrimRight(line, "\r")
		if !bytes.HasPrefix(line, []byte("SSH-")) || len(line) > 255 {
			continue
		}
		rest := string(line[4:])
		proto, software, ok := strings.Cut(rest, "-")
		if !ok || software == "" || (proto != "2.0" && proto != "1.99" && proto != "1.5") {
			continue
		}
		software, comment, _ := strings.Cut(software, " ")
		o.Service, o.Confidence, o.Fingerprint = "ssh", 100, observe.FingerprintMatched
		o.Reason = "SSH identification string"
		o.Probe = ProbeSSH
		o.Attributes = map[string]string{"ssh.protocol": proto, "ssh.software": software}
		if comment != "" {
			o.Attributes["ssh.comment"] = comment
		}
		o.Product, o.Version = splitSoftware(software, "_")
		return true
	}
	return false
}

// splitSoftware turns "OpenSSH_9.6p1" or "nginx/1.25.3" into product and
// version. A token without a separator followed by a digit is product only.
func splitSoftware(s, sep string) (product, version string) {
	product, version, ok := strings.Cut(s, sep)
	if !ok || version == "" || version[0] < '0' || version[0] > '9' {
		return s, ""
	}
	return product, version
}
