package probe

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"embed"
	"encoding/asn1"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

//go:embed native/*.yaml
var native embed.FS

const maxPayload = 65507

// Definition is the deliberately small first version of the native UDP probe
// format. Unknown YAML fields are rejected instead of being silently ignored.
type Definition struct {
	Name      string   `yaml:"name"`
	Transport string   `yaml:"transport"`
	Ports     []uint16 `yaml:"ports"`
	Tags      []string `yaml:"tags"`
	Safety    string   `yaml:"safety"`
	Payload   struct {
		Encoding string `yaml:"encoding"`
		Data     string `yaml:"data"`
	} `yaml:"payload"`
	Timeout string `yaml:"timeout"`
	Retries int    `yaml:"retries"`
	Match   []struct {
		Type string `yaml:"type"`
	} `yaml:"match"`
}

// Probe is validated and ready for use by the scan engine.
type Probe struct {
	Name    string
	Ports   []uint16
	Payload []byte
	Matcher string
	Timeout time.Duration
	Retries int
}

func Parse(r io.Reader, baseDir string) (Probe, error) {
	var d Definition
	dec := yaml.NewDecoder(io.LimitReader(r, 1<<20))
	dec.KnownFields(true)
	if err := dec.Decode(&d); err != nil {
		return Probe{}, err
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		if err == nil {
			return Probe{}, errors.New("probe file must contain one document")
		}
		return Probe{}, err
	}
	return d.Compile(baseDir)
}

func LoadFile(path string) (Probe, error) {
	f, err := os.Open(path)
	if err != nil {
		return Probe{}, err
	}
	defer f.Close()
	return Parse(f, filepath.Dir(path))
}

func (d Definition) Compile(baseDir string) (Probe, error) {
	if d.Name == "" || d.Transport != "udp" || d.Safety != "safe" {
		return Probe{}, errors.New("probe requires name, transport: udp, and safety: safe")
	}
	if d.Retries < 0 || d.Retries > 5 {
		return Probe{}, errors.New("probe retries must be 0..5")
	}
	if len(d.Match) != 1 {
		return Probe{}, errors.New("probe requires exactly one matcher")
	}
	matcher := d.Match[0].Type
	if matcher != "dns" && matcher != "ntp" && matcher != "snmp" && matcher != "any" {
		return Probe{}, fmt.Errorf("unsupported matcher %q", matcher)
	}
	var payload []byte
	var err error
	switch d.Payload.Encoding {
	case "ascii":
		payload = []byte(d.Payload.Data)
	case "hex":
		payload, err = hex.DecodeString(strings.Join(strings.Fields(d.Payload.Data), ""))
	case "base64":
		payload, err = base64.StdEncoding.DecodeString(strings.Join(strings.Fields(d.Payload.Data), ""))
	case "raw_file":
		path := d.Payload.Data
		if !filepath.IsAbs(path) {
			path = filepath.Join(baseDir, path)
		}
		f, openErr := os.Open(path)
		if openErr != nil {
			return Probe{}, openErr
		}
		defer f.Close()
		payload, err = io.ReadAll(io.LimitReader(f, maxPayload+1))
	default:
		return Probe{}, fmt.Errorf("unsupported payload encoding %q", d.Payload.Encoding)
	}
	if err != nil {
		return Probe{}, err
	}
	if len(payload) == 0 || len(payload) > maxPayload {
		return Probe{}, fmt.Errorf("payload must contain 1..%d bytes", maxPayload)
	}
	if matcher == "dns" && len(payload) < 12 {
		return Probe{}, errors.New("DNS payload is too short")
	}
	if matcher == "ntp" && len(payload) < 48 {
		return Probe{}, errors.New("NTP payload is too short")
	}
	if matcher == "snmp" && (len(payload) < 21 || payload[0] != 0x30 || payload[13] != 0xa0 || payload[15] != 0x02 || payload[16] != 0x04) {
		return Probe{}, errors.New("SNMP matcher requires a v2c GET template with a four-byte request ID")
	}
	var timeout time.Duration
	if d.Timeout != "" {
		timeout, err = time.ParseDuration(d.Timeout)
		if err != nil || timeout <= 0 {
			return Probe{}, errors.New("probe timeout must be positive duration")
		}
	}
	for _, port := range d.Ports {
		if port == 0 {
			return Probe{}, errors.New("probe port must be 1..65535")
		}
	}
	return Probe{Name: d.Name, Ports: append([]uint16(nil), d.Ports...), Payload: payload,
		Matcher: matcher, Timeout: timeout, Retries: d.Retries}, nil
}

func Builtins() ([]Probe, error) {
	entries, err := fs.Glob(native, "native/*.yaml")
	if err != nil {
		return nil, err
	}
	probes := make([]Probe, 0, len(entries))
	for _, name := range entries {
		data, err := native.ReadFile(name)
		if err != nil {
			return nil, err
		}
		p, err := Parse(bytes.NewReader(data), "")
		if err != nil {
			return nil, fmt.Errorf("%s: %w", name, err)
		}
		probes = append(probes, p)
	}
	return probes, nil
}

func ForPort(all []Probe, port uint16) []Probe {
	selected := make([]Probe, 0, 2)
	for _, p := range all {
		if len(p.Ports) == 0 {
			selected = append(selected, p)
			continue
		}
		for _, candidate := range p.Ports {
			if candidate == port {
				selected = append(selected, p)
				break
			}
		}
	}
	if len(selected) == 0 {
		selected = append(selected, Probe{Name: "generic-byte", Payload: []byte{0}, Matcher: "any"})
	}
	return selected
}

// Token derives a stateless validation value for protocol fields. The secret
// is generated once per scan, and each attempt uses a distinct counter.
func Token(secret []byte, target string, port uint16, name string, attempt uint32) uint64 {
	h := hmac.New(sha256.New, secret)
	_, _ = h.Write([]byte(target))
	var numbers [6]byte
	binary.BigEndian.PutUint16(numbers[:2], port)
	binary.BigEndian.PutUint32(numbers[2:], attempt)
	_, _ = h.Write(numbers[:])
	_, _ = h.Write([]byte(name))
	return binary.BigEndian.Uint64(h.Sum(nil)[:8])
}

func Prepare(p Probe, token uint64) []byte {
	payload := append([]byte(nil), p.Payload...)
	switch p.Matcher {
	case "dns":
		binary.BigEndian.PutUint16(payload[:2], uint16(token))
	case "ntp":
		binary.BigEndian.PutUint64(payload[40:48], token)
	case "snmp":
		binary.BigEndian.PutUint32(payload[17:21], uint32(token)&0x7fffffff)
	}
	return payload
}

// Match validates the response against fields of the transmitted request.
// An unmatched datagram is still evidence that the UDP port responded; the
// scan engine records it with reduced confidence and an unknown fingerprint.
func Match(p Probe, request, response []byte) bool {
	switch p.Matcher {
	case "dns":
		return len(request) >= 12 && len(response) >= 12 && response[2]&0x80 != 0 && bytes.Equal(request[:2], response[:2])
	case "ntp":
		return len(request) >= 48 && len(response) >= 48 && response[0]&7 == 4 && bytes.Equal(request[40:48], response[24:32])
	case "snmp":
		return matchSNMP(request, response)
	case "any":
		return true
	default:
		return false
	}
}

func matchSNMP(request, response []byte) bool {
	if len(request) < 21 {
		return false
	}
	var outer asn1.RawValue
	rest, err := asn1.Unmarshal(response, &outer)
	if err != nil || len(rest) != 0 || outer.Class != 0 || outer.Tag != 16 {
		return false
	}
	var version int
	body, err := asn1.Unmarshal(outer.Bytes, &version)
	if err != nil || version != 1 {
		return false
	}
	var community []byte
	body, err = asn1.Unmarshal(body, &community)
	if err != nil || len(community) == 0 {
		return false
	}
	var pdu asn1.RawValue
	rest, err = asn1.Unmarshal(body, &pdu)
	if err != nil || len(rest) != 0 || pdu.Class != 2 || pdu.Tag != 2 {
		return false
	}
	var requestID int
	_, err = asn1.Unmarshal(pdu.Bytes, &requestID)
	return err == nil && requestID >= 0 && uint32(requestID) == binary.BigEndian.Uint32(request[17:21])
}
