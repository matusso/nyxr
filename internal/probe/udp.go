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
	"strconv"
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
	Schema    string   `yaml:"schema"`
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
	Extract []string `yaml:"extract"`
}

// Probe is validated and ready for use by the scan engine.
type Probe struct {
	Name          string
	Tags          []string
	Ports         []uint16
	PortsDeclared bool // imported probe has port hints, even if none match this scan
	Payload       []byte
	Matcher       string
	Timeout       time.Duration
	Retries       int
	ExtractFields []string
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
	if d.Schema != "" && d.Schema != "nyxr/udp/v1" {
		return Probe{}, fmt.Errorf("unsupported UDP probe schema %q", d.Schema)
	}
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
	if matcher != "dns" && matcher != "ntp" && matcher != "snmp" && matcher != "snmpv3" && matcher != "any" &&
		matcher != "stun" && matcher != "tftp" && matcher != "ssdp" && matcher != "sip" && matcher != "coap" &&
		matcher != "bacnet" && matcher != "bacnet-read" && matcher != "bacnet-fdt" &&
		matcher != "rpc" && matcher != "memcached" && !extraMatcher(matcher) {
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
	if (len(payload) == 0 && matcher != "any") || len(payload) > maxPayload {
		return Probe{}, fmt.Errorf("payload must contain 1..%d bytes (except a NULL probe)", maxPayload)
	}
	if matcher == "dns" && (len(payload) < 12 || payload[2]&0xf8 != 0 || binary.BigEndian.Uint16(payload[4:6]) == 0) {
		return Probe{}, errors.New("DNS matcher requires a standard query with a question")
	}
	if matcher == "ntp" && (len(payload) < 48 || payload[0]&7 != 3 || payload[0]>>3&7 < 2 || payload[0]>>3&7 > 4) {
		return Probe{}, errors.New("NTP matcher requires a client-mode request")
	}
	if matcher == "snmp" {
		_, _, ok := snmpRequestIDOffset(payload, 1)
		if !ok {
			return Probe{}, errors.New("SNMP matcher requires a v2c GET template with a four-byte request ID")
		}
	}
	if matcher == "snmpv3" && !bytes.Equal(payload, snmpV3DiscoveryTemplate) {
		return Probe{}, errors.New("SNMPv3 matcher requires a noAuthNoPriv engine discovery template")
	}
	if matcher == "stun" && (len(payload) != 20 || binary.BigEndian.Uint16(payload[:2]) != 1 || !bytes.Equal(payload[4:8], []byte{0x21, 0x12, 0xa4, 0x42})) {
		return Probe{}, errors.New("STUN matcher requires a 20-byte binding request")
	}
	if matcher == "tftp" && (len(payload) < 6 || !bytes.Equal(payload[:2], []byte{0, 1}) || !bytes.HasSuffix(bytes.ToLower(payload), []byte("\x00octet\x00"))) {
		return Probe{}, errors.New("TFTP matcher requires a read request in octet mode")
	}
	if matcher == "ssdp" && !bytes.HasPrefix(payload, []byte("M-SEARCH * HTTP/1.1\r\n")) {
		return Probe{}, errors.New("SSDP matcher requires M-SEARCH")
	}
	if matcher == "sip" && (!bytes.HasPrefix(payload, []byte("OPTIONS ")) ||
		!bytes.Contains(payload, []byte("Call-ID: nyxr-0000000000000000\r\n")) ||
		!bytes.Contains(payload, []byte("Content-Length: 0\r\n"))) {
		return Probe{}, errors.New("SIP matcher requires an OPTIONS request with a Call-ID token and no body")
	}
	if matcher == "coap" && (len(payload) < 12 || payload[0] != 0x48 || payload[1] != 1) {
		return Probe{}, errors.New("CoAP matcher requires a confirmable GET with eight-byte token")
	}
	if matcher == "bacnet" && !bytes.Equal(payload, []byte{0x81, 0x0a, 0x00, 0x08, 0x01, 0x00, 0x10, 0x08}) {
		return Probe{}, errors.New("BACnet matcher requires an unicast Who-Is request")
	}
	if matcher == "bacnet-read" && !bytes.Equal(payload, []byte{0x81, 0x0a, 0x00, 0x11, 0x01, 0x04, 0x00, 0x05, 0x00, 0x0c, 0x0c, 0x02, 0x3f, 0xff, 0xff, 0x19, 0x4b}) {
		return Probe{}, errors.New("BACnet read matcher requires a Device object-identifier ReadProperty request")
	}
	if matcher == "bacnet-fdt" && !bytes.Equal(payload, []byte{0x81, 0x06, 0x00, 0x04}) {
		return Probe{}, errors.New("BACnet FDT matcher requires a Read-Foreign-Device-Table request")
	}
	if matcher == "rpc" && (len(payload) != 40 || binary.BigEndian.Uint32(payload[4:8]) != 0 ||
		binary.BigEndian.Uint32(payload[8:12]) != 2 || binary.BigEndian.Uint32(payload[20:24]) != 0 ||
		!bytes.Equal(payload[24:], make([]byte, 16))) {
		return Probe{}, errors.New("RPC matcher requires an ONC RPC NULL call with AUTH_NULL")
	}
	if matcher == "memcached" && !bytes.Equal(payload, []byte("\x00\x00\x00\x00\x00\x01\x00\x00version\r\n")) {
		return Probe{}, errors.New("memcached matcher requires a UDP version request")
	}
	if err := validateExtra(matcher, payload); err != nil {
		return Probe{}, err
	}
	allowed := map[string]string{"dns.rcode": "dns", "dns.txt": "dns", "cldap.attributes": "cldap", "ntp.stratum": "ntp", "stun.message_type": "stun",
		"tftp.error_code": "tftp", "ssdp.server": "ssdp", "ssdp.uuid": "ssdp", "sip.status": "sip", "coap.code": "coap",
		"bacnet.device_id": "bacnet", "bacnet.vendor_id": "bacnet", "bacnet.fdt_entries": "bacnet-fdt",
		"snmp.engine_id": "snmpv3"}
	if len(d.Extract) > 16 {
		return Probe{}, errors.New("at most 16 extraction fields are allowed")
	}
	seen := make(map[string]bool)
	for _, field := range d.Extract {
		if (allowed[field] != matcher && !(field == "bacnet.device_id" && matcher == "bacnet-read")) || seen[field] {
			return Probe{}, fmt.Errorf("invalid or duplicate extraction field %q for %s", field, matcher)
		}
		seen[field] = true
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
		Tags: append([]string(nil), d.Tags...), Matcher: matcher, Timeout: timeout, Retries: d.Retries,
		ExtractFields: append([]string(nil), d.Extract...)}, nil
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

// ForPort selects requests associated with a port for the common UDP profile.
func ForPort(all []Probe, port uint16) []Probe {
	selected := make([]Probe, 0, 2)
	var nullProbe Probe
	for _, p := range all {
		if p.Matcher == "any" && len(p.Payload) == 0 {
			nullProbe = p
			continue
		}
		if len(p.Ports) == 0 {
			if !p.PortsDeclared {
				selected = append(selected, p)
			}
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
		if nullProbe.Name != "" {
			return []Probe{nullProbe}
		}
		return []Probe{{Name: "udp-empty", Matcher: "any"}}
	}
	return selected
}

// ForEveryPort orders all requests for the deep UDP profile. Port lists are
// hints only; every request is tried if earlier ones do not identify a service.
func ForEveryPort(all []Probe, port uint16) []Probe {
	if len(all) == 0 {
		return []Probe{{Name: "udp-empty", Matcher: "any"}}
	}
	selected := make([]Probe, 0, len(all))
	var portless, other []Probe
	var nullProbe *Probe
	for _, p := range all {
		if p.Matcher == "any" && len(p.Payload) == 0 {
			copy := p
			nullProbe = &copy
			continue
		}
		if len(p.Ports) == 0 {
			portless = append(portless, p)
			continue
		}
		preferred := false
		for _, candidate := range p.Ports {
			if candidate == port {
				preferred = true
				break
			}
		}
		if preferred {
			selected = append(selected, p)
		} else {
			other = append(other, p)
		}
	}
	selected = append(append(selected, portless...), other...)
	if nullProbe != nil {
		selected = append(selected, *nullProbe)
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
		if offset, _, ok := snmpRequestIDOffset(payload, 1); ok {
			binary.BigEndian.PutUint32(payload[offset:offset+4], uint32(token)&0x7fffffff)
		}
	case "snmpv3":
		binary.BigEndian.PutUint16(payload[9:11], uint16(token)&0x7fff)
		binary.BigEndian.PutUint16(payload[50:52], uint16(token>>16)&0x7fff)
	case "stun":
		binary.BigEndian.PutUint64(payload[8:16], token)
	case "sip":
		payload = bytes.Replace(payload, []byte("nyxr-0000000000000000"), []byte(fmt.Sprintf("nyxr-%016x", token)), 1)
	case "coap":
		binary.BigEndian.PutUint16(payload[2:4], uint16(token>>48))
		binary.BigEndian.PutUint64(payload[4:12], token)
	case "bacnet-read":
		payload[8] = byte(token)
	case "rpc":
		binary.BigEndian.PutUint32(payload[:4], uint32(token))
	case "memcached":
		binary.BigEndian.PutUint16(payload[:2], uint16(token))
	default:
		prepareExtra(p.Matcher, payload, token)
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
		return len(request) >= 48 && len(response) >= 48 && response[0]&7 == 4 && response[0]>>3&7 == request[0]>>3&7 && bytes.Equal(request[40:48], response[24:32])
	case "snmp":
		return matchSNMP(request, response)
	case "snmpv3":
		_, ok := parseSNMPv3Report(request, response)
		return ok
	case "stun":
		return len(request) == 20 && len(response) >= 20 && response[0] == 1 && (response[1] == 1 || response[1] == 0x11) &&
			bytes.Equal(request[4:20], response[4:20])
	case "tftp":
		return len(response) >= 4 && response[0] == 0 && (response[1] == 3 || response[1] == 5)
	case "ssdp":
		return bytes.HasPrefix(response, []byte("HTTP/1.1 200 ")) || bytes.HasPrefix(response, []byte("HTTP/1.0 200 "))
	case "sip":
		return bytes.HasPrefix(response, []byte("SIP/2.0 ")) && hasHeaderValue(response, "call-id", sipCallID(request))
	case "coap":
		return len(request) >= 12 && len(response) >= 12 && response[0]>>6 == 1 && response[0]&15 == 8 &&
			response[1]>>5 >= 2 && bytes.Equal(request[4:12], response[4:12])
	case "bacnet":
		_, _, ok := parseBACnetIAm(response)
		return ok
	case "bacnet-read":
		return matchBACnetRead(request, response)
	case "bacnet-fdt":
		return matchBACnetFDT(response)
	case "rpc":
		return matchRPC(request, response)
	case "memcached":
		return len(request) == 17 && len(response) >= 17 &&
			bytes.Equal(request[:2], response[:2]) &&
			binary.BigEndian.Uint16(response[2:4]) == 0 &&
			binary.BigEndian.Uint16(response[4:6]) == 1 &&
			bytes.HasPrefix(response[8:], []byte("VERSION "))
	case "any":
		return true
	default:
		return matchExtra(p.Matcher, request, response)
	}
}

func sipCallID(request []byte) string {
	for _, line := range bytes.Split(request, []byte("\r\n")) {
		if bytes.HasPrefix(bytes.ToLower(line), []byte("call-id:")) {
			return strings.TrimSpace(string(line[8:]))
		}
	}
	return ""
}

func hasHeaderValue(response []byte, header, value string) bool {
	if value == "" {
		return false
	}
	for _, line := range bytes.Split(response, []byte("\r\n")) {
		parts := bytes.SplitN(line, []byte(":"), 2)
		if len(parts) == 2 && strings.EqualFold(string(parts[0]), header) && strings.TrimSpace(string(parts[1])) == value {
			return true
		}
	}
	return false
}

// Extract returns only fields explicitly requested by the probe definition.
// Values are bounded by the UDP response buffer and each extractor's limits.
func Extract(p Probe, response []byte) map[string]string {
	if len(p.ExtractFields) == 0 {
		return nil
	}
	fields := make(map[string]string, len(p.ExtractFields))
	for _, field := range p.ExtractFields {
		switch field {
		case "dns.rcode":
			if len(response) >= 4 {
				fields[field] = strconv.Itoa(int(response[3] & 15))
			}
		case "dns.txt":
			if value, ok := dnsTXT(response); ok {
				fields[field] = value
			}
		case "cldap.attributes":
			for name, value := range cldapAttributes(response) {
				fields[name] = value
			}
		case "ntp.stratum":
			if len(response) >= 2 {
				fields[field] = strconv.Itoa(int(response[1]))
			}
		case "snmp.engine_id":
			if report, ok := parseSNMPv3Report(nil, response); ok {
				for name, value := range report.fields() {
					fields[name] = value
				}
			}
		case "stun.message_type":
			if len(response) >= 2 {
				fields[field] = fmt.Sprintf("0x%04x", binary.BigEndian.Uint16(response[:2]))
			}
		case "tftp.error_code":
			if len(response) >= 4 && response[1] == 5 {
				fields[field] = strconv.Itoa(int(binary.BigEndian.Uint16(response[2:4])))
			}
		case "ssdp.server":
			for _, line := range bytes.Split(response, []byte("\r\n")) {
				if bytes.HasPrefix(bytes.ToLower(line), []byte("server:")) {
					fields[field] = strings.TrimSpace(string(line[7:]))
					break
				}
			}
		case "ssdp.uuid":
			for _, line := range bytes.Split(response, []byte("\r\n")) {
				if !bytes.HasPrefix(bytes.ToLower(line), []byte("usn:")) {
					continue
				}
				value := strings.ToLower(strings.TrimSpace(string(line[4:])))
				if !strings.HasPrefix(value, "uuid:") {
					continue
				}
				uuid := strings.SplitN(value[5:], "::", 2)[0]
				if validSSDPDeviceUUID(uuid) {
					fields[field] = uuid
				}
				break
			}
		case "sip.status":
			if len(response) >= 11 {
				fields[field] = string(response[8:11])
			}
		case "coap.code":
			if len(response) >= 2 {
				fields[field] = fmt.Sprintf("%d.%02d", response[1]>>5, response[1]&31)
			}
		case "bacnet.device_id", "bacnet.vendor_id":
			if p.Matcher == "bacnet-read" {
				if deviceID, ok := parseBACnetReadDeviceID(response); ok {
					fields["bacnet.device_id"] = strconv.FormatUint(uint64(deviceID), 10)
				}
			} else {
				deviceID, vendorID, ok := parseBACnetIAm(response)
				if ok {
					fields["bacnet.device_id"] = strconv.FormatUint(uint64(deviceID), 10)
					fields["bacnet.vendor_id"] = strconv.FormatUint(uint64(vendorID), 10)
				}
			}
		case "bacnet.fdt_entries":
			for name, value := range BACnetFDTFields(response) {
				fields[name] = value
			}
		}
	}
	if len(fields) == 0 {
		return nil
	}
	return fields
}

func validSSDPDeviceUUID(value string) bool {
	if len(value) != 36 {
		return false
	}
	for i, c := range value {
		if i == 8 || i == 13 || i == 18 || i == 23 {
			if c != '-' {
				return false
			}
		} else if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
}

// parseBACnetIAm accepts the minimal BACnet/IP Original-Unicast-NPDU form.
// A routed or broadcast I-Am is not attributed to the unicast target socket.
func parseBACnetIAm(b []byte) (uint32, uint32, bool) {
	if len(b) < 17 || b[0] != 0x81 || (b[1] != 0x0a && b[1] != 0x0b) || int(binary.BigEndian.Uint16(b[2:4])) != len(b) ||
		b[4] != 1 || b[5] != 0 || b[6] != 0x10 || b[7] != 0 || b[8] != 0xc4 {
		return 0, 0, false
	}
	object := binary.BigEndian.Uint32(b[9:13])
	if object>>22 != 8 {
		return 0, 0, false
	} // Device object
	pos := 13
	read := func(tag byte) (uint32, bool) {
		if pos >= len(b) || b[pos]>>4 != tag || b[pos]&8 != 0 {
			return 0, false
		}
		n := int(b[pos] & 7)
		pos++
		if n < 1 || n > 4 || n > len(b)-pos {
			return 0, false
		}
		var value uint32
		for _, x := range b[pos : pos+n] {
			value = value<<8 | uint32(x)
		}
		pos += n
		return value, true
	}
	if _, ok := read(2); !ok {
		return 0, 0, false
	} // max APDU
	if _, ok := read(9); !ok {
		return 0, 0, false
	} // segmentation
	vendor, ok := read(2)
	return object & 0x3fffff, vendor, ok && pos == len(b)
}

func validBACnetFDT(b []byte) bool {
	return len(b) >= 4 && b[0] == 0x81 && b[1] == 0x07 &&
		int(binary.BigEndian.Uint16(b[2:4])) == len(b) && (len(b)-4)%10 == 0
}

func matchBACnetFDT(b []byte) bool {
	return validBACnetFDT(b) ||
		(len(b) == 6 && b[0] == 0x81 && b[1] == 0 && b[2] == 0 && b[3] == 6 &&
			binary.BigEndian.Uint16(b[4:6]) == 0x0040)
}

func matchBACnetRead(request, response []byte) bool {
	if len(request) != 17 || len(response) < 9 || response[0] != 0x81 ||
		response[1] != 0x0a || int(binary.BigEndian.Uint16(response[2:4])) != len(response) ||
		response[4] != 1 || response[5] != 0 || response[7] != request[8] {
		return false
	}
	switch response[6] >> 4 {
	case 3, 5: // Complex-ACK or Error, both name the ReadProperty service.
		return response[8] == 0x0c
	case 6, 7: // Reject or Abort carries the matching invoke ID.
		return len(response) >= 9
	default:
		return false
	}
}

func parseBACnetReadDeviceID(b []byte) (uint32, bool) {
	if len(b) != 23 || b[0] != 0x81 || b[1] != 0x0a ||
		int(binary.BigEndian.Uint16(b[2:4])) != len(b) || b[4] != 1 || b[5] != 0 ||
		b[6] != 0x30 || b[8] != 0x0c || b[9] != 0x0c || b[14] != 0x19 ||
		b[15] != 0x4b || b[16] != 0x3e || b[17] != 0xc4 || b[22] != 0x3f {
		return 0, false
	}
	object := binary.BigEndian.Uint32(b[18:22])
	return object & 0x3fffff, object>>22 == 8
}

func matchRPC(request, response []byte) bool {
	if len(request) != 40 || len(response) < 12 || !bytes.Equal(request[:4], response[:4]) ||
		binary.BigEndian.Uint32(response[4:8]) != 1 {
		return false
	}
	switch binary.BigEndian.Uint32(response[8:12]) {
	case 0: // Accepted: opaque verifier, then an accept status.
		if len(response) < 24 {
			return false
		}
		verifierLen := binary.BigEndian.Uint32(response[16:20])
		if verifierLen > 400 {
			return false
		}
		statusAt := 20 + int((verifierLen+3)&^3)
		if len(response) < statusAt+4 {
			return false
		}
		return binary.BigEndian.Uint32(response[statusAt:statusAt+4]) == 0
	default:
		return false
	}
}

func matchSNMP(request, response []byte) bool {
	return matchSNMPVersion(request, response, 1)
}

func snmpRequestIDOffset(request []byte, expectedVersion int) (int, []byte, bool) {
	var outer asn1.RawValue
	rest, err := asn1.Unmarshal(request, &outer)
	if err != nil || len(rest) != 0 || outer.Class != 0 || outer.Tag != 16 {
		return 0, nil, false
	}
	var version int
	body, err := asn1.Unmarshal(outer.Bytes, &version)
	if err != nil || version != expectedVersion {
		return 0, nil, false
	}
	var community []byte
	body, err = asn1.Unmarshal(body, &community)
	if err != nil || len(community) == 0 {
		return 0, nil, false
	}
	var pdu asn1.RawValue
	rest, err = asn1.Unmarshal(body, &pdu)
	if err != nil || len(rest) != 0 || pdu.Class != 2 || pdu.Tag != 0 ||
		len(pdu.Bytes) < 6 || pdu.Bytes[0] != 2 || pdu.Bytes[1] != 4 {
		return 0, nil, false
	}
	return len(request) - len(pdu.Bytes) + 2, community, true
}

func matchSNMPVersion(request, response []byte, expectedVersion int) bool {
	offset, requestedCommunity, ok := snmpRequestIDOffset(request, expectedVersion)
	if !ok {
		return false
	}
	var outer asn1.RawValue
	rest, err := asn1.Unmarshal(response, &outer)
	if err != nil || len(rest) != 0 || outer.Class != 0 || outer.Tag != 16 {
		return false
	}
	var version int
	body, err := asn1.Unmarshal(outer.Bytes, &version)
	if err != nil || version != expectedVersion {
		return false
	}
	var community []byte
	body, err = asn1.Unmarshal(body, &community)
	if err != nil || !bytes.Equal(community, requestedCommunity) {
		return false
	}
	var pdu asn1.RawValue
	rest, err = asn1.Unmarshal(body, &pdu)
	if err != nil || len(rest) != 0 || pdu.Class != 2 || pdu.Tag != 2 {
		return false
	}
	var requestID int
	_, err = asn1.Unmarshal(pdu.Bytes, &requestID)
	return err == nil && requestID >= 0 && uint32(requestID) == binary.BigEndian.Uint32(request[offset:offset+4])
}
