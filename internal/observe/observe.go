// Package observe defines the versioned records that every nyxr stage emits
// and every consumer (CLI, storage, a future API/UI) reads. Records are plain
// values: the fast packet path fills the discovery fields, the deep-probe
// engine adds service identity and evidence, and the capture recorder links
// packets back to observations by scan, target, transport and port.
package observe

import (
	"crypto/rand"
	"encoding/hex"
	"net/netip"
	"time"
)

// SchemaVersion is written into every record. Consumers should reject a major
// version they do not understand; minor additions only add optional fields.
const SchemaVersion = "nyxr/v1"

// Record kinds. A JSON stream may interleave all of them; readers switch on
// the "kind" field.
const (
	KindHost           = "host"            // ICMP/ARP/NDP reachability of one address
	KindPort           = "port"            // discovery state of one transport port
	KindService        = "service"         // deep-probe identity of an open port
	KindDevice         = "device"          // multi-source device classification
	KindPacketEvidence = "packet-evidence" // captured frames belonging to one flow
	KindScan           = "scan"            // scan summary, emitted last
)

// Fingerprint values. Unknown responses are never discarded: they keep their
// raw evidence so later signatures can be developed from stored scans.
const (
	FingerprintMatched = "matched"
	FingerprintUnknown = "unknown"
)

// Observation is one claim about a target, with the confidence and reason
// that justify it. The discovery fields keep their original JSON names so
// existing consumers of nyxr output continue to work.
type Observation struct {
	Schema          string            `json:"schema,omitempty"`
	Kind            string            `json:"kind,omitempty"`
	ScanID          string            `json:"scan_id,omitempty"`
	Timestamp       time.Time         `json:"timestamp"`
	Target          netip.Addr        `json:"target"`
	Transport       string            `json:"transport"`
	Port            uint16            `json:"port,omitempty"`
	State           string            `json:"state"`
	Confidence      int               `json:"confidence"`
	Reason          string            `json:"reason"`
	Probe           string            `json:"probe"`
	Service         string            `json:"service,omitempty"`
	Product         string            `json:"product,omitempty"`
	Version         string            `json:"version,omitempty"`
	Fingerprint     string            `json:"fingerprint,omitempty"`
	MAC             string            `json:"mac,omitempty"`
	RTT             time.Duration     `json:"rtt_ns"`
	PacketsTX       int               `json:"packets_tx"`
	PacketsRX       int               `json:"packets_rx"`
	ProbesAttempted []string          `json:"probes_attempted,omitempty"`
	ResponseHex     string            `json:"response_hex,omitempty"`
	Fields          map[string]string `json:"fields,omitempty"`
	// Attributes holds protocol fields such as http.server or ssh.software.
	Attributes map[string]string `json:"attributes,omitempty"`
	TLS        *TLS              `json:"tls,omitempty"`
	// Evidence lists every deep-probe exchange, matched or not.
	Evidence []Evidence     `json:"evidence,omitempty"`
	Signals  []DeviceSignal `json:"signals,omitempty"`
}

// DeviceSignal points to an observation that supports a device claim.
type DeviceSignal struct {
	Source    string `json:"source"`
	Transport string `json:"transport"`
	Port      uint16 `json:"port,omitempty"`
	Detail    string `json:"detail"`
}

// Stamp fills the envelope fields. It leaves an explicit Kind alone.
func (o *Observation) Stamp(scanID string) {
	o.Schema, o.ScanID = SchemaVersion, scanID
	if o.Kind == "" {
		o.Kind = KindPort
		if o.Port == 0 {
			o.Kind = KindHost
		}
	}
}

// Evidence is one probe execution: what was sent, what came back, and which
// matcher (if any) recognized the response. Byte fields are base64 in JSON.
type Evidence struct {
	Probe     string        `json:"probe"`
	Layer     string        `json:"layer"` // tcp or tls (payload carried inside TLS)
	Started   time.Time     `json:"started"`
	Duration  time.Duration `json:"duration_ns"`
	Request   []byte        `json:"request,omitempty"`
	Response  []byte        `json:"response,omitempty"`
	Truncated bool          `json:"truncated,omitempty"` // response exceeded the retention limit
	Matched   string        `json:"matched,omitempty"`   // matcher name; empty when unrecognized
	Error     string        `json:"error,omitempty"`
}

// TLS is the shared TLS subsystem result, reused by every service behind TLS.
type TLS struct {
	Version      string        `json:"version"`
	CipherSuite  string        `json:"cipher_suite"`
	ALPN         string        `json:"alpn,omitempty"`
	ServerName   string        `json:"server_name,omitempty"` // SNI sent, if any
	OCSPStapled  bool          `json:"ocsp_stapled,omitempty"`
	SCTs         int           `json:"scts,omitempty"`
	Certificates []Certificate `json:"certificates,omitempty"`
}

// Certificate summarizes one presented certificate, leaf first.
type Certificate struct {
	Subject            string    `json:"subject"`
	Issuer             string    `json:"issuer"`
	Serial             string    `json:"serial"`
	DNSNames           []string  `json:"dns_names,omitempty"`
	IPAddresses        []string  `json:"ip_addresses,omitempty"`
	NotBefore          time.Time `json:"not_before"`
	NotAfter           time.Time `json:"not_after"`
	PublicKeyAlgorithm string    `json:"public_key_algorithm"`
	KeyBits            int       `json:"key_bits,omitempty"`
	SignatureAlgorithm string    `json:"signature_algorithm"`
	SelfSigned         bool      `json:"self_signed,omitempty"`
	SHA256             string    `json:"sha256"`
}

// PacketEvidence references the frames a capture recorded for one flow. The
// packet IDs are the pcapng epb_packetid values in Capture.
type PacketEvidence struct {
	Schema    string     `json:"schema"`
	Kind      string     `json:"kind"`
	ScanID    string     `json:"scan_id"`
	Target    netip.Addr `json:"target"`
	Transport string     `json:"transport"`
	Port      uint16     `json:"port,omitempty"`
	Capture   string     `json:"capture"`
	Packets   []Packet   `json:"packets"`
	// Truncated means more frames matched this flow than the index retains.
	Truncated bool `json:"truncated,omitempty"`
}

// Packet is one indexed frame in a capture file.
type Packet struct {
	ID        uint64    `json:"id"`
	Timestamp time.Time `json:"timestamp"`
	Direction string    `json:"direction"` // tx or rx relative to the scanner
	Length    int       `json:"length"`
	Summary   string    `json:"summary"`
}

// Scan summarizes one run and is emitted after every other record.
type Scan struct {
	Schema       string        `json:"schema"`
	Kind         string        `json:"kind"`
	ID           string        `json:"scan_id"`
	Profile      string        `json:"profile"`
	Started      time.Time     `json:"started"`
	Finished     time.Time     `json:"finished,omitempty"`
	Status       string        `json:"status"` // running, completed, failed
	Error        string        `json:"error,omitempty"`
	Targets      int           `json:"targets"`
	Observations int           `json:"observations"`
	Services     int           `json:"services"`
	Capture      *CaptureStats `json:"capture,omitempty"`
}

// CaptureStats reports how complete the packet evidence is. Dropped frames are
// counted rather than silently lost.
type CaptureStats struct {
	Path          string `json:"path"`
	Interface     string `json:"interface"`
	Written       uint64 `json:"written"`
	Bytes         int64  `json:"bytes"`
	DroppedQueue  uint64 `json:"dropped_queue,omitempty"`
	DroppedLimit  uint64 `json:"dropped_limit,omitempty"`
	BackendDrops  uint64 `json:"backend_drops,omitempty"`
	FlowsIndexed  int    `json:"flows_indexed"`
	FlowsTruncate uint64 `json:"flows_truncated,omitempty"`
}

// NewScanID returns a sortable, collision-resistant identifier: a UTC
// timestamp followed by 48 random bits.
func NewScanID(now time.Time) string {
	var r [6]byte
	_, _ = rand.Read(r[:])
	return now.UTC().Format("20060102T150405Z") + "-" + hex.EncodeToString(r[:])
}
