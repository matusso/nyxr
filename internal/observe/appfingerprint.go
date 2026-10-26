package observe

// Application fingerprint methods. A method names one normalization; a
// change to the normalization gets a new method so stored values stay
// comparable with each other.
const (
	FingerprintTLSServer = "nyxr-tls-server/v1"  // ServerHello version, cipher suite and extension order
	FingerprintSSHServer = "nyxr-ssh-kexinit/v1" // server KEXINIT algorithm lists in wire order
)

// AppFingerprint is a normalized application-layer fingerprint of one
// exchange. It describes how server software is configured, not which device
// runs it: many hosts share one value. It is never an asset merge key and
// never confirms an operating system or intermediary role.
type AppFingerprint struct {
	Method     string `json:"method"`
	Value      string `json:"value"` // hex SHA-256 of Normalized
	Normalized string `json:"normalized"`
	// Profile names the client offer that produced the value. Values are
	// comparable only between results of the same method and profile.
	Profile    string `json:"profile,omitempty"`
	ServerName string `json:"server_name,omitempty"` // SNI sent, if any
	Evidence   int    `json:"evidence"`              // index into Observation.Evidence
	// Status is observed, or partial when retained bytes ended early.
	Status string `json:"status"`
}

// FingerprintConflict records exchanges with one target that disagree on a
// value expected to be stable, such as the certificate behind one name.
// Conflicts are kept, not resolved: either side may be the true one.
type FingerprintConflict struct {
	Field    string   `json:"field"`
	Values   []string `json:"values"`
	Evidence []int    `json:"evidence"`
	Detail   string   `json:"detail,omitempty"`
}

// TLSProfileResult is one bounded ClientHello variant and the server's
// answer to it.
type TLSProfileResult struct {
	Profile    string `json:"profile"`
	ServerName string `json:"server_name,omitempty"`
	// Outcome is negotiated, alert, plaintext, no-response or error.
	Outcome     string `json:"outcome"`
	Version     string `json:"version,omitempty"`
	CipherSuite string `json:"cipher_suite,omitempty"`
	ALPN        string `json:"alpn,omitempty"`
	LeafSHA256  string `json:"leaf_sha256,omitempty"`
	Alert       string `json:"alert,omitempty"`
	Error       string `json:"error,omitempty"`
	Evidence    int    `json:"evidence"`
}

// SSH is the cleartext algorithm negotiation of an SSH key exchange. Server
// lists are observed bytes; Negotiated is computed from both offers with the
// RFC 4253 rule and is therefore inferred.
type SSH struct {
	KEX                 []string       `json:"kex,omitempty"`
	HostKey             []string       `json:"host_key,omitempty"`
	CiphersClientServer []string       `json:"ciphers_client_server,omitempty"`
	CiphersServerClient []string       `json:"ciphers_server_client,omitempty"`
	MACsClientServer    []string       `json:"macs_client_server,omitempty"`
	MACsServerClient    []string       `json:"macs_server_client,omitempty"`
	CompressionServer   []string       `json:"compression_server_client,omitempty"`
	Negotiated          *SSHNegotiated `json:"negotiated,omitempty"`
	// NegotiationError is set when the exchange stopped before a verified
	// host key, for example because no algorithm was shared.
	NegotiationError string `json:"negotiation_error,omitempty"`
	Evidence         int    `json:"evidence"`
	Truncated        bool   `json:"truncated,omitempty"`
}

// SSHNegotiated holds the algorithms both sides would select. An empty field
// means the offers share no algorithm in that category.
type SSHNegotiated struct {
	ClaimStatus string `json:"claim_status"` // always inferred
	KEX         string `json:"kex"`
	HostKey     string `json:"host_key"`
	Cipher      string `json:"cipher_server_client"`
	MAC         string `json:"mac_server_client"`
	Compression string `json:"compression_server_client"`
}
