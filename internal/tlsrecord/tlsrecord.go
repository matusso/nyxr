// Package tlsrecord explains raw TLS record-layer bytes field by field, so a
// response that is only an alert or a stray handshake reads as more than hex.
package tlsrecord

import (
	"encoding/binary"
	"fmt"
	"strings"

	"github.com/matusso/nyxr/internal/observe"
)

const (
	headerLen  = 5
	maxRecord  = 1<<14 + 2048 // largest ciphertext a record may carry (RFC 5246 §6.2.3)
	maxRecords = 8            // a full handshake flight carries little worth itemizing beyond this
)

var contentTypes = map[byte][2]string{
	20: {"change_cipher_spec", "switch to the negotiated keys"},
	21: {"alert", "an alert message follows: a warning or the reason the connection is being closed"},
	22: {"handshake", "a handshake message follows"},
	23: {"application_data", "encrypted payload (TLS 1.3 also hides its later handshake messages here)"},
	24: {"heartbeat", "heartbeat request or response (RFC 6520)"},
}

var versions = map[uint16][2]string{
	0x0300: {"SSL 3.0", "record-layer version SSL 3.0"},
	0x0301: {"TLS 1.0", "record-layer version TLS 1.0; also common on early records of newer handshakes"},
	0x0302: {"TLS 1.1", "record-layer version TLS 1.1"},
	0x0303: {"TLS 1.2", "record-layer version TLS 1.2; TLS 1.3 also writes 0x0303 here for compatibility"},
	0x0304: {"TLS 1.3", "TLS 1.3 never sends this on the record layer; unusual"},
}

var alertLevels = map[byte][2]string{
	1: {"warning", "the connection may continue"},
	2: {"fatal", "the sender closes the connection immediately"},
}

// Alert descriptions from the IANA TLS Alert registry.
var alerts = map[byte][2]string{
	0:   {"close_notify", "the sender is closing the connection cleanly"},
	10:  {"unexpected_message", "the server received a message it did not expect at this point"},
	20:  {"bad_record_mac", "a record failed integrity checks"},
	21:  {"decryption_failed", "a record could not be decrypted (obsolete)"},
	22:  {"record_overflow", "a record exceeded the maximum allowed length"},
	30:  {"decompression_failure", "compressed data could not be decompressed (obsolete)"},
	40:  {"handshake_failure", "no acceptable set of security parameters; often no shared cipher suite or version"},
	41:  {"no_certificate", "no certificate was available (SSL 3.0 only)"},
	42:  {"bad_certificate", "a certificate was corrupt or its signature did not verify"},
	43:  {"unsupported_certificate", "a certificate was of an unsupported type"},
	44:  {"certificate_revoked", "a certificate was revoked by its signer"},
	45:  {"certificate_expired", "a certificate has expired or is not yet valid"},
	46:  {"certificate_unknown", "an unspecified problem with a certificate"},
	47:  {"illegal_parameter", "a handshake field was out of range or inconsistent with other fields"},
	48:  {"unknown_ca", "the certificate chain does not lead to a trusted CA"},
	49:  {"access_denied", "the peer was identified but access control refused the connection"},
	50:  {"decode_error", "a message could not be parsed"},
	51:  {"decrypt_error", "a cryptographic operation in the handshake failed"},
	60:  {"export_restriction", "an export-restricted negotiation was attempted (obsolete)"},
	70:  {"protocol_version", "the server does not support the offered TLS version"},
	71:  {"insufficient_security", "the server requires stronger ciphers than were offered"},
	80:  {"internal_error", "the server failed for a reason unrelated to the client, often a misconfiguration such as no certificate for the requested name"},
	86:  {"inappropriate_fallback", "a version-fallback retry was refused (RFC 7507)"},
	90:  {"user_canceled", "the handshake was canceled for a reason unrelated to a protocol failure"},
	100: {"no_renegotiation", "renegotiation was refused"},
	109: {"missing_extension", "a required extension was not sent"},
	110: {"unsupported_extension", "an extension was sent that is not allowed in this message"},
	111: {"certificate_unobtainable", "a certificate could not be fetched from its URL (obsolete)"},
	112: {"unrecognized_name", "the server has no service for the requested SNI name"},
	113: {"bad_certificate_status_response", "an invalid OCSP response was received"},
	114: {"bad_certificate_hash_value", "a certificate hash did not match (obsolete)"},
	115: {"unknown_psk_identity", "no acceptable pre-shared key identity was offered"},
	116: {"certificate_required", "the server requires a client certificate"},
	120: {"no_application_protocol", "the server supports none of the ALPN protocols offered"},
	121: {"ech_required", "the server requires Encrypted Client Hello"},
}

var handshakeTypes = map[byte]string{
	0: "hello_request", 1: "client_hello", 2: "server_hello", 3: "hello_verify_request",
	4: "new_session_ticket", 5: "end_of_early_data", 6: "hello_retry_request", 8: "encrypted_extensions",
	11: "certificate", 12: "server_key_exchange", 13: "certificate_request", 14: "server_hello_done",
	15: "certificate_verify", 16: "client_key_exchange", 20: "finished", 21: "certificate_url",
	22: "certificate_status", 24: "key_update", 254: "message_hash",
}

// Decode explains data as a sequence of TLS records. It returns nil unless
// data starts with a plausible record header; a truncated record is
// explained as far as its bytes go.
func Decode(data []byte) []observe.ByteField {
	var out []observe.ByteField
	for off, n := 0, 0; off+headerLen <= len(data) && n < maxRecords; n++ {
		ct, version, length := data[off], binary.BigEndian.Uint16(data[off+1:]), int(binary.BigEndian.Uint16(data[off+3:]))
		if _, ok := contentTypes[ct]; !ok || data[off+1] != 3 || data[off+2] > 4 || length > maxRecord {
			break
		}
		out = append(out, header(data, off, ct, version, length)...)
		body := data[off+headerLen : min(len(data), off+headerLen+length)]
		out = append(out, explainBody(data, off+headerLen, ct, body)...)
		off += headerLen + length
	}
	return out
}

func header(data []byte, off int, ct byte, version uint16, length int) []observe.ByteField {
	t, v := contentTypes[ct], versions[version]
	return []observe.ByteField{
		field(data, off, 1, "content type", t[0], fmt.Sprintf("record type %d: %s", ct, t[1])),
		field(data, off+1, 2, "version", v[0], v[1]),
		field(data, off+3, 2, "length", fmt.Sprintf("len %d", length), fmt.Sprintf("record body is %d bytes", length)),
	}
}

func explainBody(data []byte, off int, ct byte, body []byte) []observe.ByteField {
	var out []observe.ByteField
	switch ct {
	case 21:
		if len(body) >= 1 {
			l, ok := alertLevels[body[0]]
			if !ok {
				l = [2]string{fmt.Sprintf("level %d", body[0]), "unassigned alert level"}
			}
			out = append(out, field(data, off, 1, "alert level", l[0], fmt.Sprintf("level %d: %s", body[0], l[1])))
		}
		if len(body) >= 2 {
			a, ok := alerts[body[1]]
			if !ok {
				a = [2]string{fmt.Sprintf("alert %d", body[1]), "unassigned alert description"}
			}
			out = append(out, field(data, off+1, 1, "alert description", a[0], fmt.Sprintf("description %d: %s", body[1], a[1])))
		}
	case 22:
		if len(body) >= 1 {
			name, ok := handshakeTypes[body[0]]
			if !ok {
				name = fmt.Sprintf("type %d", body[0])
			}
			out = append(out, field(data, off, 1, "handshake type", name, fmt.Sprintf("handshake message type %d", body[0])))
		}
		if len(body) >= 4 {
			n := int(body[1])<<16 | int(body[2])<<8 | int(body[3])
			out = append(out, field(data, off+1, 3, "handshake length", fmt.Sprintf("len %d", n), fmt.Sprintf("handshake message body is %d bytes", n)))
		}
	case 20:
		if len(body) >= 1 {
			out = append(out, field(data, off, 1, "message", "change_cipher_spec", "always 1"))
		}
	}
	return out
}

func field(data []byte, off, n int, name, value, note string) observe.ByteField {
	hex := make([]string, n)
	for i := range n {
		hex[i] = fmt.Sprintf("%02x", data[off+i])
	}
	return observe.ByteField{Offset: off, Length: n, Bytes: strings.Join(hex, " "), Field: name, Value: value, Note: note}
}

// NoApplicationProtocol is the alert a server sends when it supports none of
// the offered ALPN protocols.
const NoApplicationProtocol = 120

// Alert returns the description of the alert data starts with, if any.
func Alert(data []byte) (byte, bool) {
	if len(data) < headerLen+2 || data[0] != 21 || data[1] != 3 || binary.BigEndian.Uint16(data[3:]) != 2 {
		return 0, false
	}
	return data[6], true
}
