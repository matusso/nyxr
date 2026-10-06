package probe

import (
	"encoding/asn1"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
)

// An unauthenticated SNMPv3 GET with an empty authoritative engine ID asks
// the agent to return an unknownEngineIDs Report (RFC 3414, section 4).
// Both positive INTEGER fields are replaced with per-attempt IDs in Prepare.
var snmpV3DiscoveryTemplate = []byte{
	0x30, 0x3a, 0x02, 0x01, 0x03, 0x30, 0x0f, 0x02, 0x02, 0x4a, 0x69,
	0x02, 0x03, 0x00, 0xff, 0xe3, 0x04, 0x01, 0x04, 0x02, 0x01, 0x03,
	0x04, 0x10, 0x30, 0x0e, 0x04, 0x00, 0x02, 0x01, 0x00, 0x02, 0x01,
	0x00, 0x04, 0x00, 0x04, 0x00, 0x04, 0x00, 0x30, 0x12, 0x04, 0x00,
	0x04, 0x00, 0xa0, 0x0c, 0x02, 0x02, 0x37, 0xf0, 0x02, 0x01, 0x00,
	0x02, 0x01, 0x00, 0x30, 0x00,
}

// snmpV3ID keeps a two-byte INTEGER positive and minimally encoded: values
// below 0x80 would need a redundant leading zero, which strict BER decoders
// (including encoding/asn1) reject.
func snmpV3ID(v uint16) uint16 {
	v &= 0x7fff
	if v < 0x80 {
		v |= 0x80
	}
	return v
}

type snmpV3Report struct {
	engineID []byte
	boots    int
	time     int
}

func parseSNMPv3Report(request, response []byte) (snmpV3Report, bool) {
	var result snmpV3Report
	var outer asn1.RawValue
	rest, err := asn1.Unmarshal(response, &outer)
	if err != nil || len(rest) != 0 || outer.Class != 0 || outer.Tag != 16 || !outer.IsCompound {
		return result, false
	}
	var version int
	body, err := asn1.Unmarshal(outer.Bytes, &version)
	if err != nil || version != 3 {
		return result, false
	}
	var header asn1.RawValue
	body, err = asn1.Unmarshal(body, &header)
	if err != nil || header.Class != 0 || header.Tag != 16 || !header.IsCompound {
		return result, false
	}
	var msgID, maxSize, securityModel int
	var flags []byte
	h := header.Bytes
	h, err = asn1.Unmarshal(h, &msgID)
	if err != nil || msgID < 0 {
		return result, false
	}
	h, err = asn1.Unmarshal(h, &maxSize)
	if err != nil || maxSize < 484 {
		return result, false
	}
	h, err = asn1.Unmarshal(h, &flags)
	if err != nil || len(flags) != 1 || flags[0]&3 != 0 {
		return result, false
	}
	h, err = asn1.Unmarshal(h, &securityModel)
	if err != nil || len(h) != 0 || securityModel != 3 {
		return result, false
	}
	if len(request) != 0 {
		if len(request) != len(snmpV3DiscoveryTemplate) || msgID != int(binary.BigEndian.Uint16(request[9:11])) {
			return result, false
		}
	}
	var security []byte
	body, err = asn1.Unmarshal(body, &security)
	if err != nil {
		return result, false
	}
	var usm asn1.RawValue
	securityRest, err := asn1.Unmarshal(security, &usm)
	if err != nil || len(securityRest) != 0 || usm.Class != 0 || usm.Tag != 16 || !usm.IsCompound {
		return result, false
	}
	var user, auth, privacy []byte
	u := usm.Bytes
	u, err = asn1.Unmarshal(u, &result.engineID)
	if err != nil || len(result.engineID) < 5 || len(result.engineID) > 32 {
		return snmpV3Report{}, false
	}
	u, err = asn1.Unmarshal(u, &result.boots)
	if err != nil || result.boots < 0 {
		return snmpV3Report{}, false
	}
	u, err = asn1.Unmarshal(u, &result.time)
	if err != nil || result.time < 0 {
		return snmpV3Report{}, false
	}
	u, err = asn1.Unmarshal(u, &user)
	if err != nil {
		return snmpV3Report{}, false
	}
	u, err = asn1.Unmarshal(u, &auth)
	if err != nil {
		return snmpV3Report{}, false
	}
	u, err = asn1.Unmarshal(u, &privacy)
	if err != nil || len(u) != 0 || len(auth) != 0 || len(privacy) != 0 {
		return snmpV3Report{}, false
	}
	var scoped asn1.RawValue
	rest, err = asn1.Unmarshal(body, &scoped)
	if err != nil || len(rest) != 0 || scoped.Class != 0 || scoped.Tag != 16 || !scoped.IsCompound {
		return snmpV3Report{}, false
	}
	var contextEngineID, contextName []byte
	s := scoped.Bytes
	s, err = asn1.Unmarshal(s, &contextEngineID)
	if err != nil {
		return snmpV3Report{}, false
	}
	s, err = asn1.Unmarshal(s, &contextName)
	if err != nil {
		return snmpV3Report{}, false
	}
	var pdu asn1.RawValue
	s, err = asn1.Unmarshal(s, &pdu)
	if err != nil || len(s) != 0 || pdu.Class != 2 || !pdu.IsCompound || (pdu.Tag != 8 && pdu.Tag != 2) {
		return snmpV3Report{}, false
	}
	var requestID, errorStatus, errorIndex int
	p := pdu.Bytes
	p, err = asn1.Unmarshal(p, &requestID)
	if err != nil || requestID < 0 {
		return snmpV3Report{}, false
	}
	p, err = asn1.Unmarshal(p, &errorStatus)
	if err != nil || errorStatus < 0 {
		return snmpV3Report{}, false
	}
	p, err = asn1.Unmarshal(p, &errorIndex)
	if err != nil || errorIndex < 0 {
		return snmpV3Report{}, false
	}
	var varBinds asn1.RawValue
	p, err = asn1.Unmarshal(p, &varBinds)
	if err != nil || len(p) != 0 || varBinds.Class != 0 || varBinds.Tag != 16 || !varBinds.IsCompound {
		return snmpV3Report{}, false
	}
	return result, true
}

func (r snmpV3Report) fields() map[string]string {
	fields := map[string]string{
		"snmp.version":             "3",
		"snmp.engine_id":           colonHex(r.engineID),
		"snmp.engine_boots":        strconv.Itoa(r.boots),
		"snmp.engine_time_seconds": strconv.Itoa(r.time),
		"snmp.engine_time":         fmt.Sprintf("%d days, %d:%02d:%02d", r.time/86400, r.time%86400/3600, r.time%3600/60, r.time%60),
	}
	if r.engineID[0]&0x80 != 0 {
		enterprise := binary.BigEndian.Uint32(r.engineID[:4]) & 0x7fffffff
		fields["snmp.enterprise"] = strconv.FormatUint(uint64(enterprise), 10)
		format := r.engineID[4]
		switch format {
		case 1:
			fields["snmp.engine_id_format"] = "ipv4"
		case 2:
			fields["snmp.engine_id_format"] = "ipv6"
		case 3:
			fields["snmp.engine_id_format"] = "mac"
		case 4:
			fields["snmp.engine_id_format"] = "text"
		case 5:
			fields["snmp.engine_id_format"] = "octets"
		default:
			fields["snmp.engine_id_format"] = strconv.Itoa(int(format))
		}
		if format == 4 {
			fields["snmp.engine_id_data"] = string(r.engineID[5:])
		} else {
			fields["snmp.engine_id_data"] = colonHex(r.engineID[5:])
		}
	}
	return fields
}

func colonHex(value []byte) string {
	parts := make([]string, len(value))
	for i, b := range value {
		parts[i] = hex.EncodeToString([]byte{b})
	}
	return strings.Join(parts, ":")
}
