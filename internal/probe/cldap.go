package probe

import (
	"encoding/asn1"
	"encoding/hex"
	"strconv"
	"strings"
	"unicode/utf8"
)

func cldapIDOffset(request []byte) (int, bool) {
	if len(request) < 5 || request[0] != 0x30 {
		return 0, false
	}
	pos := 2
	if request[1]&0x80 != 0 {
		n := int(request[1] & 0x7f)
		if n < 1 || n > 2 || len(request) < 2+n+3 {
			return 0, false
		}
		pos += n
	}
	if len(request)-pos < 3 || request[pos] != 2 || request[pos+1] != 1 {
		return 0, false
	}
	return pos + 2, true
}

// cldapReply accepts both the connectionless SEQUENCE OF responses in RFC 1798
// and the LDAPMessage responses commonly sent over UDP by directory servers.
func cldapReply(response []byte, wantedID int) (map[string]string, bool) {
	fields := make(map[string]string)
	matched := false
	for len(response) > 0 {
		var message asn1.RawValue
		rest, err := asn1.Unmarshal(response, &message)
		if err != nil || message.Class != 0 || message.Tag != 16 || len(rest) == len(response) {
			return nil, false
		}
		response = rest
		var id int
		body, err := asn1.Unmarshal(message.Bytes, &id)
		if err != nil || (wantedID >= 0 && id != wantedID) {
			return nil, false
		}
		var op asn1.RawValue
		remaining, err := asn1.Unmarshal(body, &op)
		if err != nil || len(remaining) != 0 {
			return nil, false
		}
		if op.Class == 0 && op.Tag == 16 {
			for nested := op.Bytes; len(nested) > 0; {
				var entry asn1.RawValue
				nested, err = asn1.Unmarshal(nested, &entry)
				if err != nil || !cldapSearchResponse(entry, fields) {
					return nil, false
				}
				matched = true
			}
		} else {
			if !cldapSearchResponse(op, fields) {
				return nil, false
			}
			matched = true
		}
	}
	return fields, matched
}

func cldapSearchResponse(op asn1.RawValue, fields map[string]string) bool {
	if op.Class != 1 || !op.IsCompound {
		return false
	}
	switch op.Tag {
	case 4: // SearchResultEntry
		var dn []byte
		rest, err := asn1.Unmarshal(op.Bytes, &dn)
		if err != nil {
			return false
		}
		if len(dn) > 0 {
			fields["cldap.dn"] = cldapValue(dn)
		}
		var attrs asn1.RawValue
		rest, err = asn1.Unmarshal(rest, &attrs)
		if err != nil || len(rest) != 0 || attrs.Class != 0 || attrs.Tag != 16 {
			return false
		}
		for list := attrs.Bytes; len(list) > 0; {
			var attr asn1.RawValue
			list, err = asn1.Unmarshal(list, &attr)
			if err != nil || attr.Class != 0 || attr.Tag != 16 {
				return false
			}
			var name []byte
			values, err := asn1.Unmarshal(attr.Bytes, &name)
			if err != nil {
				return false
			}
			key, ok := cldapKey(name)
			if !ok {
				continue
			}
			var set asn1.RawValue
			remaining, err := asn1.Unmarshal(values, &set)
			if err != nil || len(remaining) != 0 || set.Class != 0 || set.Tag != 17 {
				return false
			}
			var vals []string
			for raw := set.Bytes; len(raw) > 0; {
				var value []byte
				raw, err = asn1.Unmarshal(raw, &value)
				if err != nil {
					return false
				}
				vals = append(vals, cldapValue(value))
			}
			if len(vals) > 0 && len(fields) < 256 {
				fields["cldap."+key] = strings.Join(vals, ", ")
			}
		}
		return true
	case 5: // SearchResultDone
		var result asn1.RawValue
		_, err := asn1.Unmarshal(op.Bytes, &result)
		if err != nil || result.Tag != 10 || len(result.Bytes) != 1 {
			return false
		}
		fields["cldap.result_code"] = strconv.Itoa(int(result.Bytes[0]))
		return true
	}
	return false
}

func cldapKey(name []byte) (string, bool) {
	if len(name) == 0 || len(name) > 64 {
		return "", false
	}
	for _, b := range name {
		if !((b >= 'A' && b <= 'Z') || (b >= 'a' && b <= 'z') ||
			(b >= '0' && b <= '9') || b == '-' || b == '.') {
			return "", false
		}
	}
	return strings.ToLower(string(name)), true
}

func cldapValue(value []byte) string {
	if !utf8.Valid(value) {
		return "0x" + hex.EncodeToString(value)
	}
	for _, b := range value {
		if b < 0x20 && b != '\t' && b != '\n' && b != '\r' {
			return "0x" + hex.EncodeToString(value)
		}
	}
	return string(value)
}

func cldapAttributes(response []byte) map[string]string {
	fields, _ := cldapReply(response, -1)
	return fields
}
