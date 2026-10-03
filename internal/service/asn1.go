package service

// A minimal BER/DER tag-length-value reader. The LDAP and Kerberos probes both
// need to walk responses that Go's encoding/asn1 does not parse cleanly:
// application and context tags, SET OF, and GeneralString. This reader only
// splits structure; it never allocates beyond slices into the input.

const (
	classUniversal   = 0
	classApplication = 1
	classContext     = 2
)

type tlv struct {
	class       byte
	constructed bool
	tag         int
	content     []byte
}

// readTLV decodes one element and returns it with the remaining bytes. ok is
// false on any truncation or malformed length, so callers stop on bad input.
func readTLV(b []byte) (elem tlv, rest []byte, ok bool) {
	if len(b) < 2 {
		return tlv{}, nil, false
	}
	first := b[0]
	elem.class = first >> 6
	elem.constructed = first&0x20 != 0
	elem.tag = int(first & 0x1f)
	i := 1
	if elem.tag == 0x1f { // high-tag-number form
		elem.tag = 0
		for {
			if i >= len(b) || i > 4 {
				return tlv{}, nil, false
			}
			elem.tag = elem.tag<<7 | int(b[i]&0x7f)
			more := b[i]&0x80 != 0
			i++
			if !more {
				break
			}
		}
	}
	if i >= len(b) {
		return tlv{}, nil, false
	}
	length := int(b[i])
	i++
	if length&0x80 != 0 { // long-form length
		n := length & 0x7f
		if n == 0 || n > 4 || i+n > len(b) {
			return tlv{}, nil, false
		}
		length = 0
		for range n {
			length = length<<8 | int(b[i])
			i++
		}
	}
	if length < 0 || i+length > len(b) {
		return tlv{}, nil, false
	}
	elem.content = b[i : i+length]
	return elem, b[i+length:], true
}

// children decodes every element directly inside a constructed value.
func children(content []byte) []tlv {
	var out []tlv
	for len(content) > 0 {
		e, rest, ok := readTLV(content)
		if !ok {
			break
		}
		out = append(out, e)
		content = rest
	}
	return out
}
