package horizon

import (
	"github.com/matusso/nyxr/internal/horizon/model"
	"github.com/matusso/nyxr/internal/packet"
)

const correlationVersion = "tuple-token-v2"

// correlateRich never equates a token-only path/NAT candidate with an exact
// response. It validates lengths, extensions, IP and transport checksums first.
func correlateRich(frame []byte, sent packet.ForgeSpec) (model.Features, bool) {
	p, ok := packet.DecodeResearch(frame)
	if !ok || !p.ValidChecksum() {
		return model.Features{}, false
	}
	return correlateDecoded(p, sent)
}

func correlateDecoded(p packet.ResearchDecoded, sent packet.ForgeSpec) (model.Features, bool) {
	f := model.Features{}
	if p.Destination != sent.SourceIP {
		return f, false
	}
	f.TTL, f.ResponseSource, f.Correlation = p.TTL, p.Source.String(), "exact"
	switch p.Protocol {
	case 6:
		if p.DestPort != sent.SourcePort || p.TCPAck != sent.Sequence+1 || !validOptions(p.TCPOptions) {
			return model.Features{}, false
		}
		switch p.TCPFlags {
		case 0x12, 0x52:
			f.ResponseClass = "syn-ack"
		case 0x14:
			f.ResponseClass = "rst-ack"
		default:
			return model.Features{}, false
		}
		f.TCPOptions = append([]byte(nil), p.TCPOptions...)
		if p.Source != sent.DestinationIP || p.SourcePort != sent.DestPort {
			f.Correlation = "ambiguous-path"
		}
	case 1, 58:
		q := p.Quote
		if !q.Valid || q.Protocol != 6 || !q.SequencePresent || q.Sequence != sent.Sequence || q.DestPort != sent.DestPort {
			return model.Features{}, false
		}
		f.ResponseClass, f.ICMPType, f.ICMPCode = "icmp-error", p.ICMPType, p.ICMPCode
		if q.Source != sent.SourceIP || q.Destination != sent.DestinationIP || q.SourcePort != sent.SourcePort {
			f.Correlation = "ambiguous-path"
		}
	default:
		return model.Features{}, false
	}
	return f, true
}

func receiveFlags(flags []string, f model.Features) []string {
	if f.Correlation == "ambiguous-path" {
		flags = appendUnique(flags, "ambiguous-correlation")
	}
	if f.ResponseClass == "icmp-error" {
		flags = appendUnique(flags, "icmp-error")
	}
	return flags
}
