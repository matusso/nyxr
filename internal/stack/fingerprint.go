// Package stack implements Nyxr-native, conservative TCP/IP fingerprints.
// It consumes only replies already correlated by discovery; it sends nothing.
package stack

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"

	"github.com/matusso/nyxr/internal/observe"
	"github.com/matusso/nyxr/internal/packet"
)

const MaxSamples = 8
const ProbeProfile = "nyxr-syn-v1"

// Sample owns all retained values; no bytes alias a packet receive buffer.
func Sample(p packet.Decoded) observe.StackSample {
	s := observe.StackSample{Received: p.Received, Response: "other", IPVersion: p.IPVersion,
		TTL: p.TTL, InitialTTL: initialTTL(p.TTL), Window: p.TCPWindow, Flags: p.TCPFlags,
		Sequence: p.TCPSeq, Acknowledgment: p.TCPAck, OptionsValid: true, ECN: "not-negotiated"}
	if p.TCPFlags&0x12 == 0x12 {
		s.Response = "syn-ack"
	}
	if p.TCPFlags&4 != 0 {
		s.Response = "rst-ack"
	}
	if p.IPVersion == 4 {
		df, id := p.DF, p.IPID
		s.DF, s.IPID = &df, &id
	}
	if s.Response == "syn-ack" && p.TCPFlags&0xc0 == 0x40 {
		s.ECN = "negotiated"
	}
	if p.TCPFlags&0x80 != 0 {
		s.ECN = "unexpected-cwr"
	}
	if int(p.TCPOptionsLen) > len(p.TCPOptions) {
		s.OptionsValid = false
		return s
	}
	raw := p.TCPOptions[:p.TCPOptionsLen]
	s.OptionsHex = hex.EncodeToString(raw)
	seen := map[byte]bool{}
	for at := 0; at < len(raw); {
		kind := raw[at]
		s.OptionOrder = append(s.OptionOrder, int(kind))
		if kind == 0 {
			break
		}
		if kind == 1 {
			at++
			continue
		}
		if at+2 > len(raw) || raw[at+1] < 2 || at+int(raw[at+1]) > len(raw) {
			s.OptionsValid = false
			break
		}
		n := int(raw[at+1])
		data := raw[at+2 : at+n]
		if seen[kind] {
			s.OptionsValid = false
		}
		seen[kind] = true
		switch kind {
		case 2:
			if n != 4 {
				s.OptionsValid = false
			} else {
				v := binary.BigEndian.Uint16(data)
				s.MSS = &v
				if v == 0 {
					s.OptionsValid = false
				}
			}
		case 3:
			if n != 3 {
				s.OptionsValid = false
			} else {
				v := data[0]
				s.WindowScale = &v
				if v > 14 {
					s.OptionsValid = false
				}
			}
		case 4:
			if n != 2 {
				s.OptionsValid = false
			} else {
				s.SACK = true
			}
		case 8:
			if n != 10 {
				s.OptionsValid = false
			} else {
				v, e := binary.BigEndian.Uint32(data[:4]), binary.BigEndian.Uint32(data[4:])
				s.TimestampValue, s.TimestampEcho = &v, &e
			}
		}
		at += n
	}
	return s
}

func initialTTL(ttl uint8) uint8 {
	if ttl == 0 {
		return 0
	}
	for _, v := range []uint8{32, 64, 128, 255} {
		if ttl <= v {
			return v
		}
	}
	return 255
}

// Analyze runs off the packet hot path. Multiple samples describe behavior
// within one probe's deadline, never an exhaustive retransmission policy.
func Analyze(f *observe.TCPStack) {
	if f == nil || len(f.Samples) == 0 {
		return
	}
	sort.SliceStable(f.Samples, func(i, j int) bool { return f.Samples[i].Received.Before(f.Samples[j].Received) })
	f.ProbeProfile, f.Status = ProbeProfile, observe.FingerprintUnknown
	f.Candidates, f.RepeatIntervals = nil, nil
	f.IPIDBehavior, f.RetransmissionBehavior, f.RSTBehavior = "insufficient-samples", "not-observed", "not-observed"
	first := f.Samples[0]
	key := signatureKey(first)
	sum := sha256.Sum256([]byte(key))
	f.Signature = "nx_tcp_v1_" + hex.EncodeToString(sum[:12])
	consistent := true
	for i, s := range f.Samples {
		if signatureKey(s) != key {
			consistent = false
		}
		if s.Response == "rst-ack" {
			f.RSTBehavior = "acknowledged-reset"
			if s.Window == 0 && len(s.OptionOrder) == 0 {
				f.RSTBehavior = "acknowledged-reset-zero-window-no-options"
			}
		}
		if i > 0 {
			prev := f.Samples[i-1]
			if s.Response == "syn-ack" && prev.Response == s.Response && s.Sequence == prev.Sequence && s.Acknowledgment == prev.Acknowledgment {
				f.RetransmissionBehavior = "duplicate-or-retransmitted-syn-ack"
				f.RepeatIntervals = append(f.RepeatIntervals, s.Received.Sub(prev.Received))
			}
		}
	}
	f.IPIDBehavior = ipIDBehavior(f.Samples)
	if consistent && !f.Truncated {
		f.Candidates = classify(first)
	}
	if len(f.Candidates) > 0 {
		f.Status = observe.FingerprintMatched
	}
}

func signatureKey(s observe.StackSample) string {
	var mss, ws any = "absent", "absent"
	if s.MSS != nil {
		mss = *s.MSS
	}
	if s.WindowScale != nil {
		ws = *s.WindowScale
	}
	df := "n/a"
	if s.DF != nil {
		df = fmt.Sprint(*s.DF)
	}
	// Exclude hop distance, sequence tokens, IDs, timestamp counters and times.
	// Preserve unknown option bytes so different proprietary options do not
	// collapse; normalize only the timestamp value and echo.
	raw, _ := hex.DecodeString(s.OptionsHex)
	for at := 0; at < len(raw); {
		kind := raw[at]
		if kind == 0 {
			break
		}
		if kind == 1 {
			at++
			continue
		}
		if at+2 > len(raw) || raw[at+1] < 2 || at+int(raw[at+1]) > len(raw) {
			break
		}
		n := int(raw[at+1])
		if kind == 8 && n == 10 {
			clear(raw[at+2 : at+n])
		}
		at += n
	}
	return fmt.Sprintf("%s|%d|%d|%s|%d|%d|%v|%v|%t|%s|%t", s.Response, s.IPVersion, s.InitialTTL, df, s.Window, s.Flags, mss, ws, s.SACK, hex.EncodeToString(raw), s.OptionsValid)
}

func classify(s observe.StackSample) []observe.StackCandidate {
	// TTL alone, resets, or generic tiny windows are not OS signatures.
	if s.Response != "syn-ack" || !s.OptionsValid || s.InitialTTL == 0 || s.MSS == nil || s.WindowScale == nil || !s.SACK || s.Window == 0 || s.Flags&^uint8(0x52) != 0 {
		return nil
	}
	order := make([]string, 0, len(s.OptionOrder))
	for _, k := range s.OptionOrder {
		if k == 0 {
			break
		}
		order = append(order, fmt.Sprint(k))
	}
	var family string
	var confidence int
	switch strings.Join(order, ",") {
	case "2,4,8,1,3", "2,1,1,4,1,3":
		if s.InitialTTL == 64 {
			family, confidence = "Linux", 70
		}
	case "2,1,3,1,1,4":
		if s.InitialTTL == 128 {
			family, confidence = "Windows", 65
		}
	case "2,1,3,1,1,8,4":
		if s.InitialTTL == 64 {
			family, confidence = "BSD/macOS", 60
		}
	}
	if family == "" {
		return nil
	}
	return []observe.StackCandidate{{Family: family, Confidence: confidence, Reasons: []string{
		"native SYN/ACK option-order rule", fmt.Sprintf("estimated initial TTL %d (observed %d)", s.InitialTTL, s.TTL),
		"MSS, SACK and window scaling observed; OS versions and intermediary roles remain unverified"}}}
}

func ipIDBehavior(samples []observe.StackSample) string {
	if samples[0].IPVersion != 4 {
		return "not-applicable"
	}
	if len(samples) < 2 {
		return "insufficient-samples"
	}
	zero, same, increasing := true, true, true
	for i, s := range samples {
		if s.IPID == nil {
			return "insufficient-samples"
		}
		zero = zero && *s.IPID == 0
		same = same && *s.IPID == *samples[0].IPID
		if i > 0 {
			delta := *s.IPID - *samples[i-1].IPID
			increasing = increasing && delta > 0 && delta <= 1024
		}
	}
	if zero {
		return "zero"
	}
	if same {
		return "constant"
	}
	if increasing {
		return "increasing"
	}
	return "varying"
}
