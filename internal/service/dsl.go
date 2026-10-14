package service

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/matusso/nyxr/internal/observe"
	"gopkg.in/yaml.v3"
)

// ProtocolDefinition is an immutable, validated nyxr/protocol/v1 state machine.
// A definition is loaded for each scan, so editing a file needs no rebuild.
type ProtocolDefinition struct {
	Name, Transport, Schema  string
	Provenance, SourceSHA256 string
	Ports                    []uint16
	Timeout                  time.Duration
	steps                    []protocolStep
}

type protocolDocument struct {
	Schema     string         `yaml:"schema"`
	Protocol   string         `yaml:"protocol"`
	Module     string         `yaml:"module"`
	Extends    string         `yaml:"extends"`
	Modules    []string       `yaml:"modules"`
	Transport  string         `yaml:"transport"`
	Ports      []uint16       `yaml:"ports"`
	Timeout    string         `yaml:"timeout"`
	Provenance string         `yaml:"provenance"`
	Steps      []protocolStep `yaml:"steps"`
	sourceHash string
}

type payloadSpec struct {
	Text   string `yaml:"text"`
	Hex    string `yaml:"hex"`
	Base64 string `yaml:"base64"`
}

type expectSpec struct {
	Hex    string `yaml:"hex"`
	Prefix string `yaml:"prefix"`
	Regex  string `yaml:"regex"`
	Offset int    `yaml:"offset"`
}

type lengthSpec struct {
	Offset int    `yaml:"offset"`
	Bytes  int    `yaml:"bytes"`
	Order  string `yaml:"order"`
	Add    *int   `yaml:"add"`
}

type receiveSpec struct {
	MaxBytes int         `yaml:"max_bytes"`
	Length   *lengthSpec `yaml:"length"`
}

type repeatSpec struct {
	From  string `yaml:"from"`
	Count int    `yaml:"count"`
}

type protocolStep struct {
	Label    string            `yaml:"label"`
	Send     *payloadSpec      `yaml:"send"`
	Receive  *receiveSpec      `yaml:"receive"`
	Expect   *expectSpec       `yaml:"expect"`
	StartTLS bool              `yaml:"start_tls"`
	TLS      bool              `yaml:"tls"`
	DTLS     bool              `yaml:"dtls"`
	QUIC     bool              `yaml:"quic"`
	Extract  map[string]string `yaml:"extract"`
	Set      map[string]string `yaml:"set"`
	Repeat   *repeatSpec       `yaml:"repeat"`
	OnMatch  string            `yaml:"on_match"`
	OnMiss   string            `yaml:"on_miss"`
	data     []byte
	re       *regexp.Regexp
	extract  map[string]*regexp.Regexp
}

// LoadProtocolFile compiles a bounded, strict YAML document before traffic is sent.
func LoadProtocolFile(path string) (ProtocolDefinition, error) {
	f, err := os.Open(path)
	if err != nil {
		return ProtocolDefinition{}, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, 1<<20+1))
	if err != nil {
		return ProtocolDefinition{}, err
	}
	if len(data) > 1<<20 {
		return ProtocolDefinition{}, errors.New("protocol definition exceeds 1 MiB")
	}
	return ParseProtocol(bytes.NewReader(data))
}

func ParseProtocol(r io.Reader) (ProtocolDefinition, error) {
	d, err := decodeProtocol(r)
	if err != nil {
		return ProtocolDefinition{}, err
	}
	if d.Extends != "" || len(d.Modules) != 0 || d.Module != "" {
		return ProtocolDefinition{}, errors.New("protocol dependencies require a registry")
	}
	return compileProtocol(d)
}

func decodeProtocol(r io.Reader) (protocolDocument, error) {
	var d protocolDocument
	data, err := io.ReadAll(io.LimitReader(r, 1<<20+1))
	if err != nil {
		return protocolDocument{}, err
	}
	if len(data) > 1<<20 {
		return protocolDocument{}, errors.New("protocol definition exceeds 1 MiB")
	}
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&d); err != nil {
		return protocolDocument{}, err
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		return protocolDocument{}, errors.New("protocol file must contain exactly one YAML document")
	}
	d.sourceHash = fmt.Sprintf("%x", sha256.Sum256(data))
	return d, nil
}

var protocolNameRE = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,63}$`)

func compileProtocol(d protocolDocument) (ProtocolDefinition, error) {
	if (d.Schema != "nyxr/protocol/v1" && d.Schema != "nyxr/protocol/v2") || !protocolNameRE.MatchString(d.Protocol) {
		return ProtocolDefinition{}, errors.New("protocol requires schema nyxr/protocol/v1 or nyxr/protocol/v2 and a lowercase name")
	}
	if d.Schema == "nyxr/protocol/v1" && (d.Extends != "" || len(d.Modules) != 0 || d.Module != "") {
		return ProtocolDefinition{}, errors.New("v1 does not support inheritance or modules")
	}
	if len(d.Provenance) > 256 {
		return ProtocolDefinition{}, errors.New("protocol provenance exceeds 256 bytes")
	}
	if d.Transport != "tcp" && d.Transport != "udp" {
		return ProtocolDefinition{}, errors.New("protocol transport must be tcp or udp")
	}
	if len(d.Ports) == 0 || len(d.Ports) > 32 || len(d.Steps) == 0 || len(d.Steps) > 32 {
		return ProtocolDefinition{}, errors.New("protocol requires 1..32 ports and 1..32 steps")
	}
	seenPorts := map[uint16]bool{}
	for _, port := range d.Ports {
		if port == 0 || seenPorts[port] {
			return ProtocolDefinition{}, errors.New("protocol ports must be nonzero and unique")
		}
		seenPorts[port] = true
	}
	timeout := 3 * time.Second
	if d.Timeout != "" {
		var err error
		timeout, err = time.ParseDuration(d.Timeout)
		if err != nil || timeout < time.Millisecond || timeout > 30*time.Second {
			return ProtocolDefinition{}, errors.New("protocol timeout must be 1ms..30s")
		}
	}
	labels := map[string]int{}
	hasExpect := false
	for i := range d.Steps {
		s := &d.Steps[i]
		if s.Label != "" {
			if labels[s.Label] != 0 {
				return ProtocolDefinition{}, fmt.Errorf("duplicate label %q", s.Label)
			}
			labels[s.Label] = i + 1
		}
		actions := 0
		for _, active := range []bool{s.Send != nil, s.Receive != nil, s.Expect != nil, s.StartTLS, s.TLS, s.DTLS, s.QUIC, s.Extract != nil, s.Set != nil, s.Repeat != nil} {
			if active {
				actions++
			}
		}
		if actions != 1 {
			return ProtocolDefinition{}, fmt.Errorf("step %d requires exactly one action", i+1)
		}
		if d.Schema == "nyxr/protocol/v1" && (s.TLS || s.DTLS || s.QUIC) {
			return ProtocolDefinition{}, fmt.Errorf("step %d: transport actions require v2", i+1)
		}
		if s.TLS && d.Transport != "tcp" || (s.DTLS || s.QUIC) && d.Transport != "udp" {
			return ProtocolDefinition{}, fmt.Errorf("step %d: transport action does not match %s", i+1, d.Transport)
		}
		if s.TLS && i != 0 {
			return ProtocolDefinition{}, fmt.Errorf("step %d: tls must be the first step", i+1)
		}
		if s.DTLS || s.QUIC {
			if len(d.Steps) != 1 {
				return ProtocolDefinition{}, fmt.Errorf("step %d: dtls/quic must be the only step", i+1)
			}
			if s.DTLS && d.Protocol != "dtls" || s.QUIC && d.Protocol != "quic" {
				return ProtocolDefinition{}, fmt.Errorf("step %d: native transport identity must be named dtls or quic", i+1)
			}
			hasExpect = true // the native handshake supplies observed identity
		}
		if s.Send != nil {
			var err error
			s.data, err = decodePayload(*s.Send)
			if err != nil || len(s.data) == 0 || len(s.data) > 4096 {
				return ProtocolDefinition{}, fmt.Errorf("step %d: send requires 1..4096 text, hex or base64 bytes", i+1)
			}
		}
		if s.Receive != nil {
			if s.Receive.MaxBytes < 1 || s.Receive.MaxBytes > 4096 {
				return ProtocolDefinition{}, fmt.Errorf("step %d: receive max_bytes must be 1..4096", i+1)
			}
			if l := s.Receive.Length; l != nil && (l.Bytes != 1 && l.Bytes != 2 && l.Bytes != 4 || l.Offset < 0 || l.Offset+l.Bytes > s.Receive.MaxBytes || l.Order != "big" && l.Order != "little") {
				return ProtocolDefinition{}, fmt.Errorf("step %d: invalid length field", i+1)
			}
			if l := s.Receive.Length; l != nil && l.Add != nil {
				if d.Schema != "nyxr/protocol/v2" || *l.Add < -4096 || *l.Add > 4096 {
					return ProtocolDefinition{}, fmt.Errorf("step %d: invalid v2 length arithmetic", i+1)
				}
			}
		}
		if s.StartTLS && d.Transport != "tcp" {
			return ProtocolDefinition{}, fmt.Errorf("step %d: start_tls requires tcp", i+1)
		}
		if s.Expect != nil {
			hasExpect = true
			if s.Expect.Offset < 0 {
				return ProtocolDefinition{}, fmt.Errorf("step %d: negative offset", i+1)
			}
			var err error
			s.data, s.re, err = compileExpect(*s.Expect)
			if err != nil {
				return ProtocolDefinition{}, fmt.Errorf("step %d: %w", i+1, err)
			}
		} else if s.OnMatch != "" || s.OnMiss != "" {
			return ProtocolDefinition{}, fmt.Errorf("step %d: branches require expect", i+1)
		}
		if s.Extract != nil {
			if len(s.Extract) == 0 || len(s.Extract) > 16 {
				return ProtocolDefinition{}, fmt.Errorf("step %d: extract requires 1..16 fields", i+1)
			}
			s.extract = make(map[string]*regexp.Regexp, len(s.Extract))
			for name, pattern := range s.Extract {
				if !validFieldName(name) || len(pattern) > 512 {
					return ProtocolDefinition{}, fmt.Errorf("step %d: invalid extract field %q", i+1, name)
				}
				re, err := regexp.Compile(pattern)
				if err != nil {
					return ProtocolDefinition{}, fmt.Errorf("step %d: %w", i+1, err)
				}
				s.extract[name] = re
			}
		}
		if s.Set != nil {
			if len(s.Set) == 0 || len(s.Set) > 16 {
				return ProtocolDefinition{}, fmt.Errorf("step %d: set requires 1..16 fields", i+1)
			}
			for name, value := range s.Set {
				if !validFieldName(name) || len(value) > 256 {
					return ProtocolDefinition{}, fmt.Errorf("step %d: invalid set field %q", i+1, name)
				}
			}
		}
	}
	if !hasExpect {
		return ProtocolDefinition{}, errors.New("protocol requires an expect step to support an identity claim")
	}
	for i, s := range d.Steps {
		for _, label := range []string{s.OnMatch, s.OnMiss} {
			if label != "" && labels[label] <= i+1 {
				return ProtocolDefinition{}, fmt.Errorf("step %d: branch %q must point forward", i+1, label)
			}
		}
		if s.Repeat != nil && (s.Repeat.Count < 2 || s.Repeat.Count > 4 || labels[s.Repeat.From] == 0 || labels[s.Repeat.From] > i) {
			return ProtocolDefinition{}, fmt.Errorf("step %d: repeat requires an earlier label and count 2..4", i+1)
		}
	}
	return ProtocolDefinition{Name: d.Protocol, Transport: d.Transport, Schema: d.Schema, Provenance: d.Provenance,
		SourceSHA256: d.sourceHash, Ports: d.Ports, Timeout: timeout, steps: d.Steps}, nil
}

func decodePayload(p payloadSpec) ([]byte, error) {
	n := 0
	for _, v := range []string{p.Text, p.Hex, p.Base64} {
		if v != "" {
			n++
		}
	}
	if n != 1 {
		return nil, errors.New("exactly one encoding required")
	}
	if p.Text != "" {
		return []byte(p.Text), nil
	}
	if p.Hex != "" {
		return hex.DecodeString(strings.Join(strings.Fields(p.Hex), ""))
	}
	return base64.StdEncoding.DecodeString(p.Base64)
}

var fieldNameRE = regexp.MustCompile(`^[a-z][a-z0-9_.-]{0,63}$`)

func validFieldName(name string) bool { return fieldNameRE.MatchString(name) }

func compileExpect(e expectSpec) ([]byte, *regexp.Regexp, error) {
	n := 0
	for _, v := range []string{e.Hex, e.Prefix, e.Regex} {
		if v != "" {
			n++
		}
	}
	if n != 1 {
		return nil, nil, errors.New("expect requires exactly one of hex, prefix or regex")
	}
	if e.Hex != "" {
		b, err := hex.DecodeString(strings.Join(strings.Fields(e.Hex), ""))
		if err != nil || len(b) == 0 || len(b) > 4096 {
			return nil, nil, errors.New("invalid expect hex")
		}
		return b, nil, nil
	}
	if e.Prefix != "" {
		return []byte(e.Prefix), nil, nil
	}
	if len(e.Regex) > 512 {
		return nil, nil, errors.New("expect regex too long")
	}
	re, err := regexp.Compile(e.Regex)
	if err == nil && re.Match(nil) {
		return nil, nil, errors.New("expect regex must not match an empty response")
	}
	return nil, re, err
}

func (s protocolStep) matches(response []byte) bool {
	if len(response) == 0 {
		return false
	}
	if s.Expect.Offset > len(response) {
		return false
	}
	b := response[s.Expect.Offset:]
	if s.re != nil {
		return s.re.Match(b)
	}
	return bytes.HasPrefix(b, s.data)
}

func (e *Engine) probeProtocol(ctx context.Context, t Target, d ProtocolDefinition, o *observe.Observation) bool {
	name := "dsl/" + d.Name
	if len(d.steps) == 1 && (d.steps[0].DTLS || d.steps[0].QUIC) {
		probeCtx, cancel := context.WithTimeout(ctx, min(e.cfg.Timeout, d.Timeout))
		defer cancel()
		firstEvidence := len(o.Evidence)
		matched := false
		if d.steps[0].DTLS {
			matched = e.probeDTLS(probeCtx, t, o)
		} else {
			matched = e.probeQUIC(probeCtx, t, o)
		}
		if matched {
			o.Probe = name
			o.Evidence[firstEvidence].Matched = name
			e.protocolMetadata(d, o)
		}
		return matched
	}
	limit := min(e.cfg.Timeout, d.Timeout)
	ev := observe.Evidence{Probe: name, Layer: d.Transport, Started: time.Now().UTC()}
	if err := e.pacer.wait(ctx); err != nil {
		ev.Error = errorText(err)
		o.Evidence = append(o.Evidence, ev)
		return false
	}
	dctx, cancel := context.WithTimeout(ctx, limit)
	defer cancel()
	conn, err := e.cfg.Dial(dctx, d.Transport, net.JoinHostPort(t.Addr.String(), fmt.Sprint(t.Port)))
	if err != nil {
		ev.Error, ev.Duration = errorText(err), time.Since(ev.Started)
		o.Evidence = append(o.Evidence, ev)
		return false
	}
	defer conn.Close()
	rc := e.record(conn)
	var active net.Conn = rc
	stop := deadline(ctx, rc, limit)
	defer stop()
	var last []byte
	matched := false
	end := time.Now().Add(limit)
	if cd, ok := ctx.Deadline(); ok && cd.Before(end) {
		end = cd
	}
	labels := map[string]int{}
	repeats := map[int]int{}
	for i, s := range d.steps {
		if s.Label != "" {
			labels[s.Label] = i
		}
	}
	executed, i := 0, 0
	for ; i < len(d.steps) && executed < 128; i++ {
		executed++
		s := d.steps[i]
		switch {
		case s.Send != nil:
			_, err = writeProtocol(active, s.data)
		case s.Receive != nil:
			last, err = receiveProtocol(active, s.Receive)
			if s.Receive.Length == nil && len(last) > 0 && (errors.Is(err, os.ErrDeadlineExceeded) || errors.Is(err, io.EOF)) {
				err = nil
			}
			_ = active.SetReadDeadline(end)
		case s.StartTLS:
			if d.Transport != "tcp" {
				err = errors.New("start_tls requires tcp")
				break
			}
			tc := tls.Client(active, &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS10}) // identify peer; do not assert trust
			err = tc.HandshakeContext(dctx)
			if err == nil {
				o.TLS = summarizeTLS(tc.ConnectionState())
				active = tc
			}
		case s.TLS:
			tc := tls.Client(active, &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS10}) // discovery records identity, not trust
			err = tc.HandshakeContext(dctx)
			if err == nil {
				o.TLS = summarizeTLS(tc.ConnectionState())
				active = tc
			}
		case s.Expect != nil:
			if s.matches(last) {
				matched = true
				if s.OnMatch != "" {
					i = labels[s.OnMatch] - 1
				}
			} else if s.OnMiss != "" {
				matched = false
				i = labels[s.OnMiss] - 1
			} else {
				matched = false
				i = len(d.steps)
			}
		case s.Extract != nil:
			if o.Attributes == nil {
				o.Attributes = map[string]string{}
			}
			for name, re := range s.extract {
				parts := re.FindSubmatch(last)
				if len(parts) > 0 {
					value := parts[0]
					if len(parts) > 1 {
						value = parts[1]
					}
					o.Attributes[name] = printable(value, 256)
				}
			}
		case s.Set != nil:
			if matched {
				if o.Attributes == nil {
					o.Attributes = map[string]string{}
				}
				for name, value := range s.Set {
					o.Attributes[name] = value
				}
			}
		case s.Repeat != nil:
			repeats[i]++
			if repeats[i] < s.Repeat.Count {
				i = labels[s.Repeat.From] - 1
			}
		}
		if err != nil {
			break
		}
	}
	if i < len(d.steps) && executed >= 128 {
		err = errors.New("protocol step budget exceeded")
	}
	e.finish(&ev, rc, err)
	if matched && err == nil {
		ev.Matched = name
		o.Service, o.Probe, o.Reason = d.Name, name, "protocol DSL response matched"
		e.protocolMetadata(d, o)
	}
	o.Evidence = append(o.Evidence, ev)
	return matched && err == nil
}

func (e *Engine) protocolMetadata(d ProtocolDefinition, o *observe.Observation) {
	if o.Attributes == nil {
		o.Attributes = map[string]string{}
	}
	o.Attributes["protocol.schema"] = d.Schema
	if d.SourceSHA256 != "" {
		o.Attributes["protocol.definition_sha256"] = d.SourceSHA256
	}
	if d.Provenance != "" {
		o.Attributes["protocol.provenance"] = d.Provenance
	}
	if e.cfg.RegistryVersion != 0 {
		o.Attributes["protocol.registry_version"] = fmt.Sprint(e.cfg.RegistryVersion)
	}
}

func writeProtocol(c net.Conn, data []byte) (int, error) {
	total := 0
	for total < len(data) {
		n, err := c.Write(data[total:])
		total += n
		if err != nil {
			return total, err
		}
		if n == 0 {
			return total, io.ErrShortWrite
		}
	}
	return total, nil
}

func receiveProtocol(c net.Conn, s *receiveSpec) ([]byte, error) {
	if s.Length == nil {
		return readSome(c, s.MaxBytes, 100*time.Millisecond)
	}
	l := s.Length
	head := make([]byte, l.Offset+l.Bytes)
	if n, err := io.ReadFull(c, head); err != nil {
		return head[:n], err
	}
	var n uint32
	b := head[l.Offset:]
	if l.Order == "little" {
		switch l.Bytes {
		case 1:
			n = uint32(b[0])
		case 2:
			n = uint32(binary.LittleEndian.Uint16(b))
		case 4:
			n = binary.LittleEndian.Uint32(b)
		}
	} else {
		switch l.Bytes {
		case 1:
			n = uint32(b[0])
		case 2:
			n = uint32(binary.BigEndian.Uint16(b))
		case 4:
			n = binary.BigEndian.Uint32(b)
		}
	}
	wanted := int64(n)
	if l.Add != nil {
		wanted += int64(*l.Add)
	}
	if wanted < 0 || wanted > int64(s.MaxBytes-len(head)) {
		return head, errors.New("response length exceeds protocol limit")
	}
	frame := make([]byte, len(head)+int(wanted))
	copy(frame, head)
	nread, err := io.ReadFull(c, frame[len(head):])
	return frame[:len(head)+nread], err
}
