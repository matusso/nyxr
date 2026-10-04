package pipeline

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/matusso/nyxr/internal/observe"
	"github.com/matusso/nyxr/internal/storage"
	"github.com/matusso/nyxr/internal/ui"
)

// JSONSink writes newline-delimited records. The final line is the scan
// summary; readers distinguish records by their "kind" field.
type JSONSink struct{ enc *json.Encoder }

func NewJSONSink(w io.Writer) *JSONSink { return &JSONSink{enc: json.NewEncoder(w)} }

func (s *JSONSink) Begin(observe.Scan) error                      { return nil }
func (s *JSONSink) Observation(o observe.Observation) error       { return s.enc.Encode(o) }
func (s *JSONSink) PacketEvidence(p observe.PacketEvidence) error { return s.enc.Encode(p) }
func (s *JSONSink) Finish(sc observe.Scan) error                  { return s.enc.Encode(sc) }

// TextSink writes one line per record for terminals. When its Styler is
// enabled it colors and aligns output; otherwise it emits nyxr's original
// plain layout, so piped and stored output is byte-for-byte unchanged.
type TextSink struct {
	w     io.Writer
	style *ui.Styler
}

// NewTextSink writes plain text. Call WithStyle to enable color on a terminal.
func NewTextSink(w io.Writer) *TextSink { return &TextSink{w: w, style: ui.Plain()} }

// WithStyle sets the Styler used for coloring and returns the sink.
func (s *TextSink) WithStyle(style *ui.Styler) *TextSink {
	if style != nil {
		s.style = style
	}
	return s
}

func (s *TextSink) Begin(observe.Scan) error { return nil }

func (s *TextSink) Observation(o observe.Observation) error {
	if o.Kind == observe.KindScript && o.NSE != nil {
		output := strings.TrimSpace(o.NSE.Output)
		output = strings.ReplaceAll(output, "\n", "\\n")
		if o.Port == 0 {
			_, err := fmt.Fprintf(s.w, "%s nse %s: %s\n", o.Target, o.NSE.ID, output)
			return err
		}
		_, err := fmt.Fprintf(s.w, "%s %s/%d nse %s: %s\n", o.Target, o.Transport, o.Port, o.NSE.ID, output)
		return err
	}
	if o.Kind == observe.KindDevice {
		line := s.style.Device(o.Target.String(), o.Attributes["device.class"], o.Confidence, len(o.Signals))
		_, err := fmt.Fprintln(s.w, line)
		return err
	}
	if o.Kind != observe.KindService {
		reason := o.Reason
		if o.MAC != "" {
			reason += " (MAC " + o.MAC + ")"
		}
		line := s.style.Discovery(o.Target.String(), o.Port, o.Transport, o.State, o.Confidence, reason)
		_, err := fmt.Fprintln(s.w, line)
		return err
	}
	name := o.Service
	if name == "" {
		name = "unknown"
	}
	details := []string{}
	if product := strings.TrimSpace(o.Product + " " + o.Version); product != "" {
		details = append(details, product)
	}
	if o.TLS != nil {
		t := o.TLS.Version
		if o.TLS.ALPN != "" {
			t += " " + o.TLS.ALPN
		}
		if len(o.TLS.Certificates) > 0 {
			leaf := o.TLS.Certificates[0]
			subject := leaf.Subject
			if len(leaf.DNSNames) > 0 {
				subject = leaf.DNSNames[0]
			}
			t += " cert " + subject
		}
		details = append(details, t)
	}
	if title := o.Attributes["http.title"]; title != "" {
		details = append(details, fmt.Sprintf("title %q", title))
	}
	unknown := o.Service == "" && o.Fingerprint == observe.FingerprintUnknown
	if unknown {
		if preview := firstReceivedPreview(o.Evidence); preview != "" {
			details = append(details, preview)
		} else {
			details = append(details, o.Reason)
		}
	} else {
		details = append(details, o.Reason)
	}
	head := s.style.ServiceHead(o.Target.String(), o.Port, o.Transport, name, o.Confidence)
	_, err := fmt.Fprintf(s.w, "%s %s\n", head, s.style.JoinDetails(details))
	return err
}

// Show only the first received exchange, keeping terminal output to one line.
// Full requests and responses remain in the observation evidence.
func firstReceivedPreview(evidence []observe.Evidence) string {
	for _, ev := range evidence {
		if len(ev.Response) == 0 {
			continue
		}
		label := ev.Probe + " response"
		if ev.Probe == "banner" {
			label = "banner"
			if !readableBanner(ev.Response) {
				label = "binary banner"
			}
		}
		preview := decodedPreview(ev)
		if preview == "" {
			preview = hexPreview(ev.Response)
		}
		return fmt.Sprintf("%s (%d bytes) [%s]", label, len(ev.Response), preview)
	}
	return ""
}

// decodedPreview pairs each decoded field in the first 16 bytes with its short
// meaning: "15 alert, 03 03 TLS 1.2, ...". Notes stay in the JSON evidence.
func decodedPreview(ev observe.Evidence) string {
	var parts []string
	end := 0
	for _, f := range ev.Decoded {
		if f.Offset != end || f.Offset+f.Length > 16 {
			break
		}
		parts = append(parts, f.Bytes+" "+f.Value)
		end += f.Length
	}
	if len(parts) == 0 {
		return ""
	}
	out := strings.Join(parts, ", ")
	if end < len(ev.Response) {
		out += " …"
	}
	return out
}

func readableBanner(data []byte) bool {
	if !utf8.Valid(data) {
		return false
	}
	for _, r := range string(data) {
		if r != '\r' && r != '\n' && r != '\t' && !unicode.IsPrint(r) {
			return false
		}
	}
	return true
}

// hexPreview renders at most 16 received bytes as space-separated hex.
func hexPreview(data []byte) string {
	var out strings.Builder
	for i, b := range data[:min(len(data), 16)] {
		if i > 0 {
			out.WriteByte(' ')
		}
		fmt.Fprintf(&out, "%02x", b)
	}
	if len(data) > 16 {
		out.WriteString(" …")
	}
	return out.String()
}

func (s *TextSink) PacketEvidence(p observe.PacketEvidence) error {
	ids := make([]string, 0, len(p.Packets))
	for _, pkt := range p.Packets {
		ids = append(ids, fmt.Sprint(pkt.ID))
	}
	line := s.style.Evidence(p.Target.String(), p.Port, p.Transport, len(p.Packets), p.Capture, strings.Join(ids, ","), p.Truncated)
	_, err := fmt.Fprintln(s.w, line)
	return err
}

func (s *TextSink) Finish(sc observe.Scan) error {
	tail := ""
	if c := sc.Capture; c != nil {
		tail = fmt.Sprintf("; captured %d packets to %s", c.Written, c.Path)
		if drops := c.DroppedQueue + c.DroppedLimit + c.BackendDrops; drops > 0 {
			tail += fmt.Sprintf(" (%d dropped)", drops)
		}
	}
	_, err := fmt.Fprintln(s.w, s.style.ScanSummary(sc.ID, sc.Status, sc.Observations, sc.Services, tail))
	return err
}

// StoreSink persists records in batches so the database sees one
// transaction per batch rather than per observation.
type StoreSink struct {
	ctx     context.Context
	store   *storage.Store
	batch   []observe.Observation
	packets []observe.PacketEvidence
	size    int
}

func NewStoreSink(ctx context.Context, store *storage.Store) *StoreSink {
	return &StoreSink{ctx: ctx, store: store, size: 256}
}

func (s *StoreSink) Begin(sc observe.Scan) error { return s.store.BeginScan(s.ctx, sc) }

func (s *StoreSink) Observation(o observe.Observation) error {
	s.batch = append(s.batch, o)
	if len(s.batch) >= s.size {
		return s.flush()
	}
	return nil
}

func (s *StoreSink) PacketEvidence(p observe.PacketEvidence) error {
	s.packets = append(s.packets, p)
	if len(s.packets) >= s.size {
		err := s.store.AddPacketEvidence(s.ctx, s.packets)
		s.packets = s.packets[:0]
		return err
	}
	return nil
}

func (s *StoreSink) flush() error {
	err := s.store.AddObservations(s.ctx, s.batch)
	s.batch = s.batch[:0]
	return err
}

// Finish writes remaining records even when the scan failed, so partial
// results and the failure reason are both kept.
func (s *StoreSink) Finish(sc observe.Scan) error {
	// A canceled scan context must not prevent recording what happened.
	s.ctx = context.WithoutCancel(s.ctx)
	if err := s.flush(); err != nil {
		return err
	}
	if err := s.store.AddPacketEvidence(s.ctx, s.packets); err != nil {
		return err
	}
	s.packets = s.packets[:0]
	return s.store.FinishScan(s.ctx, sc)
}

// IsOpen reports whether a discovery state is a positive result: an open
// port or a responsive host.
func IsOpen(state string) bool {
	switch state {
	case "open", "responsive", "up", "identified":
		return true
	}
	return false
}

// OpenOnlySink forwards only positive host and port results to its inner
// sink, along with the packet evidence of those results. Service and device
// records describe open ports already, and the scan summary is unchanged.
type OpenOnlySink struct {
	inner Sink
	shown map[evidenceKey]bool
}

type evidenceKey struct {
	target    string
	transport string
	port      uint16
}

func NewOpenOnlySink(inner Sink) *OpenOnlySink {
	return &OpenOnlySink{inner: inner, shown: map[evidenceKey]bool{}}
}

func (s *OpenOnlySink) Begin(sc observe.Scan) error { return s.inner.Begin(sc) }

func (s *OpenOnlySink) Observation(o observe.Observation) error {
	if o.Kind == observe.KindHost || o.Kind == observe.KindPort {
		if !IsOpen(o.State) {
			return nil
		}
		s.shown[evidenceKey{o.Target.String(), o.Transport, o.Port}] = true
	}
	return s.inner.Observation(o)
}

func (s *OpenOnlySink) PacketEvidence(p observe.PacketEvidence) error {
	if !s.shown[evidenceKey{p.Target.String(), p.Transport, p.Port}] {
		return nil
	}
	return s.inner.PacketEvidence(p)
}

func (s *OpenOnlySink) Finish(sc observe.Scan) error { return s.inner.Finish(sc) }
