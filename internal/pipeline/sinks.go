package pipeline

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/matusso/nyxr/internal/observe"
	"github.com/matusso/nyxr/internal/storage"
)

// JSONSink writes newline-delimited records. The final line is the scan
// summary; readers distinguish records by their "kind" field.
type JSONSink struct{ enc *json.Encoder }

func NewJSONSink(w io.Writer) *JSONSink { return &JSONSink{enc: json.NewEncoder(w)} }

func (s *JSONSink) Begin(observe.Scan) error                      { return nil }
func (s *JSONSink) Observation(o observe.Observation) error       { return s.enc.Encode(o) }
func (s *JSONSink) PacketEvidence(p observe.PacketEvidence) error { return s.enc.Encode(p) }
func (s *JSONSink) Finish(sc observe.Scan) error                  { return s.enc.Encode(sc) }

// TextSink writes one line per record for terminals.
type TextSink struct{ w io.Writer }

func NewTextSink(w io.Writer) *TextSink { return &TextSink{w: w} }

func (s *TextSink) Begin(observe.Scan) error { return nil }

func (s *TextSink) Observation(o observe.Observation) error {
	if o.Kind == observe.KindDevice {
		_, err := fmt.Fprintf(s.w, "%s device %-20s %3d%% %d signals\n", o.Target, o.Attributes["device.class"], o.Confidence, len(o.Signals))
		return err
	}
	port := ""
	if o.Port != 0 {
		port = fmt.Sprintf(":%d", o.Port)
	}
	if o.Kind != observe.KindService {
		reason := o.Reason
		if o.MAC != "" {
			reason += " (MAC " + o.MAC + ")"
		}
		_, err := fmt.Fprintf(s.w, "%s%s %-5s %-14s %3d%% %s\n", o.Target, port, o.Transport, o.State, o.Confidence, reason)
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
	details = append(details, o.Reason)
	_, err := fmt.Fprintf(s.w, "%s%s %-5s %-14s %3d%% %s\n", o.Target, port, o.Transport, "svc "+name, o.Confidence, strings.Join(details, " | "))
	return err
}

func (s *TextSink) PacketEvidence(p observe.PacketEvidence) error {
	port := ""
	if p.Port != 0 {
		port = fmt.Sprintf(":%d", p.Port)
	}
	ids := make([]string, 0, len(p.Packets))
	for _, pkt := range p.Packets {
		ids = append(ids, fmt.Sprint(pkt.ID))
	}
	more := ""
	if p.Truncated {
		more = " (index truncated)"
	}
	_, err := fmt.Fprintf(s.w, "%s%s %-5s evidence       %d packets in %s: %s%s\n", p.Target, port, p.Transport, len(p.Packets), p.Capture, strings.Join(ids, ","), more)
	return err
}

func (s *TextSink) Finish(sc observe.Scan) error {
	line := fmt.Sprintf("scan %s %s: %d observations, %d services identified", sc.ID, sc.Status, sc.Observations, sc.Services)
	if c := sc.Capture; c != nil {
		line += fmt.Sprintf("; captured %d packets to %s", c.Written, c.Path)
		if drops := c.DroppedQueue + c.DroppedLimit + c.BackendDrops; drops > 0 {
			line += fmt.Sprintf(" (%d dropped)", drops)
		}
	}
	_, err := fmt.Fprintln(s.w, line)
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
