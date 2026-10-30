package storage

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/matusso/nyxr/internal/observe"
)

// TraceSchema versions the claim → exchange → packet navigation record.
const TraceSchema = "nyxr/evidence-trace/v1"

// Packets are associated with an exchange when their capture timestamp lies
// within the exchange, widened by this much for clock granularity and the
// closing handshake.
const (
	traceLead  = 10 * time.Millisecond
	traceTrail = 100 * time.Millisecond
)

// EvidenceTrace links one stored claim to the retained exchanges that
// support it and to the indexed capture packets of its flow. Gaps are
// explicit: Capture.Status and Reasons say why packets are missing or
// incomplete, and a missing packet is never evidence that nothing was sent.
type EvidenceTrace struct {
	Schema      string              `json:"schema"`
	Observation observe.Observation `json:"observation"`
	Exchanges   []TraceExchange     `json:"exchanges"`
	Capture     TraceCapture        `json:"capture"`
	Runs        []observe.ProbeRun  `json:"runs"`
}

// TraceExchange summarizes one retained exchange. Decisions index the
// observation's probe_updates whose evidence range includes this exchange.
// Packets are exact capture packet IDs; their association with the exchange
// is by time window and therefore inferred.
type TraceExchange struct {
	Index         int                `json:"index"`
	Source        *observe.SourceRef `json:"source,omitempty"`
	Probe         string             `json:"probe"`
	Layer         string             `json:"layer"`
	Matched       string             `json:"matched,omitempty"`
	Error         string             `json:"error,omitempty"`
	Completeness  string             `json:"completeness,omitempty"`
	Truncated     bool               `json:"truncated,omitempty"`
	Started       time.Time          `json:"started"`
	Duration      time.Duration      `json:"duration_ns"`
	RequestBytes  int                `json:"request_bytes"`
	ResponseBytes int                `json:"response_bytes"`
	Decisions     []int              `json:"decisions,omitempty"`
	Packets       []uint64           `json:"packets,omitempty"`
}

// TraceCapture is the packet side of a trace. Status is available,
// partial (index truncated or frames dropped) or unavailable.
type TraceCapture struct {
	Status            string           `json:"status"`
	Reasons           []string         `json:"reasons,omitempty"`
	Capture           string           `json:"capture,omitempty"`
	CaptureArtifactID string           `json:"capture_artifact_id,omitempty"`
	FlowTruncated     bool             `json:"flow_truncated,omitempty"`
	DroppedQueue      uint64           `json:"dropped_queue,omitempty"`
	DroppedLimit      uint64           `json:"dropped_limit,omitempty"`
	BackendDrops      uint64           `json:"backend_drops,omitempty"`
	Association       string           `json:"packet_association,omitempty"`
	Packets           []observe.Packet `json:"packets,omitempty"`
}

// ObservationByID reads one stored observation by the ID it was stored
// with: <scan_id>/<n> from a scan stream, or store:<namespace>/<n> when the
// store assigned it. A store ID minted by another store is not found.
func (s *Store) ObservationByID(ctx context.Context, id string) (observe.Observation, bool, error) {
	slash := strings.LastIndexByte(id, '/')
	if slash < 1 || len(id) > 256 {
		return observe.Observation{}, false, errors.New("observation ID must be <scan_id>/<n> or store:<namespace>/<n>")
	}
	n, err := strconv.ParseInt(id[slash+1:], 10, 64)
	if err != nil || n < 1 {
		return observe.Observation{}, false, errors.New("observation ID must end in a positive number")
	}
	if namespace, ok := strings.CutPrefix(id[:slash], "store:"); ok {
		var own string
		if err := s.db.QueryRowContext(ctx, `SELECT value FROM identity_namespace WHERE id = 1`).Scan(&own); err != nil {
			return observe.Observation{}, false, err
		}
		if namespace != own {
			return observe.Observation{}, false, nil
		}
	} else {
		// Stream IDs are kept in the stored record; the scan narrows the search.
		err := s.db.QueryRowContext(ctx, `SELECT id FROM observations WHERE scan_id = ? AND json_extract(record, '$.observation_id') = ?`,
			id[:slash], id).Scan(&n)
		if errors.Is(err, sql.ErrNoRows) {
			return observe.Observation{}, false, nil
		}
		if err != nil {
			return observe.Observation{}, false, err
		}
	}
	obs, err := s.Observations(ctx, Filter{ObservationID: n, Limit: 1})
	if err != nil || len(obs) == 0 {
		return observe.Observation{}, false, err
	}
	return obs[0], true, nil
}

// Trace builds the evidence navigation for one stored observation.
func (s *Store) Trace(ctx context.Context, id string) (EvidenceTrace, bool, error) {
	o, ok, err := s.ObservationByID(ctx, id)
	if err != nil || !ok {
		return EvidenceTrace{}, ok, err
	}
	t := EvidenceTrace{Schema: TraceSchema, Observation: o, Exchanges: []TraceExchange{}, Runs: []observe.ProbeRun{}}
	for i, ev := range o.Evidence {
		x := TraceExchange{Index: i, Source: ev.Source, Probe: ev.Probe, Layer: ev.Layer, Matched: ev.Matched, Error: ev.Error,
			Completeness: ev.Completeness, Truncated: ev.Truncated, Started: ev.Started, Duration: ev.Duration,
			RequestBytes: len(ev.Request), ResponseBytes: len(ev.Response)}
		for j, u := range o.ProbeUpdates {
			if u.EvidenceStart <= i && i < u.EvidenceEnd {
				x.Decisions = append(x.Decisions, j)
			}
		}
		t.Exchanges = append(t.Exchanges, x)
	}
	if t.Capture, err = s.traceCapture(ctx, o); err != nil {
		return t, true, err
	}
	for i := range t.Exchanges {
		x := &t.Exchanges[i]
		from, to := x.Started.Add(-traceLead), x.Started.Add(x.Duration+traceTrail)
		for _, p := range t.Capture.Packets {
			if !p.Timestamp.Before(from) && !p.Timestamp.After(to) {
				x.Packets = append(x.Packets, p.ID)
			}
		}
	}
	if o.Source != nil {
		if t.Runs, err = s.ProbeRuns(ctx, o.Source.ArtifactID); err != nil {
			return t, true, err
		}
	}
	return t, true, nil
}

func (s *Store) traceCapture(ctx context.Context, o observe.Observation) (TraceCapture, error) {
	c := TraceCapture{Status: "unavailable"}
	sc, ok, err := s.Scan(ctx, o.ScanID)
	switch {
	case err != nil:
		return c, err
	case !ok:
		c.Reasons = append(c.Reasons, "the source scan is pruned or not retained in this store")
		return c, nil
	case sc.Status == "running":
		c.Reasons = append(c.Reasons, "the scan is still running; its capture index is written when it finishes")
		return c, nil
	case sc.Capture == nil:
		c.Reasons = append(c.Reasons, "the scan recorded no pcapng capture (scan with --pcapng)")
		return c, nil
	}
	c.Capture, c.CaptureArtifactID = sc.Capture.Path, sc.Capture.ArtifactID
	c.DroppedQueue, c.DroppedLimit, c.BackendDrops = sc.Capture.DroppedQueue, sc.Capture.DroppedLimit, sc.Capture.BackendDrops
	flows, err := s.PacketEvidence(ctx, o.ScanID, o.Target)
	if err != nil {
		return c, err
	}
	for _, f := range flows {
		if f.Transport == o.Transport && f.Port == o.Port {
			c.Packets, c.FlowTruncated = f.Packets, f.Truncated
			if f.CaptureArtifactID != "" {
				c.CaptureArtifactID = f.CaptureArtifactID
			}
		}
	}
	if len(c.Packets) == 0 {
		c.Reasons = append(c.Reasons, "no packets were indexed for this flow")
		return c, nil
	}
	c.Status, c.Association = "available", "time-window"
	if c.FlowTruncated {
		c.Reasons = append(c.Reasons, "more frames matched this flow than the capture index retains")
	}
	if drops := c.DroppedQueue + c.DroppedLimit + c.BackendDrops; drops > 0 {
		c.Reasons = append(c.Reasons, fmt.Sprintf("the capture dropped %d frames (queue %d, size budget %d, backend %d)",
			drops, c.DroppedQueue, c.DroppedLimit, c.BackendDrops))
	}
	if len(c.Reasons) > 0 {
		c.Status = "partial"
	}
	return c, nil
}
