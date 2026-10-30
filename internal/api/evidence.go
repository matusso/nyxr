package api

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/matusso/nyxr/internal/capture"
	"github.com/matusso/nyxr/internal/observe"
	"github.com/matusso/nyxr/internal/service"
)

// maxDefinition bounds an edited definition sent for replay.
const maxDefinition = 64 << 10

// evidenceTrace navigates one stored claim to its exchanges and indexed
// packets. Server paths are reduced to the capture file name.
func (s *server) evidenceTrace(w http.ResponseWriter, r *http.Request) {
	trace, ok, err := s.cfg.Store.Trace(r.Context(), r.URL.Query().Get("observation"))
	switch {
	case err != nil && !ok:
		writeError(w, http.StatusBadRequest, err.Error())
	case err != nil:
		writeError(w, http.StatusInternalServerError, err.Error())
	case !ok:
		writeError(w, http.StatusNotFound, "observation not found in this store")
	default:
		if trace.Capture.Capture != "" {
			trace.Capture.Capture = filepath.Base(trace.Capture.Capture)
		}
		writeJSON(w, http.StatusOK, trace)
	}
}

type evidenceFrame struct {
	ID        uint64    `json:"id"`
	Timestamp time.Time `json:"timestamp"`
	Direction string    `json:"direction"`
	Length    int       `json:"length"`
	Captured  int       `json:"captured"`
	Hex       string    `json:"hex"`
}

// scanFrames returns indexed frames from a verified capture inside the
// evidence directory, so one can be opened in the packet editor.
func (s *server) scanFrames(w http.ResponseWriter, r *http.Request) {
	var ids []uint64
	for _, part := range strings.Split(r.URL.Query().Get("ids"), ",") {
		id, err := strconv.ParseUint(strings.TrimSpace(part), 10, 64)
		if err != nil || id == 0 {
			writeError(w, http.StatusBadRequest, "ids must be comma-separated packet IDs")
			return
		}
		ids = append(ids, id)
	}
	if len(ids) > capture.MaxFrameLookup {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("request at most %d packet IDs", capture.MaxFrameLookup))
		return
	}
	f, _, code, err := s.openCapture(r, r.PathValue("id"))
	if err != nil {
		writeError(w, code, err.Error())
		return
	}
	defer f.Close()
	records, err := capture.ReadPackets(f, ids)
	if err != nil {
		writeError(w, http.StatusUnprocessableEntity, "capture: "+err.Error())
		return
	}
	out := struct {
		Frames  []evidenceFrame `json:"frames"`
		Missing []uint64        `json:"missing,omitempty"`
	}{Frames: []evidenceFrame{}}
	for _, id := range ids {
		rec, ok := records[id]
		if !ok {
			out.Missing = append(out.Missing, id)
			continue
		}
		out.Frames = append(out.Frames, evidenceFrame{ID: id, Timestamp: rec.Timestamp.UTC(), Direction: rec.Direction.String(),
			Length: rec.Length, Captured: len(rec.Data), Hex: hex.EncodeToString(rec.Data)})
	}
	sort.Slice(out.Frames, func(i, j int) bool { return out.Frames[i].ID < out.Frames[j].ID })
	writeJSON(w, http.StatusOK, out)
}

func decodeStrict(r *http.Request, limit int64, v any) error {
	d := json.NewDecoder(io.LimitReader(r.Body, limit))
	d.DisallowUnknownFields()
	if err := d.Decode(v); err != nil {
		return err
	}
	var extra any
	if err := d.Decode(&extra); err != io.EOF {
		return errors.New("trailing data")
	}
	return nil
}

func (s *server) storedObservation(r *http.Request, id string) (observe.Observation, int, error) {
	o, ok, err := s.cfg.Store.ObservationByID(r.Context(), id)
	switch {
	case err != nil && !ok:
		return o, http.StatusBadRequest, err
	case err != nil:
		return o, http.StatusInternalServerError, err
	case !ok:
		return o, http.StatusNotFound, errors.New("observation not found in this store")
	}
	return o, http.StatusOK, nil
}

// cloneProbe drafts an editable definition. The draft is returned as text;
// the server never writes it to disk or adds it to the protocol registry.
func (s *server) cloneProbe(w http.ResponseWriter, r *http.Request) {
	var input struct {
		ObservationID string `json:"observation_id"`
		Exchange      int    `json:"exchange"`
	}
	if err := decodeStrict(r, 4096, &input); err != nil {
		writeError(w, http.StatusBadRequest, "invalid clone request: "+err.Error())
		return
	}
	o, code, err := s.storedObservation(r, input.ObservationID)
	if err != nil {
		writeError(w, code, err.Error())
		return
	}
	definition, err := service.CloneProtocol(o, input.Exchange)
	if err != nil {
		writeError(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"definition": string(definition)})
}

// replayProbe plans, and unless dry_run is set runs, an edited definition
// against the exchange it came from. Offline runs send nothing. A live
// resend is an explicit request that needs an authenticated server started
// with --allow-packet-send, must name the original target, and is refused
// for scans made with the ot-safe profile.
func (s *server) replayProbe(w http.ResponseWriter, r *http.Request) {
	var input struct {
		ObservationID string `json:"observation_id"`
		Exchange      int    `json:"exchange"`
		Definition    string `json:"definition"`
		Mode          string `json:"mode"`
		DryRun        bool   `json:"dry_run"`
		Target        string `json:"target"`
	}
	if err := decodeStrict(r, maxDefinition+4096, &input); err != nil {
		writeError(w, http.StatusBadRequest, "invalid replay request: "+err.Error())
		return
	}
	if len(input.Definition) > maxDefinition {
		writeError(w, http.StatusRequestEntityTooLarge, "definition exceeds 64 KiB")
		return
	}
	o, code, err := s.storedObservation(r, input.ObservationID)
	if err != nil {
		writeError(w, code, err.Error())
		return
	}
	in := service.ReplayInput{Observation: o, Exchange: input.Exchange, Definition: []byte(input.Definition), Mode: input.Mode}
	_, plan, err := service.PlanReplay(in)
	if err != nil {
		writeError(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	if input.Mode == observe.ProbeRunLive {
		if target, err := netip.ParseAddr(input.Target); err != nil || target != o.Target {
			writeError(w, http.StatusUnprocessableEntity, "a live resend must name the original target "+o.Target.String())
			return
		}
		if !input.DryRun && (s.cfg.Token == "" || !s.cfg.PacketSendEnabled) {
			writeError(w, http.StatusForbidden, "live resend needs an API token and serve --allow-packet-send")
			return
		}
		sc, ok, err := s.cfg.Store.Scan(r.Context(), o.ScanID)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		if ok && sc.Profile == "ot-safe" {
			writeError(w, http.StatusForbidden, "the ot-safe profile does not allow resending edited probes")
			return
		}
	}
	if input.DryRun {
		writeJSON(w, http.StatusOK, plan)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), plan.Timeout+5*time.Second)
	defer cancel()
	run, err := service.Replay(ctx, in)
	if err != nil {
		writeError(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	if err := s.cfg.Store.AddProbeRun(r.Context(), &run, o.ScanID, in.Definition); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, run)
}
