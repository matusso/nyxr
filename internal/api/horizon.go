package api

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"

	"github.com/matusso/nyxr/internal/horizon"
	"github.com/matusso/nyxr/internal/horizon/dsl"
	"github.com/matusso/nyxr/internal/horizon/model"
)

// horizonActor identifies the caller for the audit trail without the token.
func (s *server) horizonActor(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	auth := "none"
	if s.cfg.Token != "" {
		auth = "bearer"
	}
	return fmt.Sprintf("remote=%s auth=%s", host, auth)
}

func (s *server) horizonEnabled(w http.ResponseWriter) bool {
	if s.cfg.Horizon == nil {
		writeError(w, http.StatusForbidden, "HORIZON is disabled by the operator")
		return false
	}
	// Enforced here too, not only by serve: no unauthenticated HORIZON API.
	if s.cfg.Token == "" {
		writeError(w, http.StatusForbidden, "the HORIZON API requires an API token")
		return false
	}
	return true
}

// horizonStatus maps service errors to HTTP status codes.
func horizonStatus(err error) int {
	switch {
	case errors.Is(err, horizon.ErrModeDisabled):
		return http.StatusForbidden
	case errors.Is(err, horizon.ErrBusy):
		return http.StatusTooManyRequests
	case errors.Is(err, horizon.ErrStopped), errors.Is(err, horizon.ErrRunActive), errors.Is(err, horizon.ErrRunFinished):
		return http.StatusConflict
	case errors.Is(err, horizon.ErrNoRun), errors.Is(err, horizon.ErrNoReport):
		return http.StatusNotFound
	}
	return http.StatusUnprocessableEntity
}

func (s *server) horizonCapabilities(w http.ResponseWriter, r *http.Request) {
	if !s.horizonEnabled(w) {
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"apiVersion": model.RunVersion, "modes": s.cfg.Horizon.EnabledModes(), "allModes": horizon.Modes})
}

func (s *server) horizonPlan(w http.ResponseWriter, r *http.Request) {
	if !s.horizonEnabled(w) {
		return
	}
	e, err := dsl.Parse(r.Body)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	plan, err := s.cfg.Horizon.Plan(e)
	if err != nil {
		writeError(w, horizonStatus(err), err.Error())
		return
	}
	writeJSON(w, http.StatusOK, plan)
}

// horizonRun is the synchronous /resolve endpoint, kept for compatibility.
func (s *server) horizonRun(w http.ResponseWriter, r *http.Request) {
	if !s.horizonEnabled(w) {
		return
	}
	e, err := dsl.Parse(r.Body)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	report, err := s.cfg.Horizon.Resolve(r.Context(), s.horizonActor(r), e)
	if report.APIVersion == "" {
		writeError(w, horizonStatus(err), err.Error())
		return
	}
	envelope, sealErr := horizon.Seal(report)
	if sealErr != nil {
		writeError(w, http.StatusInternalServerError, sealErr.Error())
		return
	}
	// Cancellation/failure preserves a sealed partial report and stop reason.
	code := http.StatusOK
	if err != nil {
		code = http.StatusConflict
	}
	writeJSON(w, code, envelope)
}

func (s *server) horizonStop(w http.ResponseWriter, r *http.Request) {
	if !s.horizonEnabled(w) {
		return
	}
	// The kill switch engages even if the audit write fails; report both.
	if err := s.cfg.Horizon.Stop(s.horizonActor(r)); err != nil {
		writeJSON(w, http.StatusAccepted, map[string]string{"status": "stopped", "audit": err.Error()})
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]string{"status": "stopped"})
}

type horizonRunRequest struct {
	Mode       string          `json:"mode"`
	Experiment json.RawMessage `json:"experiment"`
}

func (s *server) horizonCreateRun(w http.ResponseWriter, r *http.Request) {
	if !s.horizonEnabled(w) {
		return
	}
	var req horizonRunRequest
	d := json.NewDecoder(r.Body)
	d.DisallowUnknownFields()
	if err := d.Decode(&req); err != nil || d.More() || req.Mode == "" || len(req.Experiment) == 0 {
		writeError(w, http.StatusBadRequest, `request must be {"mode": ..., "experiment": {...}}`)
		return
	}
	e, err := dsl.Parse(bytes.NewReader(req.Experiment))
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	st, err := s.cfg.Horizon.Create(s.horizonActor(r), req.Mode, e)
	if err != nil {
		writeError(w, horizonStatus(err), err.Error())
		return
	}
	writeJSON(w, http.StatusAccepted, st)
}

func (s *server) horizonListRuns(w http.ResponseWriter, r *http.Request) {
	if !s.horizonEnabled(w) {
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"runs": s.cfg.Horizon.List()})
}

func (s *server) horizonGetRun(w http.ResponseWriter, r *http.Request) {
	if !s.horizonEnabled(w) {
		return
	}
	st, err := s.cfg.Horizon.Get(r.PathValue("id"))
	if err != nil {
		writeError(w, horizonStatus(err), err.Error())
		return
	}
	writeJSON(w, http.StatusOK, st)
}

func (s *server) horizonCancelRun(w http.ResponseWriter, r *http.Request) {
	if !s.horizonEnabled(w) {
		return
	}
	st, err := s.cfg.Horizon.Cancel(s.horizonActor(r), r.PathValue("id"))
	switch {
	case errors.Is(err, horizon.ErrRunFinished), errors.Is(err, horizon.ErrNoRun):
		writeError(w, horizonStatus(err), err.Error())
	case err != nil:
		// The run was cancelled; only its audit entry failed.
		writeJSON(w, http.StatusAccepted, map[string]any{"run": st, "audit": err.Error()})
	default:
		writeJSON(w, http.StatusAccepted, st)
	}
}

func (s *server) horizonRunReport(w http.ResponseWriter, r *http.Request) {
	if !s.horizonEnabled(w) {
		return
	}
	env, err := s.cfg.Horizon.Report(r.PathValue("id"))
	if err != nil {
		writeError(w, horizonStatus(err), err.Error())
		return
	}
	// Run IDs are server-generated hex; the lookup above already matched one.
	w.Header().Set("Content-Disposition", `attachment; filename="horizon-`+r.PathValue("id")+`.json"`)
	writeJSON(w, http.StatusOK, env)
}

func (s *server) horizonRunGraph(w http.ResponseWriter, r *http.Request) {
	if !s.horizonEnabled(w) {
		return
	}
	g, err := s.cfg.Horizon.Graph(r.PathValue("id"))
	if err != nil {
		writeError(w, horizonStatus(err), err.Error())
		return
	}
	writeJSON(w, http.StatusOK, g)
}

func (s *server) horizonMetrics(w http.ResponseWriter, r *http.Request) {
	if !s.horizonEnabled(w) {
		return
	}
	w.Header().Set("Content-Type", "text/plain; version=0.0.4")
	if m := s.cfg.Horizon.Metrics(); m != nil {
		_ = m.WritePrometheus(w)
	}
}
