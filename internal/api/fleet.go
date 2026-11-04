package api

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/matusso/nyxr/internal/config"
	"github.com/matusso/nyxr/internal/fleet"
)

// fleetEnabled gates the distributed scan API. Job submission sends scans to
// remote vantages, so it never runs without an API token.
func (s *server) fleetEnabled(w http.ResponseWriter) bool {
	if s.cfg.Fleet == nil {
		writeError(w, http.StatusForbidden, "the fleet controller is disabled (start the server with --fleet-listen)")
		return false
	}
	if s.cfg.Token == "" {
		writeError(w, http.StatusForbidden, "the fleet API requires an API token")
		return false
	}
	return true
}

// fleetScanRequest is a scan request plus partitioning options.
type fleetScanRequest struct {
	Request config.Request `json:"request"`
	fleet.JobOptions
}

func (s *server) fleetSummary(w http.ResponseWriter, r *http.Request) {
	if !s.fleetEnabled(w) {
		return
	}
	agents, err := s.cfg.Fleet.Agents(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	online := 0
	for _, a := range agents {
		if a.Connected {
			online++
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"protocol": fleet.Protocol, "agents": len(agents), "online": online})
}

func (s *server) fleetAgents(w http.ResponseWriter, r *http.Request) {
	if !s.fleetEnabled(w) {
		return
	}
	agents, err := s.cfg.Fleet.Agents(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"agents": agents})
}

func (s *server) fleetRevokeAgent(w http.ResponseWriter, r *http.Request) {
	if !s.fleetEnabled(w) {
		return
	}
	ok, err := s.cfg.Fleet.Revoke(r.Context(), r.PathValue("id"))
	switch {
	case err != nil:
		writeError(w, http.StatusInternalServerError, err.Error())
	case !ok:
		writeError(w, http.StatusNotFound, "no such active agent")
	default:
		writeJSON(w, http.StatusOK, map[string]string{"status": "revoked"})
	}
}

func (s *server) fleetListScans(w http.ResponseWriter, r *http.Request) {
	if !s.fleetEnabled(w) {
		return
	}
	limit, err := intParam(r, "limit", 50, 1000)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	jobs, err := s.cfg.Fleet.Jobs(r.Context(), limit)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"jobs": jobs})
}

func (s *server) fleetCreateScan(w http.ResponseWriter, r *http.Request) {
	if !s.fleetEnabled(w) {
		return
	}
	var req fleetScanRequest
	d := json.NewDecoder(r.Body)
	d.DisallowUnknownFields()
	if err := d.Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("invalid fleet scan request: %v", err))
		return
	}
	if d.More() {
		writeError(w, http.StatusBadRequest, "invalid fleet scan request: trailing data")
		return
	}
	job, err := s.cfg.Fleet.Submit(r.Context(), req.Request, req.JobOptions)
	if err != nil {
		writeError(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	w.Header().Set("Location", "/api/v1/fleet/scans/"+job.ID)
	writeJSON(w, http.StatusCreated, job)
}

func (s *server) fleetGetScan(w http.ResponseWriter, r *http.Request) {
	if !s.fleetEnabled(w) {
		return
	}
	d, ok, err := s.cfg.Fleet.Job(r.Context(), r.PathValue("id"))
	switch {
	case err != nil:
		writeError(w, http.StatusInternalServerError, err.Error())
	case !ok:
		writeError(w, http.StatusNotFound, "no such fleet scan")
	default:
		writeJSON(w, http.StatusOK, d)
	}
}

func (s *server) fleetCancelScan(w http.ResponseWriter, r *http.Request) {
	if !s.fleetEnabled(w) {
		return
	}
	ok, err := s.cfg.Fleet.Cancel(r.Context(), r.PathValue("id"))
	switch {
	case err != nil:
		writeError(w, http.StatusInternalServerError, err.Error())
	case !ok:
		writeError(w, http.StatusConflict, "fleet scan is not running")
	default:
		writeJSON(w, http.StatusAccepted, map[string]string{"status": "canceled"})
	}
}
