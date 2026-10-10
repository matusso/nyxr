package api

import (
	"errors"
	"net/http"

	"github.com/matusso/nyxr/internal/horizon"
	"github.com/matusso/nyxr/internal/horizon/dsl"
)

func (s *server) horizonPlan(w http.ResponseWriter, r *http.Request) {
	if s.cfg.Horizon == nil {
		writeError(w, http.StatusForbidden, "HORIZON is disabled by the operator")
		return
	}
	e, err := dsl.Parse(r.Body)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	plan, err := s.cfg.Horizon.Plan(e)
	if err != nil {
		writeError(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, plan)
}
func (s *server) horizonRun(w http.ResponseWriter, r *http.Request) {
	if s.cfg.Horizon == nil {
		writeError(w, http.StatusForbidden, "HORIZON is disabled by the operator")
		return
	}
	e, err := dsl.Parse(r.Body)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	report, err := s.cfg.Horizon.Run(r.Context(), e)
	if report.APIVersion == "" {
		code := http.StatusUnprocessableEntity
		if errors.Is(err, horizon.ErrBusy) {
			code = http.StatusTooManyRequests
		}
		if errors.Is(err, horizon.ErrStopped) {
			code = http.StatusConflict
		}
		writeError(w, code, err.Error())
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
	if s.cfg.Horizon == nil {
		writeError(w, http.StatusForbidden, "HORIZON is disabled by the operator")
		return
	}
	s.cfg.Horizon.Stop()
	writeJSON(w, http.StatusAccepted, map[string]string{"status": "stopped"})
}
