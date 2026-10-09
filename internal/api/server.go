// Package api serves the nyxr REST API, live scan events and the embedded web
// UI. Scan requests use the same config.Request document and Resolve path as
// the CLI, and results use the versioned observe records, so a web scan and a
// CLI scan with equivalent configuration produce equivalent observations.
// The API process never needs raw-socket privilege: raw packet I/O goes
// through nyxr-packetd.
package api

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"crypto/subtle"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"mime"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/matusso/nyxr/internal/config"
	"github.com/matusso/nyxr/internal/observe"
	"github.com/matusso/nyxr/internal/storage"
)

//go:embed web
var webFiles embed.FS

// maxBody bounds request documents.
const maxBody = 1 << 20

// ServerConfig configures the HTTP layer.
type ServerConfig struct {
	Manager *Manager
	Store   *storage.Store
	// Token, when set, is required as "Authorization: Bearer <token>" on
	// every API call.
	Token string
	// AllowedHosts limits accepted Host headers to defeat DNS rebinding
	// against a loopback listener. Empty accepts any host.
	AllowedHosts []string
	Version      string
	// EvidenceDir serves pcapng files captured through the API.
	EvidenceDir string
	// PacketSendEnabled explicitly permits raw frame transmission from the UI.
	PacketSendEnabled bool
}

type server struct {
	cfg   ServerConfig
	hosts map[string]bool
}

// Handler returns the API and web UI handler.
func Handler(cfg ServerConfig) http.Handler {
	s := &server{cfg: cfg, hosts: map[string]bool{}}
	for _, h := range cfg.AllowedHosts {
		s.hosts[strings.ToLower(h)] = true
	}
	api := http.NewServeMux()
	api.HandleFunc("GET /api/v1/version", s.version)
	api.HandleFunc("GET /api/v1/stats", s.stats)
	api.HandleFunc("GET /api/v1/profiles", s.profiles)
	api.HandleFunc("POST /api/v1/plan", s.plan)
	api.HandleFunc("GET /api/v1/scans", s.listScans)
	api.HandleFunc("POST /api/v1/scans", s.createScan)
	api.HandleFunc("GET /api/v1/scans/{id}", s.getScan)
	api.HandleFunc("POST /api/v1/scans/{id}/cancel", s.cancelScan)
	api.HandleFunc("GET /api/v1/scans/{id}/observations", s.scanObservations)
	api.HandleFunc("GET /api/v1/scans/{id}/evidence", s.scanEvidence)
	api.HandleFunc("GET /api/v1/scans/{id}/events", s.scanEvents)
	api.HandleFunc("GET /api/v1/scans/{id}/pcapng", s.scanPCAPNG)
	api.HandleFunc("GET /api/v1/assets", s.assets)
	api.HandleFunc("GET /api/v1/assets/identities", s.identities)
	api.HandleFunc("GET /api/v1/assets/identities/{id}", s.identity)
	api.HandleFunc("GET /api/v1/assets/identity-events", s.identityEvents)
	api.HandleFunc("GET /api/v1/assets/identity-relations", s.identityRelations)
	api.HandleFunc("GET /api/v1/assets/identity-reviews", s.identityReviews)
	api.HandleFunc("POST /api/v1/assets/identity-reviews", s.reviewIdentity)
	api.HandleFunc("GET /api/v1/assets/topology", s.topology)
	api.HandleFunc("GET /api/v1/observations", s.observations)
	api.HandleFunc("POST /api/v1/evidence/resolve", s.resolveSource)
	api.HandleFunc("GET /api/v1/packets/watch", s.watchPackets)
	api.HandleFunc("POST /api/v1/packets/send", s.sendPacket)
	api.HandleFunc("/api/", func(w http.ResponseWriter, r *http.Request) {
		writeError(w, http.StatusNotFound, "no such endpoint")
	})

	root := http.NewServeMux()
	root.Handle("/api/", s.guardAPI(api))
	static, _ := fs.Sub(webFiles, "web")
	files := http.FileServer(http.FS(static))
	root.Handle("/", files)
	return s.guardAll(root)
}

func (s *server) guardAll(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
		if len(s.hosts) > 0 && !s.hosts[hostOnly(r.Host)] {
			writeError(w, http.StatusMisdirectedRequest, "host not allowed")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *server) guardAPI(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.cfg.Token != "" {
			got, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
			if !ok || subtle.ConstantTimeCompare([]byte(got), []byte(s.cfg.Token)) != 1 {
				w.Header().Set("WWW-Authenticate", `Bearer realm="nyxr"`)
				writeError(w, http.StatusUnauthorized, "missing or invalid token")
				return
			}
		}
		if r.Method == http.MethodPost {
			// A JSON content type cannot be sent cross-origin without a
			// preflight, which this server never approves.
			mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
			if err != nil || mt != "application/json" {
				writeError(w, http.StatusUnsupportedMediaType, "POST requires Content-Type: application/json")
				return
			}
			r.Body = http.MaxBytesReader(w, r.Body, maxBody)
		}
		w.Header().Set("Cache-Control", "no-store")
		next.ServeHTTP(w, r)
	})
}

func hostOnly(hostport string) string {
	if h, _, err := net.SplitHostPort(hostport); err == nil {
		hostport = h
	}
	return strings.ToLower(strings.Trim(hostport, "[]"))
}

type apiError struct {
	Error string `json:"error"`
}

func writeError(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, apiError{Error: msg})
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

// decodeRequest reads a scan request with the same unknown-field strictness
// as the YAML --config file.
func decodeRequest(r *http.Request) (config.Request, error) {
	var req config.Request
	d := json.NewDecoder(r.Body)
	d.DisallowUnknownFields()
	if err := d.Decode(&req); err != nil {
		return req, fmt.Errorf("invalid scan request: %w", err)
	}
	if d.More() {
		return req, errors.New("invalid scan request: trailing data")
	}
	return req, nil
}

func (s *server) version(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"version": s.cfg.Version, "schema": observe.SchemaVersion})
}

func (s *server) stats(w http.ResponseWriter, r *http.Request) {
	scans, err := s.cfg.Store.ScanCount(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	assets, err := s.cfg.Store.Assets(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	open, services := 0, 0
	for _, a := range assets {
		for _, p := range a.Ports {
			if p.State == "open" {
				open++
				if p.Service != "" {
					services++
				}
			}
		}
	}
	writeJSON(w, http.StatusOK, map[string]int{
		"scans": scans, "running": len(s.cfg.Manager.Running()), "hosts": len(assets),
		"open_ports": open, "services": services,
	})
}

func (s *server) profiles(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, config.Profiles())
}

func (s *server) plan(w http.ResponseWriter, r *http.Request) {
	req, err := decodeRequest(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	res, err := s.cfg.Manager.Resolve(req)
	if err != nil {
		writeError(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	plan := res.Plan()
	if plan.PCAPNG != "" {
		plan.PCAPNG = filepath.Base(plan.PCAPNG)
	}
	writeJSON(w, http.StatusOK, plan)
}

func (s *server) createScan(w http.ResponseWriter, r *http.Request) {
	req, err := decodeRequest(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	sc, err := s.cfg.Manager.Start(req)
	switch {
	case errors.Is(err, ErrBusy):
		writeError(w, http.StatusTooManyRequests, err.Error())
	case err != nil:
		writeError(w, http.StatusUnprocessableEntity, err.Error())
	default:
		w.Header().Set("Location", "/api/v1/scans/"+sc.ID)
		writeJSON(w, http.StatusCreated, sc)
	}
}

func (s *server) listScans(w http.ResponseWriter, r *http.Request) {
	limit, err := intParam(r, "limit", 50, 1000)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	stored, err := s.cfg.Store.Scans(r.Context(), limit)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	// Live counters replace the stored "running" row of an active scan.
	live := map[string]observe.Scan{}
	for _, sc := range s.cfg.Manager.Running() {
		live[sc.ID] = sc
	}
	out := make([]observe.Scan, 0, len(stored))
	for _, sc := range stored {
		if l, ok := live[sc.ID]; ok {
			sc = l
		}
		out = append(out, publicScan(sc))
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *server) scanSummary(r *http.Request, id string) (observe.Scan, bool, error) {
	if run := s.cfg.Manager.lookup(id); run != nil {
		return run.snapshot(), true, nil
	}
	return s.cfg.Store.Scan(r.Context(), id)
}

func (s *server) getScan(w http.ResponseWriter, r *http.Request) {
	sc, ok, err := s.scanSummary(r, r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if !ok {
		writeError(w, http.StatusNotFound, "no such scan")
		return
	}
	writeJSON(w, http.StatusOK, publicScan(sc))
}

func (s *server) cancelScan(w http.ResponseWriter, r *http.Request) {
	if !s.cfg.Manager.Cancel(r.PathValue("id")) {
		writeError(w, http.StatusConflict, "scan is not running")
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]string{"status": "canceling"})
}

func (s *server) filter(r *http.Request) (storage.Filter, error) {
	q := r.URL.Query()
	f := storage.Filter{Kind: q.Get("kind"), Transport: q.Get("transport"), Service: q.Get("service"), Unknown: q.Get("unknown") == "true"}
	if a := q.Get("address"); a != "" {
		addr, err := netip.ParseAddr(a)
		if err != nil {
			return f, fmt.Errorf("address: %w", err)
		}
		f.Address = addr
	}
	if p := q.Get("port"); p != "" {
		n, err := strconv.ParseUint(p, 10, 16)
		if err != nil {
			return f, fmt.Errorf("port: %w", err)
		}
		f.Port = uint16(n)
	}
	limit, err := intParam(r, "limit", 1000, 10000)
	f.Limit = limit
	return f, err
}

func (s *server) scanObservations(w http.ResponseWriter, r *http.Request) {
	f, err := s.filter(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	f.ScanID = r.PathValue("id")
	s.writeObservations(w, r, f)
}

func (s *server) observations(w http.ResponseWriter, r *http.Request) {
	f, err := s.filter(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	s.writeObservations(w, r, f)
}

func (s *server) writeObservations(w http.ResponseWriter, r *http.Request, f storage.Filter) {
	obs, err := s.cfg.Store.Observations(r.Context(), f)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if obs == nil {
		obs = []observe.Observation{}
	}
	writeJSON(w, http.StatusOK, obs)
}

// resolveSource reads an immutable container through the existing authenticated
// API guard. The request carries a reference, never a filesystem path.
func (s *server) resolveSource(w http.ResponseWriter, r *http.Request) {
	var ref observe.SourceRef
	d := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096))
	d.DisallowUnknownFields()
	if err := d.Decode(&ref); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	var trailing any
	if err := d.Decode(&trailing); err != io.EOF {
		writeError(w, http.StatusBadRequest, "trailing source reference data")
		return
	}
	if err := ref.Validate(); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	result, err := s.cfg.Store.ResolveSource(r.Context(), ref)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (s *server) scanEvidence(w http.ResponseWriter, r *http.Request) {
	var addr netip.Addr
	if a := r.URL.Query().Get("address"); a != "" {
		var err error
		if addr, err = netip.ParseAddr(a); err != nil {
			writeError(w, http.StatusBadRequest, "address: "+err.Error())
			return
		}
	}
	ev, err := s.cfg.Store.PacketEvidence(r.Context(), r.PathValue("id"), addr)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	for i := range ev {
		ev[i].Capture = filepath.Base(ev[i].Capture)
	}
	if ev == nil {
		ev = []observe.PacketEvidence{}
	}
	writeJSON(w, http.StatusOK, ev)
}

// scanPCAPNG serves a capture only when it lies inside the evidence
// directory; CLI captures elsewhere on disk are never exposed.
func (s *server) scanPCAPNG(w http.ResponseWriter, r *http.Request) {
	sc, ok, err := s.scanSummary(r, r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if !ok || sc.Capture == nil || s.cfg.EvidenceDir == "" || sc.Status == "running" {
		writeError(w, http.StatusNotFound, "no finished capture for this scan")
		return
	}
	dir, err := filepath.Abs(s.cfg.EvidenceDir)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	path, err := filepath.Abs(sc.Capture.Path)
	if err != nil || filepath.Dir(path) != dir {
		writeError(w, http.StatusNotFound, "capture is outside the evidence directory")
		return
	}
	f, err := os.Open(path)
	if err != nil {
		writeError(w, http.StatusNotFound, "capture file is missing")
		return
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil || !fi.Mode().IsRegular() {
		writeError(w, http.StatusNotFound, "capture file is missing")
		return
	}
	if sc.Capture.ArtifactID != "" {
		// Verify the retained container outside packet RX. Use the same opened
		// file for download so path replacement cannot select different bytes.
		digest := sha256.New()
		if fi.Size() != sc.Capture.Bytes {
			writeError(w, http.StatusNotFound, "capture artifact is unavailable: size changed")
			return
		}
		if _, err := io.Copy(digest, io.LimitReader(f, sc.Capture.Bytes+1)); err != nil || "sha256:"+hex.EncodeToString(digest.Sum(nil)) != sc.Capture.ArtifactID {
			writeError(w, http.StatusNotFound, "capture artifact is unavailable: hash mismatch")
			return
		}
		if _, err := f.Seek(0, io.SeekStart); err != nil {
			writeError(w, http.StatusInternalServerError, "cannot read capture")
			return
		}
	}
	w.Header().Set("Content-Type", "application/vnd.tcpdump.pcap")
	w.Header().Set("Content-Disposition", `attachment; filename="`+filepath.Base(path)+`"`)
	http.ServeContent(w, r, filepath.Base(path), fi.ModTime(), f)
}

// assets lists stored addresses. open=true keeps only open ports (and the
// hosts that have one); scope narrows addresses by IP, CIDR or range.
func (s *server) assets(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	scope, err := config.ParseScope(q["scope"])
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	assets, err := s.cfg.Store.Assets(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if q.Get("open") == "true" {
		assets = storage.OpenOnly(assets)
	}
	out := make([]storage.Asset, 0, len(assets))
	for _, a := range assets {
		if scope.Contains(a.Address) {
			out = append(out, a)
		}
	}
	writeJSON(w, http.StatusOK, out)
}

// identities exposes the correlated asset graph with its source observations.
func (s *server) identities(w http.ResponseWriter, r *http.Request) {
	graph, err := s.cfg.Store.IdentityGraph(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, graph)
}

func (s *server) identity(w http.ResponseWriter, r *http.Request) {
	graph, err := s.cfg.Store.IdentityGraph(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	for _, asset := range graph {
		if asset.ID == r.PathValue("id") {
			writeJSON(w, http.StatusOK, asset)
			return
		}
	}
	writeError(w, http.StatusNotFound, "asset identity not found")
}

func (s *server) identityEvents(w http.ResponseWriter, r *http.Request) {
	var address netip.Addr
	if raw := r.URL.Query().Get("address"); raw != "" {
		var err error
		address, err = netip.ParseAddr(raw)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid address")
			return
		}
	}
	events, err := s.cfg.Store.IdentityHistory(r.Context(), address)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, events)
}

func (s *server) identityRelations(w http.ResponseWriter, r *http.Request) {
	relations, err := s.cfg.Store.IdentityRelations(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, relations)
}

func (s *server) identityReviews(w http.ResponseWriter, r *http.Request) {
	reviews, err := s.cfg.Store.IdentityReviews(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, reviews)
}

func (s *server) reviewIdentity(w http.ResponseWriter, r *http.Request) {
	var input struct {
		AddressA string `json:"address_a"`
		AddressB string `json:"address_b"`
		Decision string `json:"decision"`
		Note     string `json:"note"`
	}
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		writeError(w, http.StatusBadRequest, "invalid review JSON")
		return
	}
	a, errA := netip.ParseAddr(input.AddressA)
	b, errB := netip.ParseAddr(input.AddressB)
	if errA != nil || errB != nil {
		writeError(w, http.StatusBadRequest, "two valid IP addresses are required")
		return
	}
	if err := s.cfg.Store.ReviewIdentityPair(r.Context(), a, b, input.Decision, input.Note); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, map[string]string{"status": "recorded"})
}

func (s *server) topology(w http.ResponseWriter, r *http.Request) {
	links, err := s.cfg.Store.PassiveLinks(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, links)
}

// scanEvents streams Server-Sent Events: buffered history first, then live
// events, ending with the final scan summary. A finished scan yields its
// stored summary. A client that falls behind is sent "lagged" and
// disconnected; it resumes with Last-Event-ID or reads storage.
func (s *server) scanEvents(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	flusher, ok := w.(http.Flusher)
	if !ok {
		writeError(w, http.StatusInternalServerError, "streaming unsupported")
		return
	}
	var after uint64
	if v := first(r.Header.Get("Last-Event-ID"), r.URL.Query().Get("after")); v != "" {
		n, err := strconv.ParseUint(v, 10, 64)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid Last-Event-ID")
			return
		}
		after = n
	}
	run := s.cfg.Manager.lookup(id)
	if run == nil {
		sc, ok, err := s.cfg.Store.Scan(r.Context(), id)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		if !ok {
			writeError(w, http.StatusNotFound, "no such scan")
			return
		}
		startSSE(w)
		bw := bufio.NewWriter(w)
		data, _ := json.Marshal(publicScan(sc))
		writeSSE(bw, Event{Type: observe.KindScan, Data: data})
		_ = bw.Flush()
		flusher.Flush()
		return
	}
	replay, sub, gap := run.hub.subscribe(after)
	if sub != nil {
		defer run.hub.unsubscribe(sub)
	}
	startSSE(w)
	bw := bufio.NewWriter(w)
	if gap {
		writeSSE(bw, Event{Type: "gap", Data: json.RawMessage(`{"reason":"older events evicted; read them from /observations"}`)})
	}
	for _, e := range replay {
		writeSSE(bw, e)
	}
	if bw.Flush() != nil {
		return
	}
	flusher.Flush()
	if sub == nil {
		return
	}
	keepalive := time.NewTicker(15 * time.Second)
	defer keepalive.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case <-keepalive.C:
			if _, err := io.WriteString(bw, ": keepalive\n\n"); err != nil {
				return
			}
		case e, ok := <-sub.ch:
			if !ok {
				if run.hub.isLagged(sub) {
					writeSSE(bw, Event{Type: "lagged", Data: json.RawMessage(`{"reason":"client fell behind; reconnect with Last-Event-ID"}`)})
					_ = bw.Flush()
					flusher.Flush()
				}
				return
			}
			writeSSE(bw, e)
			// Drain what is already queued before flushing.
			for more := true; more; {
				select {
				case e, ok := <-sub.ch:
					if !ok {
						more = false
						break
					}
					writeSSE(bw, e)
				default:
					more = false
				}
			}
		}
		if bw.Flush() != nil {
			return
		}
		flusher.Flush()
	}
}

// publicScan hides server file-system layout: clients see only the capture
// file name, which is also the download name.
func publicScan(sc observe.Scan) observe.Scan {
	if sc.Capture != nil {
		c := *sc.Capture
		c.Path = filepath.Base(c.Path)
		sc.Capture = &c
	}
	return sc
}

func startSSE(w http.ResponseWriter) {
	h := w.Header()
	h.Set("Content-Type", "text/event-stream")
	h.Set("Cache-Control", "no-store")
	h.Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)
}

func writeSSE(w *bufio.Writer, e Event) {
	if e.Seq > 0 {
		fmt.Fprintf(w, "id: %d\n", e.Seq)
	}
	fmt.Fprintf(w, "event: %s\ndata: ", e.Type)
	// JSON never contains a raw newline, so one data line suffices.
	w.Write(bytes.TrimSpace(e.Data))
	w.WriteString("\n\n")
}

func intParam(r *http.Request, name string, def, max int) (int, error) {
	v := r.URL.Query().Get(name)
	if v == "" {
		return def, nil
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < 1 || n > max {
		return 0, fmt.Errorf("%s must be 1..%d", name, max)
	}
	return n, nil
}

func first(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}
