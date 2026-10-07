package service

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"

	"github.com/matusso/nyxr/internal/observe"
)

var envoyVersion = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+(?:-[a-zA-Z0-9.+-]+)?$`)

// validateProduct adds a product hypothesis only after observed HTTP metadata
// makes its read-only validator useful. A failed validator keeps the proven
// protocol and header claim; it never promotes another product by elimination.
func (e *Engine) validateProduct(ctx context.Context, t Target, o *observe.Observation) {
	if ctx.Err() != nil || !e.enabled[ProbeHTTP] ||
		!strings.EqualFold(o.Product, "envoy") || (o.Service != "http" && o.Service != "https") {
		return
	}
	name := "envoy-validation"
	p := &probePlanner{
		transport: "product", families: []string{name, "unknown"}, prob: []float64{0.6, 0.4},
		candidates: map[string]bool{name: true}, attempted: map[string]bool{},
	}
	probe, gain, score := p.next()
	if probe == "" || gain < 0.0001 || !e.probeBudget(o) {
		return
	}
	before := p.probabilities()
	o.ProbeDecisions = append(o.ProbeDecisions, observe.ProbeDecision{
		Probe: name, InformationGain: gain, Score: score, Hypotheses: before,
	})
	o.ProbesAttempted = append(o.ProbesAttempted, name)
	start := len(o.Evidence)
	var temp observe.Observation
	var ev observe.Evidence
	var data []byte
	var ok bool
	if o.TLS != nil {
		alpn := []string{"http/1.1"}
		if o.TLS.ALPN == "h2" {
			alpn = []string{"h2"}
		}
		tc, handshake, connected := e.handshake(ctx, t, alpn)
		o.Evidence = append(o.Evidence, handshake)
		if !connected {
			p.observeExchange(o, name, false, start, before, e)
			return
		}
		defer tc.Close()
		if tc.ConnectionState().NegotiatedProtocol == "h2" {
			ev, data, ok = e.probeHTTP2Exchange(ctx, t, tc, "/server_info", &temp)
		} else {
			ev, data, ok = e.probeHTTPExchange(ctx, t, tc, "tls", "/server_info", &temp)
		}
	} else {
		ev, data, ok = e.probeHTTPExchange(ctx, t, nil, "tcp", "/server_info", &temp)
	}
	ev.Probe, ev.Matched = name, ""
	version, validated := parseEnvoyInfo(data)
	ok = ok && validated
	if ok {
		ev.Matched = name
		o.Product, o.Version = "Envoy Proxy", version
		o.Attributes["envoy.validation"] = "server_info"
		o.Reason += "; Envoy server_info grammar validated"
	}
	o.Evidence = append(o.Evidence, ev)
	p.observeExchange(o, name, ok, start, before, e)
	if ok {
		o.Attributes["envoy.confidence"] = strconv.Itoa(p.confidence(name))
	}
}

// This grammar follows Envoy's documented GET /server_info response. Generic
// JSON containing a version or a Server header alone is not validation.
func parseEnvoyInfo(data []byte) (string, bool) {
	resp, err := http.ReadResponse(bufio.NewReader(bytes.NewReader(data)), nil)
	if err != nil {
		return "", false
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return "", false
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxHTTPRead+1))
	if err != nil || len(body) > maxHTTPRead {
		return "", false
	}
	var info struct {
		Version string                     `json:"version"`
		State   string                     `json:"state"`
		Options map[string]json.RawMessage `json:"command_line_options"`
		Uptime  string                     `json:"uptime_current_epoch"`
	}
	if json.Unmarshal(body, &info) != nil || len(info.Options) == 0 || info.Uptime == "" {
		return "", false
	}
	switch info.State {
	case "LIVE", "DRAINING", "PRE_INITIALIZING", "INITIALIZING":
	default:
		return "", false
	}
	parts := strings.Split(info.Version, "/")
	if len(parts) < 4 || len(parts[0]) < 7 || len(parts[0]) > 64 || !envoyVersion.MatchString(parts[1]) ||
		(parts[2] != "Clean" && parts[2] != "Modified") || (parts[3] != "RELEASE" && parts[3] != "DEBUG") {
		return "", false
	}
	for _, c := range parts[0] {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return "", false
		}
	}
	return parts[1], true
}
