package service

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"strings"
	"time"

	"github.com/matusso/nyxr/internal/observe"
	"gopkg.in/yaml.v3"
)

type fixtureFile struct {
	Schema     string        `yaml:"schema"`
	Provenance string        `yaml:"provenance"`
	Cases      []fixtureCase `yaml:"cases"`
}

type fixtureCase struct {
	Name          string            `yaml:"name"`
	Kind          string            `yaml:"kind"`
	Protocol      string            `yaml:"protocol"`
	Exchanges     []fixtureExchange `yaml:"exchanges"`
	Service       string            `yaml:"service"`
	Fields        map[string]string `yaml:"fields"`
	ConfidenceMin *int              `yaml:"confidence_min"`
	ConfidenceMax *int              `yaml:"confidence_max"`
	Error         bool              `yaml:"error"`
}

type fixtureExchange struct {
	RequestHex  string `yaml:"request_hex"`
	ResponseHex string `yaml:"response_hex"`
}

type FixtureResult struct {
	Name       string `json:"name"`
	Kind       string `json:"kind"`
	Passed     bool   `json:"passed"`
	Detail     string `json:"detail,omitempty"`
	Service    string `json:"service,omitempty"`
	Confidence int    `json:"confidence"`
}

// RunProtocolFixtures replays bounded synthetic responses through the ordinary
// executor and planner. It never opens a network socket or sends live traffic.
func RunProtocolFixtures(definitions []ProtocolDefinition, path string) ([]FixtureResult, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, 1<<20+1))
	if err != nil {
		return nil, err
	}
	if len(data) > 1<<20 {
		return nil, errors.New("protocol fixture exceeds 1 MiB")
	}
	var file fixtureFile
	dec := yaml.NewDecoder(strings.NewReader(string(data)))
	dec.KnownFields(true)
	if err := dec.Decode(&file); err != nil {
		return nil, err
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		return nil, errors.New("fixture file must contain exactly one YAML document")
	}
	if file.Schema != "nyxr/protocol-fixtures/v1" || strings.TrimSpace(file.Provenance) == "" || len(file.Cases) == 0 || len(file.Cases) > 64 {
		return nil, errors.New("fixture requires schema, provenance and 1..64 cases")
	}
	byName := make(map[string]ProtocolDefinition, len(definitions))
	for _, d := range definitions {
		byName[d.Name] = d
	}
	seen := map[string]bool{}
	results := make([]FixtureResult, 0, len(file.Cases))
	for _, c := range file.Cases {
		if c.Name == "" || seen[c.Name] || len(c.Exchanges) > 32 || (c.Kind != "positive" && c.Kind != "negative" && c.Kind != "truncated" && c.Kind != "noisy") {
			return nil, fmt.Errorf("invalid fixture case %q", c.Name)
		}
		seen[c.Name] = true
		d, ok := byName[c.Protocol]
		if !ok || len(d.steps) == 1 && (d.steps[0].DTLS || d.steps[0].QUIC) {
			return nil, fmt.Errorf("fixture %q requires a non-native protocol definition", c.Name)
		}
		if c.ConfidenceMin != nil && (*c.ConfidenceMin < 0 || *c.ConfidenceMin > 100) || c.ConfidenceMax != nil && (*c.ConfidenceMax < 0 || *c.ConfidenceMax > 100) {
			return nil, fmt.Errorf("fixture %q has invalid confidence bounds", c.Name)
		}
		var exchanges [][2][]byte
		for _, x := range c.Exchanges {
			request, err := hex.DecodeString(strings.Join(strings.Fields(x.RequestHex), ""))
			if err != nil || len(request) > 4096 {
				return nil, fmt.Errorf("fixture %q has invalid request hex", c.Name)
			}
			response, err := hex.DecodeString(strings.Join(strings.Fields(x.ResponseHex), ""))
			if err != nil || len(response) > 4096 {
				return nil, fmt.Errorf("fixture %q has invalid response hex", c.Name)
			}
			exchanges = append(exchanges, [2][]byte{request, response})
		}
		result := runFixtureCase(d, c, exchanges)
		results = append(results, result)
	}
	return results, nil
}

func runFixtureCase(d ProtocolDefinition, c fixtureCase, exchanges [][2][]byte) FixtureResult {
	result := FixtureResult{Name: c.Name, Kind: c.Kind}
	dial := func(context.Context, string, string) (net.Conn, error) {
		client, server := net.Pipe()
		go func() {
			defer server.Close()
			for _, x := range exchanges {
				request := make([]byte, len(x[0]))
				if _, err := io.ReadFull(server, request); err != nil || !equalBytes(request, x[0]) {
					return
				}
				if _, err := server.Write(x[1]); err != nil {
					return
				}
			}
		}()
		return client, nil
	}
	e, err := Start(context.Background(), Config{Definitions: []ProtocolDefinition{d}, Timeout: min(d.Timeout, time.Second), Workers: 1, Dial: dial}, func(observe.Observation) {})
	if err != nil {
		result.Detail = err.Error()
		return result
	}
	o := e.Interrogate(context.Background(), Target{Addr: netip.MustParseAddr("127.0.0.1"), Port: d.Ports[0], Transport: d.Transport})
	e.Close()
	result.Service, result.Confidence = o.Service, o.Confidence
	if o.Service != c.Service {
		result.Detail = fmt.Sprintf("service %q, want %q", o.Service, c.Service)
		return result
	}
	for name, want := range c.Fields {
		if got := o.Attributes[name]; got != want {
			result.Detail = fmt.Sprintf("field %s = %q, want %q", name, got, want)
			return result
		}
	}
	if c.ConfidenceMin != nil && o.Confidence < *c.ConfidenceMin || c.ConfidenceMax != nil && o.Confidence > *c.ConfidenceMax {
		result.Detail = fmt.Sprintf("confidence %d outside expected range", o.Confidence)
		return result
	}
	hasError := false
	for _, ev := range o.Evidence {
		hasError = hasError || ev.Error != ""
	}
	if hasError != c.Error {
		result.Detail = fmt.Sprintf("evidence error = %t, want %t", hasError, c.Error)
		return result
	}
	result.Passed = true
	return result
}

func equalBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
