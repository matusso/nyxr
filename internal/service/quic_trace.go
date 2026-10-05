package service

import (
	"fmt"
	"strconv"
	"strings"
	"sync"

	"github.com/quic-go/quic-go/qlog"
	"github.com/quic-go/quic-go/qlogwriter"
)

// quicTrace retains only a bounded set of peer handshake facts. The QUIC
// library owns packet parsing and decryption; this collector never stores a
// qlog or packet body.
type quicTrace struct {
	mu     sync.Mutex
	fields map[string]string
}

func newQUICTrace() *quicTrace { return &quicTrace{fields: make(map[string]string)} }

func (t *quicTrace) AddProducer() qlogwriter.Recorder { return quicTraceRecorder{trace: t} }
func (t *quicTrace) SupportsSchemas(string) bool      { return false }

func (t *quicTrace) snapshot() map[string]string {
	t.mu.Lock()
	defer t.mu.Unlock()
	out := make(map[string]string, len(t.fields))
	for key, value := range t.fields {
		out[key] = value
	}
	return out
}

type quicTraceRecorder struct{ trace *quicTrace }

func (r quicTraceRecorder) Close() error { return nil }

func (r quicTraceRecorder) RecordEvent(event qlogwriter.Event) {
	r.trace.mu.Lock()
	defer r.trace.mu.Unlock()
	f := r.trace.fields
	switch e := event.(type) {
	case qlog.ParametersSet:
		if e.Initiator != qlog.InitiatorRemote || e.Restore {
			return
		}
		f["quic.connection_id.server_initial"] = e.InitialSourceConnectionID.String()
		f["quic.transport.active_connection_id_limit"] = strconv.FormatUint(e.ActiveConnectionIDLimit, 10)
		f["quic.transport.max_udp_payload_size"] = strconv.FormatInt(int64(e.MaxUDPPayloadSize), 10)
		f["quic.transport.max_idle_timeout_ms"] = strconv.FormatInt(e.MaxIdleTimeout.Milliseconds(), 10)
		if e.MaxDatagramFrameSize > 0 {
			f["quic.transport.max_datagram_frame_size"] = strconv.FormatInt(int64(e.MaxDatagramFrameSize), 10)
		}
	case qlog.VersionNegotiationReceived:
		f["quic.version_negotiation"] = "true"
		versions := make([]string, 0, min(len(e.SupportedVersions), 16))
		for _, version := range e.SupportedVersions[:min(len(e.SupportedVersions), 16)] {
			versions = append(versions, fmt.Sprint(version))
		}
		f["quic.version_negotiation.offered"] = strings.Join(versions, ",")
	case qlog.VersionInformation:
		if len(e.ServerVersions) > 0 {
			versions := make([]string, 0, min(len(e.ServerVersions), 16))
			for _, version := range e.ServerVersions[:min(len(e.ServerVersions), 16)] {
				versions = append(versions, fmt.Sprint(version))
			}
			f["quic.versions.server"] = strings.Join(versions, ",")
		}
	}
}
