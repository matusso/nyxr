package api

import (
	"bufio"
	"context"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/matusso/nyxr/internal/packet"
	"github.com/matusso/nyxr/internal/packetd"
)

type watchedPacket struct {
	Timestamp time.Time       `json:"timestamp"`
	Length    int             `json:"length"`
	Hex       string          `json:"hex"`
	Summary   string          `json:"summary"`
	Decoded   *packet.Decoded `json:"decoded,omitempty"`
}

func packetInterface(name string) error {
	if name == "" || len(name) > 128 || strings.TrimSpace(name) != name || strings.ContainsAny(name, "\x00\r\n") {
		return errors.New("interface is required")
	}
	return nil
}

// watchPackets owns a packetd session for the lifetime of this response. The
// browser retains only its most recent rows; no captured bytes are persisted.
func (s *server) watchPackets(w http.ResponseWriter, r *http.Request) {
	if s.cfg.Manager == nil || s.cfg.Manager.cfg.OpenLive == nil {
		writeError(w, http.StatusServiceUnavailable, "packet watching needs --packetd")
		return
	}
	device := r.URL.Query().Get("interface")
	if err := packetInterface(device); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	pio, err := s.cfg.Manager.cfg.OpenLive(device)
	if err != nil {
		writeError(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	defer pio.Close()
	flusher, ok := w.(http.Flusher)
	if !ok {
		writeError(w, http.StatusInternalServerError, "streaming unsupported")
		return
	}
	startSSE(w)
	bw := bufio.NewWriter(w)
	_, _ = bw.WriteString(": watching\n\n")
	_ = bw.Flush()
	flusher.Flush()

	decoder := packet.NewDecoder()
	buffers := make([][]byte, 32)
	for i := range buffers {
		buffers[i] = make([]byte, packetd.MaxFrame)
	}
	window := time.Now()
	sent, skipped := 0, 0
	for r.Context().Err() == nil {
		n, err := pio.ReceiveBatch(r.Context(), buffers)
		if err != nil {
			if !errors.Is(err, context.Canceled) && r.Context().Err() == nil {
				writePacketEvent(bw, "error", map[string]string{"error": err.Error()})
				_ = bw.Flush()
				flusher.Flush()
			}
			return
		}
		if time.Since(window) >= time.Second {
			if skipped > 0 {
				writePacketEvent(bw, "sampled", map[string]int{"skipped": skipped})
			}
			window, sent, skipped = time.Now(), 0, 0
		}
		for i := 0; i < n; i++ {
			frame := buffers[i]
			if sent >= 100 {
				skipped++
			} else {
				p := watchedPacket{Timestamp: time.Now().UTC(), Length: len(frame), Hex: hex.EncodeToString(frame)}
				if decoded, ok := decoder.Decode(frame); ok {
					p.Decoded = &decoded
					p.Summary = fmt.Sprintf("%s %s:%d → %s:%d", decoded.Protocol, decoded.Source, decoded.SourcePort, decoded.Destination, decoded.DestPort)
				} else if len(frame) >= 14 {
					p.Summary = fmt.Sprintf("EtherType 0x%04x", binary.BigEndian.Uint16(frame[12:14]))
				} else {
					p.Summary = "short frame"
				}
				writePacketEvent(bw, "packet", p)
				sent++
			}
			buffers[i] = frame[:cap(frame)]
		}
		if bw.Flush() != nil {
			return
		}
		flusher.Flush()
	}
}

func writePacketEvent(w *bufio.Writer, typ string, value any) {
	b, _ := json.Marshal(value)
	fmt.Fprintf(w, "event: %s\ndata: %s\n\n", typ, b)
}

func (s *server) sendPacket(w http.ResponseWriter, r *http.Request) {
	if !s.cfg.PacketSendEnabled {
		writeError(w, http.StatusForbidden, "packet sending is disabled; start serve with --allow-packet-send")
		return
	}
	if s.cfg.Manager == nil || s.cfg.Manager.cfg.OpenLive == nil {
		writeError(w, http.StatusServiceUnavailable, "packet sending needs --packetd")
		return
	}
	var input struct {
		Interface string `json:"interface"`
		Hex       string `json:"hex"`
	}
	d := json.NewDecoder(r.Body)
	d.DisallowUnknownFields()
	if err := d.Decode(&input); err != nil {
		writeError(w, http.StatusBadRequest, "invalid packet request: "+err.Error())
		return
	}
	var extra any
	if err := d.Decode(&extra); err != io.EOF {
		writeError(w, http.StatusBadRequest, "invalid packet request: trailing data")
		return
	}
	if err := packetInterface(input.Interface); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	clean := strings.Map(func(c rune) rune {
		if c == ' ' || c == '\n' || c == '\r' || c == '\t' {
			return -1
		}
		return c
	}, input.Hex)
	if len(clean) < packetd.MinFrame*2 || len(clean) > packetd.MaxFrame*2 {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("frame must be %d..%d bytes", packetd.MinFrame, packetd.MaxFrame))
		return
	}
	frame, err := hex.DecodeString(clean)
	if err != nil {
		writeError(w, http.StatusBadRequest, "frame must contain hexadecimal bytes")
		return
	}
	pio, err := s.cfg.Manager.cfg.OpenLive(input.Interface)
	if err != nil {
		writeError(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	defer pio.Close()
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	n, err := pio.SendBatch(ctx, [][]byte{frame})
	if err != nil || n != 1 {
		writeError(w, http.StatusBadGateway, fmt.Sprintf("packetd send: %v", err))
		return
	}
	// packetd can still reject a frame under its own interface policy.
	writeJSON(w, http.StatusAccepted, map[string]any{"status": "submitted", "bytes": len(frame)})
}
