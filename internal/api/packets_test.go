package api

import (
	"context"
	"encoding/hex"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/matusso/nyxr/internal/packetio"
)

type packetTestIO struct {
	frame []byte
	sent  []byte
	read  bool
}

func (p *packetTestIO) ReceiveBatch(_ context.Context, buffers [][]byte) (int, error) {
	if p.read {
		return 0, io.EOF
	}
	p.read = true
	buffers[0] = buffers[0][:copy(buffers[0], p.frame)]
	return 1, nil
}
func (p *packetTestIO) SendBatch(_ context.Context, frames [][]byte) (int, error) {
	p.sent = append([]byte(nil), frames[0]...)
	return 1, nil
}
func (p *packetTestIO) Stats() packetio.Stats { return packetio.Stats{} }
func (p *packetTestIO) Close() error          { return nil }

func TestPacketWatchAndSend(t *testing.T) {
	frame, _ := hex.DecodeString("0102030405060a0b0c0d0e0f0800")
	fake := &packetTestIO{frame: frame}
	manager := &Manager{cfg: ManagerConfig{OpenLive: func(device string) (packetio.PacketIO, error) {
		if device != "test0" {
			t.Fatalf("unexpected interface %q", device)
		}
		return fake, nil
	}}}
	handler := Handler(ServerConfig{Manager: manager, PacketSendEnabled: true})

	watch := httptest.NewRecorder()
	handler.ServeHTTP(watch, httptest.NewRequest(http.MethodGet, "/api/v1/packets/watch?interface=test0", nil))
	if watch.Code != http.StatusOK || !strings.Contains(watch.Body.String(), `"hex":"`+hex.EncodeToString(frame)+`"`) || !strings.Contains(watch.Body.String(), "event: packet") {
		t.Fatalf("watch: %d %s", watch.Code, watch.Body.String())
	}

	send := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/packets/send", strings.NewReader(`{"interface":"test0","hex":"01 02 03 04 05 06 0a 0b 0c 0d 0e 0f 08 00"}`))
	req.Header.Set("Content-Type", "application/json")
	handler.ServeHTTP(send, req)
	if send.Code != http.StatusAccepted || hex.EncodeToString(fake.sent) != hex.EncodeToString(frame) {
		t.Fatalf("send: %d %s, frame %x", send.Code, send.Body.String(), fake.sent)
	}
}

func TestPacketSendRefusals(t *testing.T) {
	fake := &packetTestIO{}
	manager := &Manager{cfg: ManagerConfig{OpenLive: func(string) (packetio.PacketIO, error) { return fake, nil }}}
	for _, tc := range []struct {
		name    string
		enabled bool
		body    string
		code    int
	}{
		{"disabled", false, `{"interface":"test0","hex":"0102030405060a0b0c0d0e0f0800"}`, http.StatusForbidden},
		{"short frame", true, `{"interface":"test0","hex":"abcd"}`, http.StatusBadRequest},
		{"bad hex", true, `{"interface":"test0","hex":"0102030405060a0b0c0d0e0f080x"}`, http.StatusBadRequest},
		{"missing interface", true, `{"hex":"0102030405060a0b0c0d0e0f0800"}`, http.StatusBadRequest},
		{"extra field", true, `{"interface":"test0","hex":"0102030405060a0b0c0d0e0f0800","count":100}`, http.StatusBadRequest},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodPost, "/api/v1/packets/send", strings.NewReader(tc.body))
			req.Header.Set("Content-Type", "application/json")
			Handler(ServerConfig{Manager: manager, PacketSendEnabled: tc.enabled}).ServeHTTP(w, req)
			if w.Code != tc.code || len(fake.sent) != 0 {
				t.Fatalf("response %d %s, sent %x", w.Code, w.Body.String(), fake.sent)
			}
		})
	}
}
