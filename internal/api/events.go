package api

import (
	"encoding/json"
	"sync"
)

// Event is one live record of a running scan. Seq increases by one per event
// so a reconnecting client can resume with Last-Event-ID.
type Event struct {
	Seq  uint64          `json:"seq"`
	Type string          `json:"type"` // observation, packet-evidence, scan
	Data json.RawMessage `json:"data"`
}

const (
	// historySize bounds events retained for replay to late or reconnecting
	// subscribers. Older events remain available from storage.
	historySize = 4096
	// subscriberBuffer bounds events queued for one subscriber. A subscriber
	// that falls this far behind is disconnected instead of slowing the scan.
	subscriberBuffer = 256
)

// hub fans one scan's events out to subscribers without ever blocking the
// publisher: memory per scan and per subscriber is fixed.
type hub struct {
	mu     sync.Mutex
	ring   []Event // circular, len <= historySize
	start  int     // index of the oldest event in ring
	next   uint64  // Seq of the next event
	subs   map[*subscriber]struct{}
	closed bool
}

type subscriber struct {
	ch     chan Event
	lagged bool // set when dropped for falling behind
}

func newHub() *hub { return &hub{next: 1, subs: map[*subscriber]struct{}{}} }

func (h *hub) publish(typ string, v any) {
	data, err := json.Marshal(v)
	if err != nil {
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.closed {
		return
	}
	e := Event{Seq: h.next, Type: typ, Data: data}
	h.next++
	if len(h.ring) < historySize {
		h.ring = append(h.ring, e)
	} else {
		h.ring[h.start] = e
		h.start = (h.start + 1) % historySize
	}
	for s := range h.subs {
		select {
		case s.ch <- e:
		default:
			s.lagged = true
			close(s.ch)
			delete(h.subs, s)
		}
	}
}

// subscribe returns buffered events after seq and a live subscriber. The
// subscriber is nil when the hub is closed; replay then holds everything
// retained. gap reports that events after seq were already evicted.
func (h *hub) subscribe(after uint64) (replay []Event, s *subscriber, gap bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for i := 0; i < len(h.ring); i++ {
		e := h.ring[(h.start+i)%len(h.ring)]
		if i == 0 && e.Seq > after+1 {
			gap = true
		}
		if e.Seq > after {
			replay = append(replay, e)
		}
	}
	if h.closed {
		return replay, nil, gap
	}
	s = &subscriber{ch: make(chan Event, subscriberBuffer)}
	h.subs[s] = struct{}{}
	return replay, s, gap
}

func (h *hub) unsubscribe(s *subscriber) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if _, ok := h.subs[s]; ok {
		delete(h.subs, s)
		close(s.ch)
	}
}

// isLagged reports whether s was dropped for falling behind.
func (h *hub) isLagged(s *subscriber) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	return s.lagged
}

// close ends every subscription after the final event.
func (h *hub) close() {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.closed = true
	for s := range h.subs {
		close(s.ch)
		delete(h.subs, s)
	}
}
