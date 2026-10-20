package api

import (
	"net/http"
	"sync/atomic"
	"time"

	"golang.org/x/net/websocket"

	"tross/core/event"
)

// Поток для интерфейса: события шины и состояние каналов раз в
// wsLinksEvery — вместо опроса.
const (
	wsLinksEvery = 2 * time.Second
	wsMax        = 16
)

type wsMessage struct {
	Type  string      `json:"type"` // event | links
	Topic event.Topic `json:"topic,omitempty"`
	Time  time.Time   `json:"time,omitzero"`
	Data  any         `json:"data,omitempty"`
}

var wsOpen atomic.Int32

func (s *Server) handleWS(w http.ResponseWriter, r *http.Request) {
	// Чужая страница не подключится и с чужой cookie (SameSite=Strict её
	// и так не пришлёт) — проверка Origin вдобавок.
	if r.Header.Get("Origin") == "" || !sameOrigin(r) {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "cross-origin websocket"})
		return
	}
	if wsOpen.Add(1) > wsMax {
		wsOpen.Add(-1)
		writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": "too many live connections"})
		return
	}
	defer wsOpen.Add(-1)
	srv := websocket.Server{Handshake: func(*websocket.Config, *http.Request) error { return nil }, Handler: func(c *websocket.Conn) {
		defer c.Close()
		var evs <-chan event.Event
		if s.opts.Events != nil {
			ch, unsub := s.opts.Events()
			defer unsub()
			evs = ch
		}
		// Чтение — только чтобы заметить закрытие со стороны браузера.
		closed := make(chan struct{})
		go func() {
			var b []byte
			for websocket.Message.Receive(c, &b) == nil {
			}
			close(closed)
		}()
		t := time.NewTicker(wsLinksEvery)
		defer t.Stop()
		send := func(m wsMessage) bool {
			_ = c.SetWriteDeadline(time.Now().Add(5 * time.Second))
			return websocket.JSON.Send(c, m) == nil
		}
		links := func() bool {
			snap := s.opts.Monitor.Snapshot()
			out := make([]linkDTO, 0, len(snap))
			for _, st := range snap {
				out = append(out, toLinkDTO(st))
			}
			return send(wsMessage{Type: "links", Data: out})
		}
		if s.opts.Monitor != nil && !links() {
			return
		}
		for {
			select {
			case <-closed:
				return
			case <-r.Context().Done():
				return
			case e, ok := <-evs:
				if !ok || !send(wsMessage{Type: "event", Topic: e.Topic, Time: e.Time, Data: e.Data}) {
					return
				}
			case <-t.C:
				if s.opts.Monitor != nil && !links() {
					return
				}
			}
		}
	}}
	srv.ServeHTTP(w, r)
}
