package sse

import (
	"log"
	"net/http"
	"xkeen-panel/internal/models"
)

// StatusProvider supplies the current status (implemented by the watchdog).
type StatusProvider interface {
	GetStatus() models.Status
}

// HandleEvents streams status, logs and restart events over SSE.
func HandleEvents(bus *EventBus, sp StatusProvider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		flusher, ok := w.(http.Flusher)
		if !ok {
			http.Error(w, "streaming not supported", http.StatusInternalServerError)
			return
		}

		ch := bus.Subscribe()
		if ch == nil {
			http.Error(w, `{"error":"too many SSE clients"}`, http.StatusServiceUnavailable)
			return
		}
		defer bus.Unsubscribe(ch)

		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("Connection", "keep-alive")
		w.Header().Set("X-Accel-Buffering", "no")

		// Send the current status on connect
		initial := Event{Type: "status", Data: sp.GetStatus()}
		if data, err := FormatSSE(initial); err == nil {
			w.Write(data)
			flusher.Flush()
		}

		// Stream events from the EventBus
		for {
			select {
			case <-r.Context().Done():
				return
			case evt, ok := <-ch:
				if !ok {
					return
				}
				data, err := FormatSSE(evt)
				if err != nil {
					log.Printf("[SSE] Ошибка сериализации: %v", err)
					continue
				}
				if _, err := w.Write(data); err != nil {
					return
				}
				flusher.Flush()
			}
		}
	}
}
