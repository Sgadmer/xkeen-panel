package sse

import (
	"net/http"
	"time"
)

// Older clients can still attach to a finite SSE stream. Disconnecting stops
// delivery to that browser. The shared job belongs to the server.
func (j *ProbeJobs) Stream(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming not supported", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("X-Accel-Buffering", "no")
	send := func(kind string, data any) bool {
		body, err := FormatSSE(Event{Type: kind, Data: data})
		if err != nil {
			return false
		}
		if _, err := w.Write(body); err != nil {
			return false
		}
		flusher.Flush()
		return true
	}
	run := j.start()
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	sent := 0
	for {
		s := j.snapshot(run)
		for _, m := range s.Results[sent:] {
			if !send("latency", m) {
				return
			}
		}
		sent = len(s.Results)
		if !send("progress", map[string]any{"total": len(s.IDs), "completed": sent, "probe_kind": "https"}) {
			return
		}
		if !s.Running {
			if s.Error != "" {
				send("failure", map[string]string{"error": s.Error})
			} else {
				send("done", map[string]any{"complete": true, "total": len(s.IDs), "probe_kind": "https"})
			}
			return
		}
		select {
		case <-r.Context().Done():
			return
		case <-run.done:
		case <-tick.C:
		}
	}
}
