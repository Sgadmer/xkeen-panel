package sse

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"xkeen-panel/internal/models"
	"xkeen-panel/internal/xkeen"
)

type httpsLatencyProbe func(xkeen.Runtime, []models.Server, xkeen.ProbeOptions) ([]models.Server, error)

// HandleStreamHTTPSLatency keeps the familiar finite SSE stream while testing
// HTTPS through each real outbound, including UDP-based Hysteria2 endpoints.
func HandleStreamHTTPSLatency(sub *xkeen.SubscriptionManager, detector *xkeen.Detector, stateDir string, concurrency int, timeout time.Duration) http.HandlerFunc {
	return newHTTPSLatencyHandler(sub, detector.Runtime, stateDir, concurrency, timeout, xkeen.CheckServersHTTPS)
}

func newHTTPSLatencyHandler(sub *xkeen.SubscriptionManager, runtime func() xkeen.Runtime, stateDir string, concurrency int, timeout time.Duration, probe httpsLatencyProbe) http.HandlerFunc {
	if concurrency < 1 {
		concurrency = 3
	}
	if timeout < 2*time.Second {
		timeout = 8 * time.Second
	}
	return func(w http.ResponseWriter, r *http.Request) {
		flusher, ok := w.(http.Flusher)
		if !ok {
			http.Error(w, "streaming not supported", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("Connection", "keep-alive")
		w.Header().Set("X-Accel-Buffering", "no")
		send := func(event string, value interface{}) bool {
			data, err := FormatSSE(Event{Type: event, Data: value})
			if err != nil {
				return false
			}
			if _, err = w.Write(data); err != nil {
				return false
			}
			flusher.Flush()
			return true
		}
		servers := sub.GetServers()
		if !send("progress", map[string]interface{}{"completed": 0, "total": len(servers), "probe_kind": "https"}) {
			return
		}
		if len(servers) == 0 {
			send("done", map[string]interface{}{"complete": true, "total": 0, "probe_kind": "https"})
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 120*time.Second)
		defer cancel()
		type batchResult struct {
			servers []models.Server
			err     error
		}
		results := make(chan batchResult, 1)
		go func() {
			checked, err := probe(runtime(), servers, xkeen.ProbeOptions{
				Context: ctx, Timeout: timeout, Concurrency: concurrency, StateDir: stateDir,
			})
			if err == nil && ctx.Err() == nil {
				sub.UpdateLatencies(checked)
			}
			results <- batchResult{servers: checked, err: err}
		}()
		heartbeat := time.NewTicker(10 * time.Second)
		defer heartbeat.Stop()
		for {
			select {
			case <-ctx.Done():
				if r.Context().Err() == nil {
					send("failure", map[string]string{"error": "HTTPS-проверка не завершилась. Повторите попытку."})
				}
				return
			case <-heartbeat.C:
				if _, err := fmt.Fprint(w, ": heartbeat\n\n"); err != nil {
					return
				}
				flusher.Flush()
			case result := <-results:
				if result.err != nil {
					// Core diagnostics can contain endpoint credentials. Only this
					// fixed user-facing message crosses the stream boundary.
					send("failure", map[string]string{"error": "Не удалось выполнить HTTPS-проверку. Рабочее подключение сохранено."})
					return
				}
				for index, server := range result.servers {
					if !send("latency", map[string]interface{}{"id": server.ID, "latency_ms": server.Latency,
						"probe_kind": "https", "last_checked": server.LastChecked}) {
						return
					}
					if !send("progress", map[string]interface{}{"completed": index + 1, "total": len(result.servers), "probe_kind": "https"}) {
						return
					}
				}
				send("done", map[string]interface{}{"complete": true, "total": len(result.servers), "probe_kind": "https"})
				return
			}
		}
	}
}
