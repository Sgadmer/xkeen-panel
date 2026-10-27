package sse

import (
	"context"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"xkeen-panel/internal/models"
	"xkeen-panel/internal/xkeen"
)

func httpsTestSubscription(t *testing.T) *xkeen.SubscriptionManager {
	t.Helper()
	dir := t.TempDir()
	data := models.SubscriptionData{Servers: []models.Server{{ID: 7, Name: "Synthetic", Protocol: "hysteria2",
		Address: "private-endpoint.invalid", Port: 443, RawURI: "hy2://PRIVATE_FAKE_VALUE@private-endpoint.invalid",
		RawOutbound: json.RawMessage(`{"password":"PRIVATE_FAKE_VALUE"}`), Latency: -1}}}
	raw, err := json.Marshal(data)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "subscription.json"), raw, 0o600); err != nil {
		t.Fatal(err)
	}
	sub := xkeen.NewSubscriptionManager(dir)
	if err := sub.Load(); err != nil {
		t.Fatal(err)
	}
	return sub
}

func TestHTTPSLatencyStreamUsesNativeBatchAndNeverSendsCredentials(t *testing.T) {
	sub := httpsTestSubscription(t)
	called := false
	probe := func(rt xkeen.Runtime, servers []models.Server, options xkeen.ProbeOptions) ([]models.Server, error) {
		called = true
		if rt.Core != xkeen.CoreXray || options.Context == nil || options.Concurrency != 3 || options.Timeout != 8*time.Second || options.StateDir != "private-state" {
			t.Error("incorrect native probe options")
		}
		servers[0].Latency = 34
		servers[0].ProbeKind = "https"
		servers[0].LastChecked = time.Now()
		return servers, nil
	}
	handler := newHTTPSLatencyHandler(sub, func() xkeen.Runtime { return xkeen.Runtime{Core: xkeen.CoreXray} }, "private-state", 3, 8*time.Second, probe)
	response := httptest.NewRecorder()
	handler(response, httptest.NewRequest("GET", "/api/servers/check", nil))
	body := response.Body.String()
	if !called || !strings.Contains(body, "event: latency") || !strings.Contains(body, `"latency_ms":34`) || !strings.Contains(body, "event: done") || !strings.Contains(body, "event: progress") {
		t.Fatal("native HTTPS results were not streamed")
	}
	for _, private := range []string{"PRIVATE_FAKE_VALUE", "private-endpoint.invalid", "raw_uri", "raw_outbound", "hy2://"} {
		if strings.Contains(body, private) {
			t.Fatal("private endpoint data appeared in SSE")
		}
	}
	if saved := sub.GetServers()[0]; saved.Latency != 34 || saved.ProbeKind != "https" {
		t.Fatal("HTTPS result was not saved")
	}
}

func TestHTTPSLatencyStreamSanitizesProbeErrors(t *testing.T) {
	sub := httpsTestSubscription(t)
	handler := newHTTPSLatencyHandler(sub, func() xkeen.Runtime { return xkeen.Runtime{} }, "", 3, 8*time.Second,
		func(xkeen.Runtime, []models.Server, xkeen.ProbeOptions) ([]models.Server, error) {
			return nil, errors.New("PRIVATE_FAKE_VALUE https://private-endpoint.invalid/token")
		})
	response := httptest.NewRecorder()
	handler(response, httptest.NewRequest("GET", "/api/servers/check", nil))
	body := response.Body.String()
	if !strings.Contains(body, "event: failure") || strings.Contains(body, "PRIVATE_FAKE_VALUE") || strings.Contains(body, "private-endpoint.invalid") || strings.Contains(body, "event: done") {
		t.Fatal("error was not safely reported")
	}
}

func TestHTTPSLatencyStreamCancelsBackgroundProbeOnDisconnect(t *testing.T) {
	sub := httpsTestSubscription(t)
	started, canceled := make(chan struct{}), make(chan struct{})
	handler := newHTTPSLatencyHandler(sub, func() xkeen.Runtime { return xkeen.Runtime{} }, "", 3, 8*time.Second,
		func(_ xkeen.Runtime, _ []models.Server, options xkeen.ProbeOptions) ([]models.Server, error) {
			close(started)
			<-options.Context.Done()
			close(canceled)
			return nil, options.Context.Err()
		})
	ctx, cancel := context.WithCancel(context.Background())
	finished := make(chan struct{})
	go func() {
		handler(httptest.NewRecorder(), httptest.NewRequest("GET", "/api/servers/check", nil).WithContext(ctx))
		close(finished)
	}()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("background probe was not started")
	}
	cancel()
	for _, signal := range []<-chan struct{}{finished, canceled} {
		select {
		case <-signal:
		case <-time.After(time.Second):
			t.Fatal("disconnected request left its probe running")
		}
	}
}
