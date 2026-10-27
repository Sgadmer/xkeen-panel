package api

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"xkeen-panel/internal/components"
	"xkeen-panel/internal/xkeen"
)

func TestComponentsAPIRejectsMalformedRequestsBeforeMutation(t *testing.T) {
	manager := components.New(components.Options{DataDir: t.TempDir(), Runtime: func() xkeen.Runtime { return xkeen.Runtime{} }, Restart: func(context.Context) error { return nil }})
	h := ComponentsHandler{manager: manager}
	for _, body := range []string{`{"plan_id":"abc"} {}`, `{"plan_id":"abc","shell":"echo"}`, `not json`} {
		w := httptest.NewRecorder()
		r := httptest.NewRequest("POST", "/api/components/apply", strings.NewReader(body))
		h.HandleApply(w, r)
		if w.Code != 400 {
			t.Fatalf("malformed request got %d", w.Code)
		}
	}
	w := httptest.NewRecorder()
	h.HandleApply(w, httptest.NewRequest("POST", "/api/components/apply", strings.NewReader(`{"plan_id":"unknown"}`)))
	if w.Code != 409 {
		t.Fatalf("unknown preview got %d", w.Code)
	}
	w = httptest.NewRecorder()
	h.HandleGeodata(w, httptest.NewRequest("PUT", "/api/components/geodata", strings.NewReader(`{"sources":["https://attacker.invalid"],"auto":true,"day":-1,"hour":4,"minute":0}`)))
	if w.Code != 400 {
		t.Fatal("accepted arbitrary geodata URL")
	}
}

func TestComponentsHTTPSAcceptanceRequiresSuccessfulTLSResponse(t *testing.T) {
	for _, code := range []int{200, 204, 302, 403, 451, 503} {
		t.Run(http.StatusText(code), func(t *testing.T) {
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.TLS == nil || r.Method != http.MethodGet {
					t.Error("acceptance did not send HTTPS GET")
				}
				w.WriteHeader(code)
				_, _ = io.WriteString(w, "PRIVATE_RESPONSE_MARKER")
			}))
			defer server.Close()
			client := server.Client()
			client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
			err := componentsHTTPSRequest(context.Background(), client, server.URL+"/private-token")
			if (err == nil) != (code < 400) {
				t.Fatalf("incorrect acceptance for HTTP %d: %v", code, err)
			}
			if err != nil && (strings.Contains(err.Error(), "PRIVATE_RESPONSE") || strings.Contains(err.Error(), "private-token") || strings.Contains(err.Error(), server.URL)) {
				t.Fatal("HTTPS acceptance exposed request or response data")
			}
		})
	}
}

func TestComponentsHTTPSCheckUsesCurrentSOCKSAndRedactsFailures(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	requested := make(chan string, 1)
	go func() {
		connection, err := listener.Accept()
		if err != nil {
			return
		}
		defer connection.Close()
		_ = connection.SetDeadline(time.Now().Add(3 * time.Second))
		greeting := make([]byte, 3)
		if _, err := io.ReadFull(connection, greeting); err != nil {
			return
		}
		if greeting[0] != 5 || greeting[1] != 1 || greeting[2] != 0 {
			return
		}
		_, _ = connection.Write([]byte{5, 0})
		header := make([]byte, 5)
		if _, err := io.ReadFull(connection, header); err != nil || header[0] != 5 || header[1] != 1 || header[3] != 3 {
			return
		}
		address := make([]byte, int(header[4])+2)
		if _, err := io.ReadFull(connection, address); err != nil {
			return
		}
		requested <- string(address[:len(address)-2])
		_, _ = connection.Write([]byte{5, 5, 0, 1, 0, 0, 0, 0, 0, 0})
	}()
	err = componentsHTTPSCheck(context.Background(), listener.Addr().String(), "https://current-selection.invalid/private-token")
	if err == nil || strings.Contains(err.Error(), "current-selection") || strings.Contains(err.Error(), "private-token") {
		t.Fatal("failed SOCKS tunnel was accepted or disclosed its target")
	}
	select {
	case host := <-requested:
		if host != "current-selection.invalid" {
			t.Fatal("acceptance did not use the configured target through SOCKS")
		}
	case <-time.After(4 * time.Second):
		t.Fatal("acceptance did not reach the current proxy input")
	}
	for _, address := range []string{"", "localhost:1080", "192.0.2.1:1080", "malformed"} {
		if err := componentsHTTPSCheck(context.Background(), address, "https://current-selection.invalid/"); err == nil {
			t.Fatal("acceptance permitted a missing or nonlocal proxy")
		}
	}
}

func TestComponentsHTTPSAcceptanceRespectsCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := componentsHTTPSRequest(ctx, &http.Client{}, "https://current-selection.invalid/private-token"); err == nil || strings.Contains(err.Error(), "private-token") {
		t.Fatal("canceled acceptance succeeded or exposed its target")
	}
}
