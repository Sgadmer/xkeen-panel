package api

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"xkeen-panel/internal/updater"
)

type updateHTTPSpy func(*http.Request) (*http.Response, error)

func (spy updateHTTPSpy) RoundTrip(r *http.Request) (*http.Response, error) { return spy(r) }

func TestLockedUpdateEndpointsRejectChangesWithoutIO(t *testing.T) {
	dir := t.TempDir()
	binary := filepath.Join(dir, "panel")
	initial := map[string][]byte{
		"panel":       []byte("custom fork binary remains installed"),
		"panel.prev":  []byte("previous binary must not be restored"),
		"update.json": []byte(`{"auto":true,"previous":"v2.0.0","locked":false}`),
	}
	type initialFile struct {
		mode    os.FileMode
		modTime time.Time
	}
	metadata := map[string]initialFile{}
	for name, data := range initial {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		metadata[name] = initialFile{mode: info.Mode(), modTime: info.ModTime()}
	}
	var requests, restarts, publishes atomic.Int32
	u := updater.New(updater.Options{
		Locked: true, Current: "v2.1.0", BinPath: binary, DataDir: dir,
		APIBase: "https://updates.example.invalid",
		Client: &http.Client{Transport: updateHTTPSpy(func(r *http.Request) (*http.Response, error) {
			requests.Add(1)
			return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(`{"tag_name":"v99.0.0","assets":[]}`)), Header: make(http.Header), Request: r}, nil
		})},
		Restart: func() error { restarts.Add(1); return nil },
		Publish: func(updater.State) { publishes.Add(1) },
	})
	h := NewUpdateHandler(u)
	for _, call := range []struct {
		name, method, path, body string
		handler                  http.HandlerFunc
	}{
		{"check", http.MethodPost, "/api/update/check", "", h.HandleCheck},
		{"apply", http.MethodPost, "/api/update/apply", "", h.HandleApply},
		{"rollback", http.MethodPost, "/api/update/rollback", "", h.HandleRollback},
		{"enable auto", http.MethodPut, "/api/update/settings", `{"auto":true}`, h.HandleSettings},
		{"disable auto", http.MethodPut, "/api/update/settings", `{"auto":false}`, h.HandleSettings},
	} {
		t.Run(call.name, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			call.handler(recorder, httptest.NewRequest(call.method, call.path, strings.NewReader(call.body)))
			if recorder.Code != http.StatusForbidden {
				t.Fatalf("locked endpoint returned %d instead of 403: %s", recorder.Code, recorder.Body.String())
			}
			var response map[string]string
			if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
				t.Fatal(err)
			}
			if response["error"] != updater.ErrLocked.Error() {
				t.Fatal("locked response does not explain the build policy")
			}
		})
	}
	status := httptest.NewRecorder()
	h.HandleStatus(status, httptest.NewRequest(http.MethodGet, "/api/update", nil))
	var state updater.State
	if status.Code != http.StatusOK || json.Unmarshal(status.Body.Bytes(), &state) != nil || !state.Locked || state.Supported || state.Auto || state.Available {
		t.Fatal("read-only status does not expose the locked build policy")
	}
	if requests.Load() != 0 || restarts.Load() != 0 || publishes.Load() != 0 {
		t.Fatal("locked endpoints attempted release access, restart or state publication")
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != len(initial) {
		t.Fatal("locked endpoints created or removed update files")
	}
	for name, expected := range initial {
		path := filepath.Join(dir, name)
		actual, err := os.ReadFile(path)
		if err != nil || !bytes.Equal(actual, expected) {
			t.Fatalf("locked endpoint changed %s", name)
		}
		info, err := os.Stat(path)
		if err != nil || info.Mode() != metadata[name].mode || !info.ModTime().Equal(metadata[name].modTime) {
			t.Fatalf("locked endpoint rewrote metadata for %s", name)
		}
	}
}
