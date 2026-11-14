package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"xkeen-panel/internal/models"
	"xkeen-panel/internal/sse"
	"xkeen-panel/internal/xkeen"
)

func TestProbeJobServerIDs(t *testing.T) {
	sub := xkeen.NewSubscriptionManager(t.TempDir())
	data := models.SubscriptionData{CatalogVersion: 1, Servers: []models.Server{
		{ID: 0, RawURI: "fixture-a", Latency: 10},
		{ID: 5, RawURI: "fixture-b", Latency: 20},
		{ID: 8, RawURI: "fixture-c", Latency: 30},
	}}
	if err := sub.RestoreData(data); err != nil {
		t.Fatal(err)
	}
	release := make(chan struct{})
	defer close(release)
	h := Handlers{Checks: sse.NewProbeJobs(sub, xkeen.ProbeOptions{}, func(servers []models.Server, options xkeen.ProbeOptions) ([]models.Server, error) {
		select {
		case <-release:
		case <-options.Context.Done():
			return nil, options.Context.Err()
		}
		for i := range servers {
			servers[i].Latency, servers[i].ProbeKind = 37, "https"
		}
		return servers, nil
	}, nil)}
	call := func(method, body string, want int) sse.ProbeProgress {
		t.Helper()
		w := httptest.NewRecorder()
		h.HandleProbeJob(w, httptest.NewRequest(method, "/api/servers/check/job", strings.NewReader(body)))
		if w.Code != want {
			t.Fatalf("%s %q: got %d, want %d", method, body, w.Code, want)
		}
		var progress sse.ProbeProgress
		if want < 300 {
			if err := json.Unmarshal(w.Body.Bytes(), &progress); err != nil {
				t.Fatal(err)
			}
		}
		return progress
	}
	for _, body := range []string{
		`{"server_ids":[]}`, `{"server_ids":null}`, `{"server_ids":[null]}`,
		`{"server_ids":[-1]}`, `{"server_ids":[0,99]}`, `{"server_ids":["0"]}`,
		`{"server_ids":[1.5]}`, `{"ids":[0]}`, `{}` + " {}", "null", `{"server_ids":`,
	} {
		call(http.MethodPost, body, http.StatusBadRequest)
	}
	if progress := call(http.MethodGet, "", http.StatusOK); progress.Run != 0 {
		t.Fatal("invalid request started a job")
	}
	selected := call(http.MethodPost, `{"server_ids":[8,0,0]}`, http.StatusAccepted)
	if !selected.Running || !reflect.DeepEqual(selected.IDs, []int{0, 8}) {
		t.Fatalf("unexpected selected job %+v", selected)
	}
	call(http.MethodPost, `{"server_ids":[5]}`, http.StatusConflict)
	if p := call(http.MethodPost, "", http.StatusAccepted); p.Run != selected.Run || !reflect.DeepEqual(p.IDs, selected.IDs) {
		t.Fatal("legacy request did not join the active job")
	}
	if p := call(http.MethodGet, "", http.StatusOK); !p.Running || p.Run != selected.Run {
		t.Fatal("detached request lost its job")
	}
	waitDone := func() sse.ProbeProgress {
		t.Helper()
		for deadline := time.Now().Add(3 * time.Second); time.Now().Before(deadline); {
			if p := call(http.MethodGet, "", http.StatusOK); !p.Running {
				return p
			}
			time.Sleep(time.Millisecond)
		}
		t.Fatal("background job did not finish")
		return sse.ProbeProgress{}
	}
	release <- struct{}{}
	if p := waitDone(); p.Error != "" || len(p.Results) != 2 {
		t.Fatalf("unexpected completed job %+v", p)
	}
	saved := sub.GetServers()
	if saved[0].Latency != 37 || saved[2].Latency != 37 || !reflect.DeepEqual(saved[1], data.Servers[1]) {
		t.Fatal("subset results were not merged into the catalog")
	}
	all := call(http.MethodPost, "", http.StatusAccepted)
	if all.Run != selected.Run+1 || !reflect.DeepEqual(all.IDs, []int{0, 5, 8}) {
		t.Fatalf("legacy check-all selected wrong servers %+v", all)
	}
	release <- struct{}{}
	waitDone()
}
