package xkeen

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"xkeen-panel/internal/models"
)

type subscriptionSeenRequest struct {
	HWID string
	UA   string
}

func readTestSubscriptionClient(t *testing.T, sm *SubscriptionManager) subscriptionClientState {
	t.Helper()
	data, err := os.ReadFile(sm.subscriptionClientPath())
	if err != nil {
		t.Fatal(err)
	}
	var state subscriptionClientState
	if err := json.Unmarshal(data, &state); err != nil {
		t.Fatal(err)
	}
	return state
}

func TestNativeSubscriptionCreatesPersistentIdentityBeforeFirstRequest(t *testing.T) {
	dir := t.TempDir()
	sm := NewSubscriptionManager(dir)
	var savedBeforeRequest atomic.Bool
	var mu sync.Mutex
	var seen []subscriptionSeenRequest
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, err := os.Stat(sm.subscriptionClientPath())
		savedBeforeRequest.Store(err == nil)
		mu.Lock()
		seen = append(seen, subscriptionSeenRequest{r.Header.Get("x-hwid"), r.UserAgent()})
		mu.Unlock()
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()
	for i := 0; i < 2; i++ {
		sm = NewSubscriptionManager(dir)
		if _, err := sm.UpdateURL(srv.URL); err == nil {
			t.Fatal("expected an upstream failure")
		}
	}
	state := readTestSubscriptionClient(t, sm)
	mu.Lock()
	defer mu.Unlock()
	if !savedBeforeRequest.Load() || len(seen) != 2 || !subscriptionHWIDPattern.MatchString(state.HWID) {
		t.Fatal("the installation identity was not durably established before fetching")
	}
	for _, request := range seen {
		if request.HWID != state.HWID || request.UA != "INCY/1.0/Linux" {
			t.Fatal("the primary request profile or persistent identity changed")
		}
	}
	if _, err := os.Stat(sm.filePath()); !os.IsNotExist(err) {
		t.Fatal("a failed import wrote subscription.json")
	}
	if info, err := os.Stat(sm.subscriptionClientPath()); err == nil && info.Mode().Perm()&0077 != 0 && os.PathSeparator != '\\' {
		t.Fatal("identity file is not private")
	}
}

func TestNativeSubscriptionReusesSeededIdentityAndRemembersSuccessfulProfile(t *testing.T) {
	dir := t.TempDir()
	sm := NewSubscriptionManager(dir)
	seed := subscriptionClientState{Version: 1, HWID: "router-existing-device-123456"}
	data, _ := json.Marshal(seed)
	if err := os.WriteFile(sm.subscriptionClientPath(), data, 0600); err != nil {
		t.Fatal(err)
	}
	var seen []subscriptionSeenRequest
	var mu sync.Mutex
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen = append(seen, subscriptionSeenRequest{r.Header.Get("x-hwid"), r.UserAgent()})
		mu.Unlock()
		if r.UserAgent() == "INCY/1.0/Linux" {
			fmt.Fprint(w, "vless://00000000-0000-0000-0000-000000000000@127.0.0.1:443#Приложение%20не%20поддерживается,%20используйте%20incy")
			return
		}
		fmt.Fprint(w, base64.StdEncoding.EncodeToString([]byte(uriA)))
	}))
	defer srv.Close()
	if _, err := sm.UpdateURL(srv.URL); err != nil {
		t.Fatal(err)
	}
	reloaded := NewSubscriptionManager(dir)
	if err := reloaded.Load(); err != nil {
		t.Fatal(err)
	}
	if _, err := reloaded.Refresh(); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(seen) != 3 || seen[0].UA != "INCY/1.0/Linux" || seen[1].UA != "Go-http-client/1.1" || seen[2].UA != seen[1].UA {
		t.Fatal("fallback or remembered profile caused unnecessary upstream requests")
	}
	for _, request := range seen {
		if request.HWID != seed.HWID {
			t.Fatal("fallback or reload used a different registered device")
		}
	}
	state := readTestSubscriptionClient(t, reloaded)
	if state.Profile != "go" || state.URLSHA256 != subscriptionURLHash(srv.URL) {
		t.Fatal("the successful profile was not scoped to the subscription URL")
	}
}

func TestNativeSubscriptionTerminalResponsesDoNotRotateProfilesOrLoseServers(t *testing.T) {
	for _, tc := range []struct {
		name, header, value string
		status              int
	}{
		{"device-limit", "x-hwid-max-devices-reached", "true", 404},
		{"legacy-device-limit", "x-hwid-limit", " YES ", 200},
		{"rate-limit", "x-hwid-not-supported", "true", 429},
		{"upstream-failure", "x-hwid-not-supported", "true", 503},
		{"auth-failure", "", "", 403},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sm := loadSub(t, []models.Server{{RawURI: uriA, Name: "Original", Active: true}}, 0)
			before := sm.GetData()
			var requests atomic.Int32
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)
				if tc.header != "" {
					w.Header().Set(tc.header, tc.value)
				}
				w.WriteHeader(tc.status)
				fmt.Fprint(w, "private upstream body must not reach errors")
			}))
			defer srv.Close()
			if _, err := sm.UpdateURL(srv.URL + "/token-secret"); err == nil || strings.Contains(err.Error(), "token-secret") || strings.Contains(err.Error(), "private upstream") {
				t.Fatal("expected a redacted terminal failure")
			}
			if requests.Load() != 1 || !reflect.DeepEqual(before, sm.GetData()) {
				t.Fatal("terminal response retried profiles or changed the previous subscription")
			}
		})
	}
}

func TestNativeSubscriptionExplicitCompatibilityHeaderRetriesWithSameHWID(t *testing.T) {
	sm := NewSubscriptionManager(t.TempDir())
	var requests []subscriptionSeenRequest
	var mu sync.Mutex
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		requests = append(requests, subscriptionSeenRequest{r.Header.Get("x-hwid"), r.UserAgent()})
		requestCount := len(requests)
		mu.Unlock()
		if requestCount == 1 {
			w.Header().Set("x-hwid-not-supported", " TRUE ")
			w.WriteHeader(404)
			return
		}
		w.Header().Set("x-hwid-max-devices-reached", "false")
		fmt.Fprint(w, uriA)
	}))
	defer srv.Close()
	if _, err := sm.UpdateURL(srv.URL); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(requests) != 2 || requests[0].HWID == "" || requests[0].HWID != requests[1].HWID {
		t.Fatal("compatibility fallback changed device identity")
	}
}

func TestNativeSubscriptionBodyLimitStopsWithoutProfileRetry(t *testing.T) {
	for _, declared := range []bool{false, true} {
		t.Run(fmt.Sprint(declared), func(t *testing.T) {
			sm := NewSubscriptionManager(t.TempDir())
			var requests atomic.Int32
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)
				if declared {
					w.Header().Set("Content-Length", fmt.Sprint(subscriptionBodyLimit+1))
					w.WriteHeader(200)
					return
				}
				fmt.Fprint(w, strings.Repeat("x", subscriptionBodyLimit+1))
			}))
			defer srv.Close()
			if _, err := sm.UpdateURL(srv.URL); err == nil || !strings.Contains(err.Error(), "2 МиБ") {
				t.Fatal("response size limit was not enforced")
			}
			if requests.Load() != 1 {
				t.Fatal("oversized responses must not trigger profile retries")
			}
		})
	}
}

func TestNativeSubscriptionCorruptIdentityNeverGeneratesAReplacement(t *testing.T) {
	sm := NewSubscriptionManager(t.TempDir())
	original := []byte(`{"version":1,"hwid":"bad"}`)
	if err := os.WriteFile(sm.subscriptionClientPath(), original, 0600); err != nil {
		t.Fatal(err)
	}
	var requests atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { requests.Add(1) }))
	defer srv.Close()
	if _, err := sm.UpdateURL(srv.URL); err == nil {
		t.Fatal("corrupt identity was accepted")
	}
	after, _ := os.ReadFile(sm.subscriptionClientPath())
	if requests.Load() != 0 || string(after) != string(original) {
		t.Fatal("corrupt identity caused replacement or an upstream device registration")
	}
}

func TestNativeSubscriptionConcurrentManagersShareOneInstallationIdentity(t *testing.T) {
	dir := t.TempDir()
	const workers = 6
	var mu sync.Mutex
	ids := make(map[string]bool)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		ids[r.Header.Get("x-hwid")] = true
		mu.Unlock()
		fmt.Fprint(w, uriA)
	}))
	defer srv.Close()
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := NewSubscriptionManager(dir).downloadAndParse(srv.URL); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	mu.Lock()
	defer mu.Unlock()
	if len(ids) != 1 || ids[""] {
		t.Fatal("concurrent first imports used multiple device slots")
	}
}

type failingSubscriptionTransport struct{}

func (failingSubscriptionTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	return nil, fmt.Errorf("cannot contact private-url %s with secret-token", r.URL)
}

func TestNativeSubscriptionTransportErrorsNeverExposeURL(t *testing.T) {
	sm := NewSubscriptionManager(t.TempDir())
	sm.httpClient = &http.Client{Transport: failingSubscriptionTransport{}}
	_, err := sm.UpdateURL("https://example.invalid/private/secret-token?key=secret-key")
	if err == nil || strings.Contains(err.Error(), "secret") || strings.Contains(err.Error(), "example.invalid") {
		t.Fatal("transport error exposed a secret URL")
	}
}

func TestNativeSubscriptionRedirectsKeepSameOriginIdentityAndStripCrossOrigin(t *testing.T) {
	for _, crossOrigin := range []bool{false, true} {
		t.Run(fmt.Sprint(crossOrigin), func(t *testing.T) {
			var received subscriptionSeenRequest
			var referer string
			var mu sync.Mutex
			destination := func(w http.ResponseWriter, r *http.Request) {
				mu.Lock()
				received = subscriptionSeenRequest{r.Header.Get("x-hwid"), r.UserAgent()}
				referer = r.Referer()
				mu.Unlock()
				fmt.Fprint(w, uriA)
			}
			var external *httptest.Server
			if crossOrigin {
				external = httptest.NewServer(http.HandlerFunc(destination))
				defer external.Close()
			}
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/final" {
					destination(w, r)
					return
				}
				location := "/final"
				if crossOrigin {
					location = external.URL + location
				}
				http.Redirect(w, r, location, http.StatusFound)
			}))
			defer srv.Close()
			sm := NewSubscriptionManager(t.TempDir())
			if _, err := sm.UpdateURL(srv.URL + "/private-token?key=secret"); err != nil {
				t.Fatal(err)
			}
			mu.Lock()
			defer mu.Unlock()
			if referer != "" || received.UA != "INCY/1.0/Linux" {
				t.Fatal("redirect leaked the secret referring URL or changed the client profile")
			}
			if crossOrigin && received.HWID != "" || !crossOrigin && received.HWID == "" {
				t.Fatal("redirect failed to scope HWID to the subscription origin")
			}
		})
	}
}

func TestNativeSubscriptionRejectsHTTPSDowngradeAndRedirectLoops(t *testing.T) {
	var plainRequests atomic.Int32
	plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { plainRequests.Add(1) }))
	defer plain.Close()
	tls := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, plain.URL, http.StatusFound)
	}))
	defer tls.Close()
	sm := NewSubscriptionManager(t.TempDir())
	sm.httpClient = tls.Client()
	if _, err := sm.UpdateURL(tls.URL + "/private-token"); err == nil || strings.Contains(err.Error(), "private-token") {
		t.Fatal("HTTPS downgrade did not fail with a redacted error")
	}
	if plainRequests.Load() != 0 {
		t.Fatal("HTTPS downgrade reached a plaintext server")
	}
	var redirects atomic.Int32
	loop := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		redirects.Add(1)
		http.Redirect(w, r, "/next", http.StatusFound)
	}))
	defer loop.Close()
	if _, err := NewSubscriptionManager(t.TempDir()).UpdateURL(loop.URL); err == nil || redirects.Load() != 6 {
		t.Fatal("redirect chain was not bounded at five redirects")
	}
}

func TestSubscriptionSnapshotsDeepCopyRawOutbounds(t *testing.T) {
	raw := json.RawMessage(`{"protocol":"vless","settings":{"address":"example.invalid","port":443,"id":"test"}}`)
	sm := loadSub(t, []models.Server{{ID: 0, RawURI: "xray-json://test", RawOutbound: raw, Active: true}}, 0)
	for _, get := range []func() *models.Server{
		func() *models.Server { d := sm.GetData(); return &d.Servers[0] },
		func() *models.Server { d := sm.GetServers(); return &d[0] },
		sm.GetActiveServer,
		func() *models.Server {
			d, err := sm.SetActive(0)
			if err != nil {
				t.Fatal(err)
			}
			return d
		},
		func() *models.Server {
			d, err := sm.SetActiveByRawURI("xray-json://test")
			if err != nil {
				t.Fatal(err)
			}
			return d
		},
	} {
		returned := get()
		returned.RawOutbound[0] = '!'
		if !json.Valid(sm.GetServers()[0].RawOutbound) {
			t.Fatal("a snapshot exposed mutable stored credentials")
		}
	}
	input := []models.Server{{RawURI: "xray-json://test", RawOutbound: append(json.RawMessage(nil), raw...)}}
	sm.mu.Lock()
	sm.applyRefreshLocked(input)
	sm.mu.Unlock()
	input[0].RawOutbound[0] = '!'
	if !json.Valid(sm.GetServers()[0].RawOutbound) {
		t.Fatal("refresh retained its caller's mutable raw outbound")
	}
}

func TestSubscriptionIdentityStateOnlyContainsHashOfURL(t *testing.T) {
	sm := NewSubscriptionManager(t.TempDir())
	state, err := sm.loadSubscriptionClient()
	if err != nil {
		t.Fatal(err)
	}
	if err := sm.rememberSubscriptionProfile("https://example.invalid/super-secret-token", state.HWID, "incy"); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(filepath.Join(sm.dataDir, "subscription-client.json"))
	if strings.Contains(string(data), "super-secret-token") || strings.Contains(string(data), "example.invalid") {
		t.Fatal("client metadata duplicated the private subscription URL")
	}
	if got := subscriptionProfilesFor(readTestSubscriptionClient(t, sm), "https://different.invalid/new"); got[0].name != "incy" {
		t.Fatal("a remembered profile escaped to an unrelated subscription URL")
	}
}

func TestNativeSubscriptionHonorsRequestCancellation(t *testing.T) {
	sm := NewSubscriptionManager(t.TempDir())
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := sm.fetchSubscriptionProfile(ctx, "https://example.invalid/secret-token", "router-test-id-123456", subscriptionProfiles[0])
	if err == nil || strings.Contains(err.Error(), "secret-token") {
		t.Fatal("cancelled request did not fail safely")
	}
}

func TestNativeSubscriptionPersistsImportReportAndRestoresDataWithoutChangingClient(t *testing.T) {
	sm := NewSubscriptionManager(t.TempDir())
	if err := sm.RestoreData(models.SubscriptionData{URL: "https://old.example.invalid/private-token", Servers: []models.Server{{ID: 0, Name: "Original", RawURI: uriA, Active: true}}, ActiveID: 0}); err != nil {
		t.Fatal(err)
	}
	previous := sm.GetData()
	previousReport := sm.GetImportReport()
	const fixture = `[
		{"remarks":"Netherlands","outbounds":[{"protocol":"vless","tag":"old-provider-tag","settings":{"address":"example.invalid","port":443,"id":"aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"}}]},
		{"remarks":"Unsupported composite","routing":{"rules":[{"type":"field","outboundTag":"missing"}],"balancers":[{"tag":"auto","selector":["a","b"]}]},"outbounds":[{"protocol":"vless","tag":"a","settings":{"address":"a.invalid","port":443,"id":"aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"}},{"protocol":"vless","tag":"b","settings":{"address":"b.invalid","port":443,"id":"bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"}}]}
	]`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, fixture) }))
	defer srv.Close()
	returned, err := sm.UpdateURL(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	if len(returned) != 1 || len(returned[0].RawOutbound) == 0 {
		t.Fatal("native JSON endpoints were not imported intact")
	}
	returned[0].RawOutbound[0] = '!'
	if !json.Valid(sm.GetServers()[0].RawOutbound) {
		t.Fatal("successful import returned a credential alias")
	}
	report := sm.GetImportReport()
	if report.Imported != 1 || report.SkippedComposite != 1 || len(report.Warnings) == 0 {
		t.Fatal("composite profile skips were not reported")
	}
	report.Warnings[0] = "MUTATED"
	if sm.GetImportReport().Warnings[0] == "MUTATED" {
		t.Fatal("import report returned a mutable alias")
	}
	reloaded := NewSubscriptionManager(sm.dataDir)
	if err := reloaded.Load(); err != nil {
		t.Fatal(err)
	}
	if reloaded.GetImportReport().SkippedComposite != 1 {
		t.Fatal("import report was not persisted in the compatible envelope")
	}
	clientBeforeRollback, err := os.ReadFile(sm.subscriptionClientPath())
	if err != nil {
		t.Fatal(err)
	}
	if err := sm.RestoreData(previous); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(previous, sm.GetData()) || !reflect.DeepEqual(previousReport, sm.GetImportReport()) {
		t.Fatal("post-import rollback failed to restore the exact previous subscription and report")
	}
	clientAfterRollback, _ := os.ReadFile(sm.subscriptionClientPath())
	if string(clientBeforeRollback) != string(clientAfterRollback) {
		t.Fatal("post-import rollback changed the registered device or negotiated client")
	}
	loadedRollback := NewSubscriptionManager(sm.dataDir)
	if err := loadedRollback.Load(); err != nil || !reflect.DeepEqual(previous, loadedRollback.GetData()) {
		t.Fatal("restored subscription did not survive process reload")
	}
}

func TestNativeSubscriptionAllFakeRecordsAreRejectedWithoutRotatingHWID(t *testing.T) {
	stub := "vless://00000000-0000-0000-0000-000000000000@127.0.0.1:443#Приложение%20не%20поддерживается,%20включите%20HWID"
	for _, response := range []string{stub, base64.StdEncoding.EncodeToString([]byte(stub)), `{"remarks":"Приложение не поддерживается, используйте incy","outbounds":[{"protocol":"vless","settings":{"address":"127.0.0.1","port":443,"id":"00000000-0000-0000-0000-000000000000"}}]}`} {
		sm := NewSubscriptionManager(t.TempDir())
		var mu sync.Mutex
		seen := make(map[string]int)
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			mu.Lock()
			seen[r.Header.Get("x-hwid")]++
			mu.Unlock()
			fmt.Fprint(w, response)
		}))
		if _, err := sm.UpdateURL(srv.URL); err == nil {
			t.Fatal("a fake record was accepted as a real server")
		}
		srv.Close()
		mu.Lock()
		if len(seen) != 1 || seen[""] != 0 {
			t.Fatal("fake-record fallback generated new device identities")
		}
		for _, requests := range seen {
			if requests != len(subscriptionProfiles) {
				t.Fatal("client-format fallback was not bounded to the supported profiles")
			}
		}
		mu.Unlock()
		if len(sm.GetServers()) != 0 {
			t.Fatal("rejected fake records changed the subscription")
		}
	}
}
