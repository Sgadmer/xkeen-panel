package updater

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"xkeen-panel/internal/releasesig"
)

func TestPublishedReleaseChannels(t *testing.T) {
	for _, tc := range []struct {
		name, current, want, channel string
		releases                     []githubRelease
		available                    bool
	}{
		{name: "beta only repository", current: "v3.0.0-beta.1", want: "v3.0.0-beta.1", channel: "preview", releases: []githubRelease{{TagName: "v3.0.0-beta.1", Prerelease: true}}},
		{name: "numeric beta upgrade", current: "v3.0.0-beta.1", want: "v3.0.0-beta.10", channel: "preview", available: true, releases: []githubRelease{{TagName: "v3.0.0-beta.2", Prerelease: true}, {TagName: "v3.0.0-beta.10", Prerelease: true}}},
		{name: "beta graduates to stable", current: "v3.0.0-beta.2", want: "v3.0.0", channel: "preview", available: true, releases: []githubRelease{{TagName: "v3.0.0-beta.9", Prerelease: true}, {TagName: "v3.0.0"}}},
		{name: "stable excludes prerelease", current: "v2.0.0", channel: "stable", releases: []githubRelease{{TagName: "v3.0.0-beta.2", Prerelease: true}, {TagName: "v3.0.0-rc.1"}}},
		// A beta build installed by hand does not opt into further betas.
		{name: "beta build stays on stable by default", current: "v3.0.0-beta.1", channel: "stable", releases: []githubRelease{{TagName: "v3.0.0-beta.2", Prerelease: true}}},
		{name: "beta build on stable graduates", current: "v3.0.0-beta.1", want: "v3.0.0", channel: "stable", available: true, releases: []githubRelease{{TagName: "v3.0.0-beta.2", Prerelease: true}, {TagName: "v3.0.0"}}},
		{name: "stable build may ask for betas", current: "v2.0.0", want: "v3.0.0-beta.2", channel: "preview", available: true, releases: []githubRelease{{TagName: "v3.0.0-beta.2", Prerelease: true}, {TagName: "v2.0.1"}}},
		{name: "stable fallback filters draft and invalid", current: "v2.0.0", want: "v2.0.1", channel: "stable", available: true, releases: []githubRelease{{TagName: "not-a-version"}, {TagName: "v9.0.0", Draft: true}, {TagName: "v2.0.1"}, {TagName: "v3.0.0-beta.1", Prerelease: true}}},
		{name: "no releases", current: "v2.0.0", channel: "stable", releases: []githubRelease{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var server *httptest.Server
			server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/repos/owner/repo/releases" || r.URL.RawQuery != "per_page=100" {
					t.Errorf("unexpected request: %s", r.URL)
					http.NotFound(w, r)
					return
				}
				payload := append([]githubRelease{}, tc.releases...)
				for i := range payload {
					payload[i].Assets = append(payload[i].Assets, struct {
						Name string `json:"name"`
						URL  string `json:"browser_download_url"`
					}{testAsset, server.URL + "/panel"}, struct {
						Name string `json:"name"`
						URL  string `json:"browser_download_url"`
					}{sumsAsset, server.URL + "/sums"}, struct {
						Name string `json:"name"`
						URL  string `json:"browser_download_url"`
					}{releasesig.Asset, server.URL + "/sig"})
				}
				json.NewEncoder(w).Encode(payload)
			}))
			defer server.Close()
			u := New(Options{Current: tc.current, DataDir: t.TempDir(), Repo: "owner/repo", APIBase: server.URL, Client: server.Client()})
			u.asset = testAsset
			if err := u.SetChannel(tc.channel); err != nil {
				t.Fatal(err)
			}
			state, err := u.Check(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			if state.Available != tc.available || state.Channel != tc.channel || state.CheckError != "" {
				t.Fatalf("unexpected state: %+v", state)
			}
			if tc.want == "" {
				if state.Latest != nil {
					t.Fatal("empty channel advertised a release")
				}
			} else if state.Latest == nil || state.Latest.Tag != tc.want {
				t.Fatalf("wrong release: %+v", state.Latest)
			}
		})
	}
}

func TestReleaseCatalogErrorsAreNotHidden(t *testing.T) {
	for _, tc := range []struct {
		name, current, body string
		status              int
	}{
		{"missing repository", "v2.0.0", "", 404},
		{"rate limit", "v3.0.0-beta.1", "", 403},
		{"corrupt catalog", "v3.0.0-beta.1", "[", 200},
		{"trailing garbage", "v3.0.0-beta.1", "[] broken", 200},
		{"null catalog", "v3.0.0-beta.1", "null", 200},
		{"stable trailing garbage", "v2.0.0", `{"tag_name":"v2.0.1"} broken`, 200},
		{"oversized stable trailing whitespace", "v2.0.0", `{"tag_name":"v2.0.1"}` + strings.Repeat(" ", 2<<20), 200},
		{"oversized catalog trailing whitespace", "v3.0.0-beta.1", `[]` + strings.Repeat(" ", 8<<20), 200},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(tc.status); w.Write([]byte(tc.body)) }))
			defer server.Close()
			u := New(Options{Current: tc.current, DataDir: t.TempDir(), Repo: "owner/repo", APIBase: server.URL, Client: server.Client()})
			u.asset = testAsset
			state, err := u.Check(context.Background())
			if err == nil || state.CheckError == "" || state.Latest != nil || len(state.Versions) != 0 {
				t.Fatal("real catalog failure was hidden")
			}
		})
	}
}

func TestIncompletePublishedReleaseIsNotOffered(t *testing.T) {
	for name, assets := range map[string]string{
		"no assets": ``,
		// CI has finished, the maintainer has not signed the checksums yet.
		"not signed yet": `{"name":"` + testAsset + `","browser_download_url":"https://example.invalid/panel"},{"name":"SHA256SUMS","browser_download_url":"https://example.invalid/sums"}`,
	} {
		t.Run(name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Write([]byte(`[{"tag_name":"v3.0.0-beta.2","prerelease":true,"assets":[` + assets + `]}]`))
			}))
			defer server.Close()
			u := New(Options{Current: "v3.0.0-beta.1", DataDir: t.TempDir(), Repo: "owner/repo", APIBase: server.URL, Client: server.Client()})
			u.asset = testAsset
			if err := u.SetChannel("preview"); err != nil {
				t.Fatal(err)
			}
			state, err := u.Check(context.Background())
			if err != nil || state.Latest != nil || state.Available || len(state.Versions) != 0 {
				t.Fatalf("incomplete release advertised: %+v, %v", state, err)
			}
		})
	}
}
