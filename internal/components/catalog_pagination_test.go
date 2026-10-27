package components

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestComponentsCatalogPaginatesLargeXrayMetadataAndCachesChannels(t *testing.T) {
	m, _ := testManager(t)
	var requests atomic.Int32
	// The former single response exceeded 4 MiB mostly because of platform
	// assets and release notes, neither of which the version chooser needs.
	asset := map[string]interface{}{"name": "fixture.zip", "browser_download_url": "https://github.com/XTLS/Xray-core/releases/download/v26.3.27/" + strings.Repeat("a", 1024), "uploader": map[string]string{"irrelevant": strings.Repeat("b", 1024)}}
	assets := make([]interface{}, 100)
	for i := range assets {
		assets[i] = asset
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.URL.Query().Get("per_page") != "5" {
			t.Errorf("catalog requested oversized page: %s", r.URL.RawQuery)
		}
		page, _ := strconv.Atoi(r.URL.Query().Get("page"))
		if page < 1 || page > catalogMaxPages {
			t.Errorf("unbounded page %d", page)
		}
		batch := make([]map[string]interface{}, 5)
		for i := range batch {
			number := (page-1)*5 + i
			batch[i] = map[string]interface{}{"tag_name": fmt.Sprintf("v26.3.%d", number), "name": "fixture release", "prerelease": number == 37, "draft": number == 49, "assets": assets, "body": strings.Repeat("notes ", 2000)}
		}
		_ = json.NewEncoder(w).Encode(batch)
	}))
	defer server.Close()
	m.apiBase = server.URL
	beta, err := m.Releases(context.Background(), "xray", "prerelease")
	if err != nil || len(beta) != 1 || beta[0].Version != "v26.3.37" {
		t.Fatalf("beta releases: %v %v", beta, err)
	}
	if requests.Load() != catalogMaxPages {
		t.Fatalf("got %d requests, want bounded scan %d", requests.Load(), catalogMaxPages)
	}
	stable, err := m.Releases(context.Background(), "xray", "stable")
	if err != nil || len(stable) != 48 {
		t.Fatalf("stable releases: count=%d err=%v", len(stable), err)
	}
	all, err := m.Releases(context.Background(), "xray", "all")
	if err != nil || len(all) != 49 || requests.Load() != catalogMaxPages {
		t.Fatalf("shared channel cache: count=%d requests=%d err=%v", len(all), requests.Load(), err)
	}
	for _, release := range all {
		if release.Assets != nil {
			t.Fatal("catalog retained platform asset metadata")
		}
	}
}

func TestComponentsCatalogEmptyChannelIsJSONArrayAndDoesNotRefetch(t *testing.T) {
	m, _ := testManager(t)
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		_, _ = fmt.Fprint(w, `[{"tag_name":"2.1","prerelease":false}]`)
	}))
	defer server.Close()
	m.apiBase = server.URL
	for i := 0; i < 2; i++ {
		releases, err := m.Releases(context.Background(), "xkeen", "prerelease")
		if err != nil || releases == nil || len(releases) != 0 {
			t.Fatalf("empty catalog must be []: %#v %v", releases, err)
		}
	}
	if requests.Load() != 1 {
		t.Fatal("empty catalog was not cached")
	}
}

func TestComponentsCatalogRejectsMalformedOversizedOrExtraPagePayload(t *testing.T) {
	for _, body := range []string{
		`{"message":"not an array"}`,
		`[{"tag_name":"2.1"}`,
		`[] {"extra":true}`,
		`[{"tag_name":"2.1","body":"` + strings.Repeat("a", catalogPageLimit) + `"}]`,
		`[{},{},{},{},{},{}]`,
	} {
		t.Run(strconv.Itoa(len(body)), func(t *testing.T) {
			if _, err := decodeCatalogPage(strings.NewReader(body)); err == nil {
				t.Fatal("accepted malformed, oversized or unbounded catalog page")
			}
		})
	}
}

func TestComponentsCatalogDoesNotCachePartialResultsOrIgnoreNetworkFailures(t *testing.T) {
	m, _ := testManager(t)
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.URL.Query().Get("page") == "2" {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		_, _ = fmt.Fprint(w, `[{"tag_name":"2.1"},{"tag_name":"2.0"},{"tag_name":"1.9"},{"tag_name":"1.8"},{"tag_name":"1.7"}]`)
	}))
	m.apiBase = server.URL
	if releases, err := m.Releases(context.Background(), "xkeen", "stable"); err == nil || releases != nil {
		t.Fatal("partial catalog advertised as complete")
	}
	if len(m.catalog) != 0 {
		t.Fatal("failed request cached partial results")
	}
	server.Close()
	if _, err := m.Releases(context.Background(), "xkeen", "stable"); err == nil {
		t.Fatal("network failure was ignored")
	}
	if requests.Load() != 2 {
		t.Fatal("catalog did not reach the failing second page")
	}
}

func TestComponentsCatalogHonorsCancellation(t *testing.T) {
	m, _ := testManager(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}))
	defer server.Close()
	m.apiBase = server.URL
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if _, err := m.Releases(ctx, "xray", "all"); err == nil {
		t.Fatal("cancelled catalog query did not fail")
	}
	if len(m.catalog) != 0 {
		t.Fatal("cancelled catalog query was cached")
	}
}

func TestComponentsExactReleaseLookupKeepsVerifiedAssets(t *testing.T) {
	m, _ := testManager(t)
	const version = "v26.3.27"
	const name = "Xray-linux-arm64-v8a.zip"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/repos/XTLS/Xray-core/releases/tags/"+version {
			t.Error("exact version lookup changed endpoint")
		}
		_ = json.NewEncoder(w).Encode(githubRelease{Version: version, Assets: []Asset{{Name: name, Size: 42, Digest: "sha256:" + strings.Repeat("a", 64), URL: "https://github.com/XTLS/Xray-core/releases/download/" + version + "/" + name}}})
	}))
	defer server.Close()
	m.apiBase = server.URL
	release, err := m.release(context.Background(), "XTLS/Xray-core", version)
	if err != nil || len(release.Assets) != 1 {
		t.Fatalf("selected release lost its assets: %v", err)
	}
	m.opts.TestHTTP = false
	artifact, err := m.resolveArtifact(context.Background(), "XTLS/Xray-core", release, name, "xray")
	if err != nil || artifact.SHA256 != strings.Repeat("a", 64) {
		t.Fatalf("exact release checksum verification failed: %+v %v", artifact, err)
	}
}
