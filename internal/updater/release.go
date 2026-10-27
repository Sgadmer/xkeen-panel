package updater

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"runtime"
	"strings"
	"time"
)

const sumsAsset = "SHA256SUMS"

type Release struct {
	Tag         string    `json:"tag"`
	Notes       string    `json:"notes"`
	URL         string    `json:"url"`
	PublishedAt time.Time `json:"published_at"`
	Prerelease  bool      `json:"prerelease"`

	assetURL string
	sumsURL  string
}

// install.sh resolves the same names, so they must never change.
func AssetName(goos, goarch string) string {
	if goos != "linux" {
		return ""
	}
	switch goarch {
	case "arm64":
		return "xkeen-panel-aarch64"
	case "mipsle":
		return "xkeen-panel-mipsel"
	}
	return ""
}

func currentAsset() string {
	return AssetName(runtime.GOOS, runtime.GOARCH)
}

type githubRelease struct {
	TagName     string    `json:"tag_name"`
	Body        string    `json:"body"`
	HTMLURL     string    `json:"html_url"`
	PublishedAt time.Time `json:"published_at"`
	Prerelease  bool      `json:"prerelease"`
	Draft       bool      `json:"draft"`
	Assets      []struct {
		Name string `json:"name"`
		URL  string `json:"browser_download_url"`
	} `json:"assets"`
}

func (u *Updater) releaseView(payload githubRelease) Release {
	r := Release{Tag: payload.TagName, Notes: payload.Body, URL: payload.HTMLURL, PublishedAt: payload.PublishedAt, Prerelease: payload.Prerelease}
	for _, asset := range payload.Assets {
		if asset.Name == u.asset {
			r.assetURL = asset.URL
		}
		if asset.Name == sumsAsset {
			r.sumsURL = asset.URL
		}
	}
	return r
}

// A beta installation follows published beta and stable versions. A stable
// installation never opts into prereleases merely because no stable exists.
func (u *Updater) updateChannel() string {
	if v, ok := parseSemver(u.current); ok && v.isPrerelease() {
		return "preview"
	}
	return "stable"
}

func (u *Updater) fetchLatest(ctx context.Context) (Release, error) {
	if u.updateChannel() == "preview" {
		return u.fetchPublished(ctx, true)
	}
	url := fmt.Sprintf("%s/repos/%s/releases/latest", u.apiBase, u.repo)
	resp, err := u.get(ctx, url, "application/vnd.github+json")
	if err != nil {
		var status *httpStatusError
		if errors.As(err, &status) && status.code == http.StatusNotFound {
			return u.fetchPublished(ctx, false)
		}
		return Release{}, err
	}
	defer resp.Body.Close()

	var payload githubRelease
	limited := &io.LimitedReader{R: resp.Body, N: (2 << 20) + 1}
	decoder := json.NewDecoder(limited)
	if err := decoder.Decode(&payload); err != nil {
		return Release{}, fmt.Errorf("ответ GitHub не разобран: %w", err)
	}
	if err := decoder.Decode(new(interface{})); err != io.EOF || limited.N == 0 {
		return Release{}, fmt.Errorf("ответ GitHub слишком большой или повреждён")
	}

	version, valid := parseSemver(payload.TagName)
	if !valid || payload.Draft {
		return Release{}, fmt.Errorf("GitHub вернул некорректный релиз")
	}
	if payload.Prerelease || version.isPrerelease() {
		return u.fetchPublished(ctx, false)
	}
	return u.releaseView(payload), nil
}

func (u *Updater) fetchPublished(ctx context.Context, includePreview bool) (Release, error) {
	address := fmt.Sprintf("%s/repos/%s/releases?per_page=100", u.apiBase, u.repo)
	resp, err := u.get(ctx, address, "application/vnd.github+json")
	if err != nil {
		return Release{}, err
	}
	defer resp.Body.Close()
	var releases []githubRelease
	limited := &io.LimitedReader{R: resp.Body, N: (8 << 20) + 1}
	decoder := json.NewDecoder(limited)
	if err = decoder.Decode(&releases); err != nil {
		return Release{}, fmt.Errorf("список опубликованных релизов не разобран")
	}
	if err = decoder.Decode(new(interface{})); err != io.EOF || releases == nil || limited.N == 0 {
		return Release{}, fmt.Errorf("список опубликованных релизов повреждён")
	}
	var selected Release
	var selectedVersion semver
	for _, payload := range releases {
		version, valid := parseSemver(payload.TagName)
		if !valid || payload.Draft || !includePreview && (payload.Prerelease || version.isPrerelease()) {
			continue
		}
		release := u.releaseView(payload)
		// A release can be visible briefly before all CI assets are uploaded.
		if release.assetURL == "" || release.sumsURL == "" {
			continue
		}
		if selected.Tag == "" || newer(selectedVersion, version) {
			selected, selectedVersion = release, version
		}
	}
	return selected, nil
}

func (u *Updater) expectedSum(ctx context.Context, release Release) (string, error) {
	if release.sumsURL == "" {
		return "", fmt.Errorf("в релизе %s нет %s — установка без проверки суммы отменена", release.Tag, sumsAsset)
	}

	resp, err := u.get(ctx, release.sumsURL, "")
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	scanner := bufio.NewScanner(io.LimitReader(resp.Body, 64<<10))
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) == 2 && strings.TrimPrefix(fields[1], "*") == u.asset {
			return strings.ToLower(fields[0]), nil
		}
	}
	if err := scanner.Err(); err != nil {
		return "", fmt.Errorf("%s не прочитан: %w", sumsAsset, err)
	}

	return "", fmt.Errorf("в %s нет суммы для %s", sumsAsset, u.asset)
}

func (u *Updater) get(ctx context.Context, url, accept string) (*http.Response, error) {
	if u.locked {
		return nil, ErrLocked
	}
	if u.apiBase == "https://api.github.com" && !trustedUpdateURL(url, u.repo) {
		return nil, fmt.Errorf("источник обновления не принадлежит репозиторию %s", u.repo)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "xkeen-panel/"+u.current)
	if accept != "" {
		req.Header.Set("Accept", accept)
	}

	resp, err := u.client.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		if resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusTooManyRequests {
			return nil, fmt.Errorf("GitHub ограничил запросы (HTTP %d), попробуйте позже", resp.StatusCode)
		}
		return nil, &httpStatusError{address: url, code: resp.StatusCode}
	}

	return resp, nil
}

type httpStatusError struct {
	address string
	code    int
}

func (e *httpStatusError) Error() string { return fmt.Sprintf("%s: HTTP %d", e.address, e.code) }

func trustedUpdateURL(raw, repo string) bool {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme != "https" || parsed.User != nil || parsed.Fragment != "" {
		return false
	}
	if parsed.Host == "api.github.com" {
		return parsed.Path == "/repos/"+repo+"/releases/latest" && parsed.RawQuery == "" || parsed.Path == "/repos/"+repo+"/releases" && parsed.RawQuery == "per_page=100"
	}
	return parsed.Host == "github.com" && parsed.RawQuery == "" && strings.HasPrefix(parsed.Path, "/"+repo+"/releases/download/") && !strings.Contains(parsed.Path, "/../")
}
