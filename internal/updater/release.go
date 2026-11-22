package updater

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"runtime"
	"sort"
	"strings"
	"time"

	"xkeen-panel/internal/releasesig"
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
	sigURL   string
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
		if asset.Name == releasesig.Asset {
			r.sigURL = asset.URL
		}
	}
	return r
}

// The channel is the owner's choice and stable unless they asked for more: a
// beta build put on the router by hand does not opt into further betas.
// The caller holds u.mu.
func (u *Updater) updateChannel() string {
	if u.settings.Channel == channelPreview {
		return channelPreview
	}
	return channelStable
}

// fetchPublished lists what this panel may install, newest first: published
// releases of the channel that carry the binary, its checksums and the
// signature. The signature itself is verified when a release is installed.
func (u *Updater) fetchPublished(ctx context.Context, includePreview bool) ([]Release, error) {
	address := fmt.Sprintf("%s/repos/%s/releases?per_page=100", u.apiBase, u.repo)
	resp, err := u.get(ctx, address, "application/vnd.github+json")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var releases []githubRelease
	limited := &io.LimitedReader{R: resp.Body, N: (8 << 20) + 1}
	decoder := json.NewDecoder(limited)
	if err = decoder.Decode(&releases); err != nil {
		return nil, fmt.Errorf("список опубликованных релизов не разобран")
	}
	if err = decoder.Decode(new(interface{})); err != io.EOF || releases == nil || limited.N == 0 {
		return nil, fmt.Errorf("список опубликованных релизов повреждён")
	}
	var found []Release
	versions := map[string]semver{}
	for _, payload := range releases {
		version, valid := parseSemver(payload.TagName)
		if !valid || payload.Draft || !includePreview && (payload.Prerelease || version.isPrerelease()) {
			continue
		}
		release := u.releaseView(payload)
		// A release can be visible briefly before all CI assets are uploaded,
		// and the signature is added by the maintainer after that.
		if release.assetURL == "" || release.sumsURL == "" || release.sigURL == "" {
			continue
		}
		if _, twice := versions[release.Tag]; twice {
			continue
		}
		versions[release.Tag] = version
		found = append(found, release)
	}
	sort.SliceStable(found, func(i, j int) bool {
		return newer(versions[found[j].Tag], versions[found[i].Tag])
	})
	// Only the newest one shows its notes; the rest are a list to pick from.
	for i := 1; i < len(found); i++ {
		found[i].Notes = ""
	}
	return found, nil
}

func (u *Updater) expectedSum(ctx context.Context, release Release) (string, error) {
	if release.sumsURL == "" {
		return "", fmt.Errorf("в релизе %s нет %s — установка без проверки суммы отменена", release.Tag, sumsAsset)
	}

	if release.sigURL == "" {
		return "", fmt.Errorf("в релизе %s нет подписи %s — установка отменена", release.Tag, releasesig.Asset)
	}

	sums, err := u.fetchSmall(ctx, release.sumsURL)
	if err != nil {
		return "", fmt.Errorf("%s не прочитан: %w", sumsAsset, err)
	}
	signature, err := u.fetchSmall(ctx, release.sigURL)
	if err != nil {
		return "", fmt.Errorf("%s не прочитан: %w", releasesig.Asset, err)
	}
	// GitHub can serve any file under this name. Only checksums approved with
	// a release key decide which binary may replace the running panel.
	if err := releasesig.Verify(u.keys, release.Tag, sums, signature); err != nil {
		return "", fmt.Errorf("релиз %s: %w — установка отменена", release.Tag, err)
	}

	scanner := bufio.NewScanner(bytes.NewReader(sums))
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

// fetchSmall reads a short text asset whole, so that the bytes checked by the
// signature are the bytes that are then used.
func (u *Updater) fetchSmall(ctx context.Context, address string) ([]byte, error) {
	resp, err := u.get(ctx, address, "")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	const limit = 64 << 10
	body, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, err
	}
	if len(body) > limit {
		return nil, errors.New("файл слишком большой")
	}
	return body, nil
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
		return parsed.Path == "/repos/"+repo+"/releases" && parsed.RawQuery == "per_page=100"
	}
	return parsed.Host == "github.com" && parsed.RawQuery == "" && strings.HasPrefix(parsed.Path, "/"+repo+"/releases/download/") && !strings.Contains(parsed.Path, "/../")
}
