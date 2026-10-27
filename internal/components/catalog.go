// Package components manages verified upstream binaries and geodata. It never
// downloads a user supplied URL or executes an interactive menu by feeding keys.
package components

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

const maxArtifact = 128 << 20

type Asset struct {
	Name   string `json:"name"`
	Size   int64  `json:"size"`
	Digest string `json:"digest"`
	URL    string `json:"browser_download_url"`
}

type Release struct {
	Version    string  `json:"tag_name"`
	Name       string  `json:"name"`
	Prerelease bool    `json:"prerelease"`
	Draft      bool    `json:"draft"`
	URL        string  `json:"html_url"`
	Published  string  `json:"published_at"`
	Assets     []Asset `json:"-"`
}

type githubRelease struct {
	Version    string  `json:"tag_name"`
	Name       string  `json:"name"`
	Prerelease bool    `json:"prerelease"`
	Draft      bool    `json:"draft"`
	URL        string  `json:"html_url"`
	Published  string  `json:"published_at"`
	Assets     []Asset `json:"assets"`
}

func (r githubRelease) release() Release {
	return Release{r.Version, r.Name, r.Prerelease, r.Draft, r.URL, r.Published, r.Assets}
}

var tagPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+-]{0,79}$`)

func officialRepo(component string) (string, error) {
	switch component {
	case "xkeen":
		return "jameszeroX/XKeen", nil
	case "xray":
		return "XTLS/Xray-core", nil
	}
	return "", fmt.Errorf("неизвестный компонент")
}

func (m *Manager) request(ctx context.Context, address string, limit int64) ([]byte, error) {
	u, err := url.Parse(address)
	if err != nil || !m.allowedURL(u) {
		return nil, fmt.Errorf("источник загрузки не разрешён")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, address, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "xkeen-panel-components")
	req.Header.Set("Accept", "application/vnd.github+json")
	resp, err := m.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("источник обновления недоступен")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		if resp.StatusCode == 403 || resp.StatusCode == 429 {
			return nil, fmt.Errorf("GitHub ограничил запросы; повторите позже")
		}
		return nil, fmt.Errorf("источник обновления ответил HTTP %d", resp.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil || int64(len(b)) > limit {
		return nil, fmt.Errorf("ответ обновления слишком большой или повреждён")
	}
	return b, nil
}

func (m *Manager) allowedURL(u *url.URL) bool {
	if u.User != nil || u.Fragment != "" {
		return false
	}
	if m.opts.TestHTTP && (u.Scheme == "http" || u.Scheme == "https") {
		return true
	}
	if u.Scheme != "https" || (u.Port() != "" && u.Port() != "443") {
		return false
	}
	switch strings.ToLower(u.Hostname()) {
	case "api.github.com", "github.com", "release-assets.githubusercontent.com", "objects.githubusercontent.com", "raw.githubusercontent.com":
		return true
	}
	return false
}

func (m *Manager) Releases(ctx context.Context, component, channel string) ([]Release, error) {
	repo, err := officialRepo(component)
	if err != nil {
		return nil, err
	}
	if channel != "stable" && channel != "prerelease" && channel != "all" {
		return nil, fmt.Errorf("выберите stable, prerelease или all")
	}
	key := component + ":" + channel
	m.mu.Lock()
	cached, ok := m.catalog[key]
	m.mu.Unlock()
	if ok && time.Since(cached.at) < 15*time.Minute {
		return append([]Release(nil), cached.releases...), nil
	}
	b, err := m.request(ctx, m.apiBase+"/repos/"+repo+"/releases?per_page=50", 4<<20)
	if err != nil {
		return nil, err
	}
	var incoming []githubRelease
	if json.Unmarshal(b, &incoming) != nil {
		return nil, fmt.Errorf("список версий не разобран")
	}
	var result []Release
	for _, r := range incoming {
		if !r.Draft && tagPattern.MatchString(r.Version) && (channel == "all" || channel == "stable" && !r.Prerelease || channel == "prerelease" && r.Prerelease) {
			result = append(result, r.release())
		}
	}
	if result == nil {
		result = []Release{}
	}
	m.mu.Lock()
	m.catalog[key] = catalogCache{time.Now(), result}
	m.mu.Unlock()
	return result, nil
}

func (m *Manager) release(ctx context.Context, repo, version string) (Release, error) {
	if !tagPattern.MatchString(version) {
		return Release{}, fmt.Errorf("неверный номер версии")
	}
	b, err := m.request(ctx, m.apiBase+"/repos/"+repo+"/releases/tags/"+url.PathEscape(version), 2<<20)
	if err != nil {
		return Release{}, err
	}
	var r githubRelease
	if json.Unmarshal(b, &r) != nil || r.Version != version || r.Draft {
		return Release{}, fmt.Errorf("релиз не найден или ещё не опубликован")
	}
	return r.release(), nil
}

func (m *Manager) latestRelease(ctx context.Context, repo string) (Release, error) {
	b, err := m.request(ctx, m.apiBase+"/repos/"+repo+"/releases/latest", 2<<20)
	if err != nil {
		return Release{}, err
	}
	var r githubRelease
	if json.Unmarshal(b, &r) != nil || !tagPattern.MatchString(r.Version) || r.Draft {
		return Release{}, fmt.Errorf("релиз не найден")
	}
	return r.release(), nil
}

func assetByName(release Release, name string) (Asset, error) {
	for _, asset := range release.Assets {
		if asset.Name == name && asset.Size > 0 && asset.Size <= maxArtifact {
			return asset, nil
		}
	}
	return Asset{}, fmt.Errorf("в релизе нет подходящего файла %s", name)
}

func (m *Manager) resolveArtifact(ctx context.Context, repo string, release Release, name, target string) (Artifact, error) {
	asset, err := assetByName(release, name)
	if err != nil {
		return Artifact{}, err
	}
	u, err := url.Parse(asset.URL)
	if err != nil || !m.allowedURL(u) {
		return Artifact{}, fmt.Errorf("недопустимый адрес файла релиза")
	}
	if !m.opts.TestHTTP {
		prefix := "/" + repo + "/releases/download/" + release.Version + "/"
		if !strings.EqualFold(u.Hostname(), "github.com") || !strings.HasPrefix(strings.ToLower(u.Path), strings.ToLower(prefix)) || filepath.Base(u.Path) != name {
			return Artifact{}, fmt.Errorf("файл не принадлежит выбранному официальному релизу")
		}
	}
	sum := strings.TrimPrefix(asset.Digest, "sha256:")
	if !validSHA(sum) {
		// Xray publishes an adjacent .dgst for older releases without an API digest.
		checksum, lookup := assetByName(release, name+".dgst")
		if lookup != nil {
			return Artifact{}, fmt.Errorf("у файла нет проверяемой SHA-256; версия недоступна для безопасной установки")
		}
		if !m.opts.TestHTTP && !strings.HasPrefix(checksum.URL, strings.TrimSuffix(asset.URL, name)) {
			return Artifact{}, fmt.Errorf("недопустимый адрес контрольной суммы")
		}
		body, e := m.request(ctx, checksum.URL, 64<<10)
		if e != nil {
			return Artifact{}, e
		}
		match := regexp.MustCompile(`(?im)^SHA2?-256\s*=\s*([a-f0-9]{64})\s*$`).FindSubmatch(body)
		if len(match) != 2 {
			return Artifact{}, fmt.Errorf("SHA-256 релиза не найдена")
		}
		sum = strings.ToLower(string(match[1]))
	}
	return Artifact{Name: name, URL: asset.URL, SHA256: strings.ToLower(sum), Size: asset.Size, Target: target, Version: release.Version, Repository: repo}, nil
}

func validSHA(s string) bool { b, e := hex.DecodeString(s); return e == nil && len(b) == 32 }

func (m *Manager) download(ctx context.Context, artifact Artifact, path string) error {
	if !validSHA(artifact.SHA256) || artifact.Size < 1 || artifact.Size > maxArtifact {
		return fmt.Errorf("некорректный манифест загрузки")
	}
	u, e := url.Parse(artifact.URL)
	if e != nil || !m.allowedURL(u) {
		return fmt.Errorf("недопустимый источник")
	}
	req, e := http.NewRequestWithContext(ctx, http.MethodGet, artifact.URL, nil)
	if e != nil {
		return e
	}
	req.Header.Set("User-Agent", "xkeen-panel-components")
	resp, e := m.client.Do(req)
	if e != nil {
		return fmt.Errorf("не удалось загрузить компонент")
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("не удалось загрузить компонент: HTTP %d", resp.StatusCode)
	}
	f, e := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if e != nil {
		return e
	}
	h := sha256.New()
	n, copyErr := io.Copy(io.MultiWriter(f, h), io.LimitReader(resp.Body, artifact.Size+1))
	closeErr := f.Close()
	if copyErr != nil || closeErr != nil || n != artifact.Size || hex.EncodeToString(h.Sum(nil)) != artifact.SHA256 {
		_ = os.Remove(path)
		return fmt.Errorf("файл повреждён или его SHA-256 не совпала")
	}
	return nil
}
