package cardcontroller

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"xkeen-panel/internal/geoip"
)

const refilterKey = "x-xkeen-panel-refilter"
const refilterSites = "XKP-refilter-domains"
const refilterIPs = "XKP-refilter-ip"

type RefilterStatus struct {
	Enabled                  bool   `json:"enabled"`
	Mode                     string `json:"mode"`
	ProtectedFallback        bool   `json:"protected_fallback"`
	ActiveConnectionsPending bool   `json:"active_connections_pending,omitempty"`
	Source                   string `json:"source"`
	Domains                  int    `json:"domains"`
	Prefixes                 int    `json:"prefixes"`
	UpdatedAt                string `json:"updated_at,omitempty"`
	Error                    string `json:"error,omitempty"`
}

type refilterCache struct {
	Enabled        bool   `json:"enabled"`
	Domains        int    `json:"domains"`
	Prefixes       int    `json:"prefixes"`
	DomainBehavior string `json:"domain_behavior"`
	SiteHash       string `json:"site_hash"`
	IPHash         string `json:"ip_hash"`
	Stamp          string `json:"stamp"`
	UpdatedAt      string `json:"updated_at"`
	DrainToken     string `json:"drain_token"`
}

func refilterEnabled(doc map[string]interface{}) bool {
	value, _ := object(doc[refilterKey])["enabled"].(bool)
	return value
}

func readRefilter(doc map[string]interface{}) (refilterCache, error) {
	var c refilterCache
	if raw, exists := doc[refilterKey]; exists {
		b, err := json.Marshal(raw)
		if err != nil || json.Unmarshal(b, &c) != nil || !validHash(c.SiteHash) || !validHash(c.IPHash) || c.Domains <= 0 || c.Prefixes <= 0 || c.DomainBehavior != "domain" && c.DomainBehavior != "classical" {
			return c, errors.New("повреждены метаданные локальной базы Re:filter")
		}
	}
	return c, nil
}

func (v refilterCache) status(problem string) RefilterStatus {
	mode := "custom"
	if v.Enabled {
		mode = "blocklist"
	}
	return RefilterStatus{Enabled: v.Enabled, Mode: mode, Source: "Re:filter", Domains: v.Domains, Prefixes: v.Prefixes, UpdatedAt: v.UpdatedAt, Error: problem}
}

func (c *Controller) RefilterStatus() (RefilterStatus, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	p, err := c.read()
	if err != nil {
		return RefilterStatus{}, err
	}
	info, err := readRefilter(p.doc)
	if _, _, modeErr := readProtectedRouting(p.doc); modeErr != nil {
		return RefilterStatus{}, modeErr
	}
	return c.routingModeStatus(p, info.status(c.refilterError)), err
}

func refilterPath(name, hash string) string { return name + "-" + hash + ".txt" }

func saveRuleFile(dir, name string, file geoip.RuleFile) (string, error) {
	sum := sha256.Sum256(file.Data)
	hash := hex.EncodeToString(sum[:])
	target := filepath.Join(dir, refilterPath(name, hash))
	if info, err := os.Lstat(target); err == nil {
		if !info.Mode().IsRegular() {
			return "", errors.New("путь набора правил Re:filter занят")
		}
		if info.Size() == int64(len(file.Data)) {
			data, err := os.ReadFile(target)
			if err == nil && bytes.Equal(data, file.Data) {
				return hash, nil
			}
		}
	} else if !os.IsNotExist(err) {
		return "", err
	}
	tmp, err := stage(dir, file.Data)
	if err != nil {
		return "", err
	}
	defer os.Remove(tmp)
	return hash, os.Rename(tmp, target)
}

func refilterStamp(site, ip string) (string, error) {
	var parts []string
	for _, path := range []string{site, ip} {
		info, err := os.Stat(path)
		if err != nil || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > 32<<20 {
			return "", errors.New("локальные базы GeoSite и GeoIP Re:filter недоступны")
		}
		parts = append(parts, fmt.Sprintf("%d-%d", info.Size(), info.ModTime().UnixNano()))
	}
	return strings.Join(parts, "/"), nil
}

// Call from the existing maintenance loop under the normal panel change lock.
// Unchanged sources cost two stats; an update keeps the old immutable pair
// until Mihomo has accepted both new files in one configuration reload.
func (c *Controller) UpdateRefilter(ctx context.Context, enabled *bool, force bool) (RefilterStatus, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	p, err := c.read()
	if err != nil {
		return RefilterStatus{}, err
	}
	old, err := readRefilter(p.doc)
	if err != nil {
		return RefilterStatus{}, err
	}
	status := func(info refilterCache, problem string) RefilterStatus {
		return c.routingModeStatus(p, info.status(problem))
	}
	next := old
	if err := c.finishRefilterDrain(ctx, p, old); err != nil {
		c.refilterError = err.Error()
		return status(old, c.refilterError), err
	}
	if enabled != nil {
		next.Enabled = *enabled
	}
	if !next.Enabled && !force && !old.Enabled {
		return status(old, c.refilterError), nil
	}
	fail := func(err error) (RefilterStatus, error) {
		c.refilterError = err.Error()
		return status(old, c.refilterError), err
	}
	dir := filepath.Dir(c.path)
	if next.Enabled || force {
		assets := filepath.Join(filepath.Dir(c.rt.XrayConfDir), "dat")
		site, ip := filepath.Join(assets, "geosite_refilter.dat"), filepath.Join(assets, "geoip_refilter.dat")
		stamp, err := refilterStamp(site, ip)
		if err != nil {
			return fail(err)
		}
		if !force && old.Enabled && old.Stamp == stamp {
			c.refilterError = ""
			return status(old, ""), nil
		}
		domains, err := geoip.ReadRefilter(site, true)
		if err != nil {
			return fail(err)
		}
		prefixes, err := geoip.ReadRefilter(ip, false)
		if err != nil {
			return fail(err)
		}
		after, err := refilterStamp(site, ip)
		if err != nil || after != stamp {
			return fail(errors.New("геобазы изменились во время чтения, сохранена прежняя копия"))
		}
		next.SiteHash, err = saveRuleFile(dir, refilterSites, domains)
		if err != nil {
			return fail(err)
		}
		next.IPHash, err = saveRuleFile(dir, refilterIPs, prefixes)
		if err != nil {
			return fail(err)
		}
		next.Domains, next.Prefixes, next.DomainBehavior, next.Stamp = domains.Count, prefixes.Count, domains.Behavior, stamp
		if old.SiteHash != next.SiteHash || old.IPHash != next.IPHash {
			next.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
		}
	}
	if next.Enabled != old.Enabled || next.Enabled && (old.SiteHash != next.SiteHash || old.IPHash != next.IPHash) {
		next.DrainToken = time.Now().UTC().Format(time.RFC3339Nano)
	}
	if next != old {
		_, err = c.apply(ctx, "", "", func(p *profile) error {
			// Keep YAML maps through the render pass, including on first activation.
			b, _ := json.Marshal(next)
			state := map[string]interface{}{}
			_ = json.Unmarshal(b, &state)
			if prior := object(p.doc["rule-providers"]); prior != nil {
				for _, name := range []string{refilterIPs, refilterSites} {
					if _, exists := prior[name]; exists && !old.Enabled {
						return errors.New("имя набора правил Re:filter уже занято в профиле")
					}
				}
			}
			p.doc[refilterKey] = state
			return nil
		})
		if err != nil {
			c.cleanRefilterCandidate(next, old)
			return fail(err)
		}
		current, err := c.read()
		if err != nil {
			return fail(err)
		}
		p = current
		if err = c.finishRefilterDrain(ctx, current, next); err != nil {
			c.refilterError = err.Error()
			return status(next, c.refilterError), err
		}
	}
	for _, item := range []struct{ name, old, next string }{{refilterSites, old.SiteHash, next.SiteHash}, {refilterIPs, old.IPHash, next.IPHash}} {
		if item.old != "" && item.old != item.next {
			_ = os.Remove(filepath.Join(dir, refilterPath(item.name, item.old)))
		}
	}
	c.refilterError = ""
	return status(next, ""), nil
}

// c.apply may fail after the new file is already live. Inspect the installed
// profile before removing newly created, content-addressed files on failure.
func (c *Controller) cleanRefilterCandidate(next, old refilterCache) {
	p, err := c.read()
	if err != nil {
		return
	}
	current, err := readRefilter(p.doc)
	if err != nil {
		return
	}
	for _, v := range []struct{ name, candidate, old, current string }{{refilterSites, next.SiteHash, old.SiteHash, current.SiteHash}, {refilterIPs, next.IPHash, old.IPHash, current.IPHash}} {
		if validHash(v.candidate) && v.candidate != v.old && v.candidate != v.current {
			_ = os.Remove(filepath.Join(filepath.Dir(c.path), refilterPath(v.name, v.candidate)))
		}
	}
}

func (a coreAPI) refilterReady(ctx context.Context, doc map[string]interface{}) bool {
	if !refilterEnabled(doc) {
		return true
	}
	v, err := readRefilter(doc)
	if err != nil {
		return false
	}
	var response struct {
		Providers map[string]struct {
			RuleCount int
			Behavior  string
		}
	}
	if a.request(ctx, "GET", "/providers/rules", nil, &response) != nil {
		return false
	}
	sites, ips := response.Providers[refilterSites], response.Providers[refilterIPs]
	return sites.RuleCount == v.Domains && ips.RuleCount == v.Prefixes && strings.EqualFold(sites.Behavior, v.DomainBehavior) && strings.EqualFold(ips.Behavior, "ipcidr")
}

func refilterProviders(doc map[string]interface{}, info refilterCache) error {
	providers := object(doc["rule-providers"])
	if raw, found := doc["rule-providers"]; found && raw != nil && providers == nil {
		return errors.New("неподдерживаемый формат rule-providers")
	}
	if providers == nil && info.Enabled {
		providers = map[string]interface{}{}
		doc["rule-providers"] = providers
	}
	for _, item := range []struct{ name, behavior, hash string }{{refilterSites, info.DomainBehavior, info.SiteHash}, {refilterIPs, "ipcidr", info.IPHash}} {
		if info.Enabled {
			providers[item.name] = map[string]interface{}{"type": "file", "behavior": item.behavior, "format": "text", "path": refilterPath(item.name, item.hash)}
		} else {
			delete(providers, item.name)
		}
	}
	return nil
}
