package components

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

type GeoSource struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	Kind       string `json:"kind"`
	Repository string `json:"repository"`
	Asset      string `json:"asset"`
	Filename   string `json:"filename"`
}

func GeoSources() []GeoSource {
	return []GeoSource{
		{"geosite-refilter", "Re:filter", "GeoSite", "1andrevich/Re-filter-lists", "geosite.dat", "geosite_refilter.dat"},
		{"geosite-v2fly", "v2fly", "GeoSite", "v2fly/domain-list-community", "dlc.dat", "geosite_v2fly.dat"},
		{"geosite-zkeen", "ZKeen", "GeoSite", "jameszeroX/zkeen-domains", "zkeen.dat", "geosite_zkeen.dat"},
		{"geoip-refilter", "Re:filter", "GeoIP", "1andrevich/Re-filter-lists", "geoip.dat", "geoip_refilter.dat"},
		{"geoip-v2fly", "Loyalsoldier / v2fly", "GeoIP", "Loyalsoldier/v2ray-rules-dat", "geoip.dat", "geoip_v2fly.dat"},
		{"geoip-zkeen", "ZKeenIP", "GeoIP", "jameszeroX/zkeen-ip", "zkeenip.dat", "geoip_zkeenip.dat"},
		{"geoipset-ru4", "Российские IPv4 напрямую", "GeoIPSET", "jameszeroX/zkeen-ip", "ru", "ru_exclude_ipv4.lst"},
		{"geoipset-ru6", "Российские IPv6 напрямую", "GeoIPSET", "jameszeroX/zkeen-ip", "ru6", "ru_exclude_ipv6.lst"},
	}
}
func geoSource(id string) (GeoSource, bool) {
	for _, source := range GeoSources() {
		if source.ID == id {
			return source, true
		}
	}
	return GeoSource{}, false
}
func validateGeo(s GeoSettings) error {
	if s.Day < -1 || s.Day > 6 || s.Hour < 0 || s.Hour > 23 || s.Minute < 0 || s.Minute > 59 || len(s.Sources) > 8 {
		return fmt.Errorf("неверное расписание геобаз")
	}
	seen := map[string]bool{}
	for _, id := range s.Sources {
		if _, ok := geoSource(id); !ok || seen[id] {
			return fmt.Errorf("неизвестный или повторный источник геобаз")
		}
		seen[id] = true
	}
	if s.Auto && len(s.Sources) == 0 {
		return fmt.Errorf("для автообновления выберите источники")
	}
	return nil
}

func sourceForFilename(name string) (GeoSource, bool) {
	for _, s := range GeoSources() {
		if s.Filename == name {
			return s, true
		}
	}
	return GeoSource{}, false
}
func (m *Manager) logicalGeodataPath(source GeoSource) string {
	rt := m.runtime()
	if source.Kind == "GeoIPSET" {
		return filepath.Join(filepath.Dir(rt.XkeenJSON), "ipset", source.Filename)
	}
	return filepath.Join(filepath.Dir(rt.XrayConfDir), "dat", source.Filename)
}

// These two aliases are created by existing XKeen installations. Keep their
// native targets in use so an XKeen refresh and a panel refresh update one file.
// No other symlink is allowed to redirect a component transaction.
func (m *Manager) nativeGeoAliases() map[string]string {
	dir := filepath.Join(filepath.Dir(m.runtime().XrayConfDir), "dat")
	return map[string]string{
		filepath.Join(dir, "geosite_zkeen.dat"): filepath.Join(dir, "zkeen.dat"),
		filepath.Join(dir, "geoip_zkeenip.dat"): filepath.Join(dir, "zkeenip.dat"),
	}
}

func (m *Manager) nativeGeoLinkTarget(path, link string) (string, bool) {
	expected, ok := m.nativeGeoAliases()[filepath.Clean(path)]
	if !ok || link == "" {
		return "", false
	}
	// Accept the native absolute form and a direct basename only. Cleaning
	// parent segments could disguise a path through an intermediate symlink.
	if link != expected && link != filepath.Base(expected) {
		return "", false
	}
	return expected, true
}

func (m *Manager) trustedGeoLink(path string) (string, string, error) {
	link, err := os.Readlink(path)
	if err != nil {
		return "", "", err
	}
	target, ok := m.nativeGeoLinkTarget(path, link)
	if !ok {
		return "", "", fmt.Errorf("неподдерживаемая ссылка в управляемой геобазе")
	}
	// Only a single hop to the exact known filename is supported. A missing
	// native file may be downloaded, and its previous absence is backed up.
	if info, err := os.Lstat(target); err == nil {
		if !info.Mode().IsRegular() {
			return "", "", fmt.Errorf("неподдерживаемая цель ссылки геобазы")
		}
	} else if !os.IsNotExist(err) {
		return "", "", err
	}
	return target, link, nil
}

func (m *Manager) geodataWritePath(source GeoSource) (string, error) {
	path := m.logicalGeodataPath(source)
	if info, err := os.Lstat(path); err == nil {
		if info.Mode()&os.ModeSymlink != 0 {
			target, _, err := m.trustedGeoLink(path)
			return target, err
		}
		if !info.Mode().IsRegular() {
			return "", fmt.Errorf("необычный файл вместо геобазы")
		}
	} else if !os.IsNotExist(err) {
		return "", err
	}
	return path, nil
}

func (m *Manager) geodataPath(source GeoSource) string {
	path, err := m.geodataWritePath(source)
	if err != nil {
		// Planning/capture will reject the original unsafe link before mutation.
		return m.logicalGeodataPath(source)
	}
	return path
}
func (m *Manager) SetGeodata(s GeoSettings) error {
	if e := validateGeo(s); e != nil {
		return e
	}
	if s.Auto && m.externalGeoSchedule() {
		return fmt.Errorf("сначала отключите штатное расписание геобаз XKeen в параметрах ниже; затем включите расписание панели")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.job != nil && m.job.Finished == nil {
		return fmt.Errorf("дождитесь завершения операции")
	}
	s.LastAttempt = m.geo.LastAttempt
	s.Sources = sortedUnique(s.Sources)
	old := m.geo
	m.geo = s
	if e := m.saveGeoLocked(); e != nil {
		m.geo = old
		return fmt.Errorf("не удалось сохранить расписание")
	}
	return nil
}

// Start runs selected geodata updates at router-local time. Core upgrades are
// always explicit and are never scheduled by this loop.
func (m *Manager) Start(ctx context.Context) {
	m.Recover(ctx)
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			m.tick(ctx, now)
		}
	}
}
func (m *Manager) tick(ctx context.Context, now time.Time) {
	m.mu.Lock()
	s := m.geo
	busy := m.job != nil && m.job.Finished == nil
	today := now.Format("2006-01-02")
	if busy || !s.Auto || s.LastAttempt == today || s.Day >= 0 && int(now.Weekday()) != s.Day || now.Hour() < s.Hour || now.Hour() == s.Hour && now.Minute() < s.Minute {
		m.mu.Unlock()
		return
	}
	m.geo.LastAttempt = today
	if e := m.saveGeoLocked(); e != nil {
		m.mu.Unlock()
		return
	}
	m.mu.Unlock()
	plan, e := m.Preview(ctx, PlanRequest{Component: "geodata"})
	if e == nil {
		_, e = m.Apply(plan.ID)
	}
	if e != nil && m.opts.Log != nil {
		m.opts.Log("[COMPONENTS] Запланированное обновление геобаз не выполнено: %v", e)
	}
}
