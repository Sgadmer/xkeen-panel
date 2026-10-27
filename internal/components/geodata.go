package components

import (
	"context"
	"fmt"
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
func (m *Manager) geodataPath(source GeoSource) string {
	rt := m.runtime()
	if source.Kind == "GeoIPSET" {
		return filepath.Join(filepath.Dir(rt.XkeenJSON), "ipset", source.Filename)
	}
	return filepath.Join(filepath.Dir(rt.XrayConfDir), "dat", source.Filename)
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
