package cardcontroller

import (
	"context"
	"encoding/json"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"xkeen-panel/internal/models"
	"xkeen-panel/internal/xkeen"
)

func planOf(t *testing.T, c *Controller, p profile, dir string, file Portable) (map[string][]string, map[string][]string) {
	t.Helper()
	steps, skipped, err := c.planImport(p, dir, file)
	if err != nil {
		t.Fatal(err)
	}
	changes := map[string][]string{}
	for _, step := range steps {
		changes[step.section] = append(changes[step.section], step.text)
	}
	return changes, skipped
}

func has(lines []string, part string) bool {
	for _, line := range lines {
		if strings.Contains(line, part) {
			return true
		}
	}
	return false
}

// What lowers protection is kept apart from everything else, and what can not
// be done on this router is told instead of being guessed.
func TestImportPlanSeparatesWhatWeakensProtection(t *testing.T) {
	dir := t.TempDir()
	key := strings.Repeat("a", 64)
	nl := models.Server{Name: "Амстердам", SourceName: "Север", RawURI: "vless://11111111-2222-3333-4444-555555555555@192.0.2.1:443?type=tcp"}
	twin := models.Server{Name: "Двойник", SourceName: "Север", RawURI: "vless://11111111-2222-3333-4444-555555555555@192.0.2.2:443?type=tcp"}
	twin2 := models.Server{Name: "Двойник", SourceName: "Юг", RawURI: "vless://11111111-2222-3333-4444-555555555555@192.0.2.3:443?type=tcp"}
	servers := []models.Server{nl, twin, twin2}
	c := New(filepath.Join(dir, "config.yaml"), dir, xkeen.Runtime{}, func() []models.Server { return servers })
	registerCustom(t, customService(t, customCard, "Форум", "forum.example.org"))
	p := profile{
		// The common route and the general kill switch make this router "protected".
		assigned: map[string]string{defaultID: key, "claude": key, "youtube": allPoolID, "steam": directTarget, customCard: allPoolID},
		doc: map[string]interface{}{
			stateKey:            map[string]interface{}{},
			protectedRoutingKey: map[string]interface{}{"version": 1, "drain_token": time.Now().UTC().Format(time.RFC3339Nano)},
			killSwitchKey:       map[string]interface{}{"enabled": true, "services": map[string]interface{}{"telegram": "off"}},
			exclusionKey:        xkeen.Exclusions{Entries: []xkeen.Exclusion{exclusion(t, "kept.example.org")}},
			"rules":             []interface{}{"DOMAIN-SUFFIX,kept.example.org,DIRECT", "MATCH,DIRECT"},
		},
	}
	file := Portable{
		KillSwitch:  &PortableKillSwitch{Enabled: false, Cards: map[string]string{"telegram": "on", "youtube": "off", "discord": "inherit", "claude": "on", "nobody": "on", "custom:Форум": "off", "github": "sometimes"}},
		RoutingMode: "blocklist",
		DNS:         &DNSSettings{Mode: dnsModeSecure, Preset: "quad9"},
		CustomServices: []PortableService{
			{Name: "Форум", Addresses: []string{"forum.example.org", "more.example.org"}},
			{Name: "Банк", Addresses: []string{"bank.example.org"}},
			{Name: "Подмена", Addresses: []string{"api.anthropic.com"}},
		},
		Exclusions: []PortableExclusion{{Value: "kept.example.org"}, {Value: "new.example.org", Comment: "новое"}, {Value: "claude.ai"}, {Value: "*.com"}},
		Routes: map[string]PortableRoute{
			"claude":       {Kind: "direct"},
			"youtube":      {Kind: "direct"},
			"steam":        {Kind: "direct"},
			"telegram":     {Kind: "country", Country: "nl"},
			"discord":      {Kind: "server", Source: "Север", Name: "Амстердам"},
			"github":       {Kind: "server", Name: "Двойник"},
			"spotify":      {Kind: "server", Source: "Север", Name: "Нет такого"},
			"netflix":      {Kind: "pool", Name: "Мой пул"},
			"custom:Банк":  {Kind: "auto"},
			"custom:Чужой": {Kind: "auto"},
			"twitch":       {Kind: "teleport"},
		},
	}
	changes, skipped := planOf(t, c, p, dir, file)

	// Lowering protection: three sections of their own.
	weak := changes["weak_kill_switch"]
	if !has(weak, "Выключить общий kill switch") || !has(weak, "YouTube: всегда выключен") || !has(weak, "Форум: всегда выключен") || !has(weak, "Discord: как в настройках") {
		t.Errorf("weak kill switch changes: %v", weak)
	}
	if !has(changes["weak_routing_mode"], "по списку блокировок") {
		t.Errorf("the block-list mode is not a weakening change: %v", changes)
	}
	if weakRoutes := changes["weak_routes"]; len(weakRoutes) != 1 || !has(weakRoutes, "YouTube → напрямую") {
		t.Errorf("direct routes: %v", weakRoutes)
	}
	// Everything else, including what raises protection.
	if safe := changes["kill_switch"]; len(safe) != 1 || !has(safe, "Telegram: всегда включён") {
		t.Errorf("safe kill switch changes: %v", safe)
	}
	if routes := changes["routes"]; len(routes) != 3 || !has(routes, "Telegram → пул страны NL") || !has(routes, "Discord → сервер «Амстердам» (Север)") || !has(routes, "Банк → автовыбор") {
		t.Errorf("routes: %v", routes)
	}
	if services := changes["custom_services"]; len(services) != 2 || !has(services, "Изменить адреса сервиса «Форум»") || !has(services, "Добавить сервис «Банк»") {
		t.Errorf("custom services: %v", services)
	}
	if added := changes["exclusions"]; len(added) != 1 || !has(added, "new.example.org") || has(added, "kept.example.org") || has(added, "claude.ai") {
		t.Errorf("exclusions: %v", added)
	}
	if !has(changes["dns"], "quad9") {
		t.Errorf("dns: %v", changes["dns"])
	}
	// What is left out, with the reason.
	for section, part := range map[string]string{
		"custom_services": "Claude", "exclusions": "Claude",
	} {
		if !has(skipped[section], part) {
			t.Errorf("%s: no skipped line about %q in %v", section, part, skipped[section])
		}
	}
	for _, part := range []string{"Claude / Anthropic: этой карточке нужен VPN", "неоднозначно", "в подписках этого роутера нет", "мультипула «Мой пул» здесь нет", "карточки «Чужой» здесь нет", "неизвестный вид маршрута"} {
		if !has(skipped["routes"], part) {
			t.Errorf("routes: no skipped line about %q in %v", part, skipped["routes"])
		}
	}
	for _, part := range []string{"карточки «nobody» здесь нет", "неизвестный режим"} {
		if !has(skipped["kill_switch"], part) {
			t.Errorf("kill switch: no skipped line about %q in %v", part, skipped["kill_switch"])
		}
	}
	if has(changes["routes"], "Steam") || has(changes["weak_routes"], "Steam") {
		t.Error("an unchanged route was planned again")
	}

	// A file that says what is already so changes nothing.
	same := Portable{
		KillSwitch:     &PortableKillSwitch{Enabled: true, Cards: map[string]string{"telegram": "off"}},
		RoutingMode:    "protected",
		DNS:            &DNSSettings{Mode: dnsModeRouter},
		CustomServices: []PortableService{{Name: "Форум", Addresses: []string{"forum.example.org"}}},
		Exclusions:     []PortableExclusion{{Value: "kept.example.org"}},
		Routes:         map[string]PortableRoute{"youtube": {Kind: "auto"}, "steam": {Kind: "direct"}, "custom:Форум": {Kind: "auto"}},
	}
	if changes, skipped = planOf(t, c, p, dir, same); len(changes) != 0 || len(skipped) != 0 {
		t.Fatalf("an import of the current state plans changes: %v, skipped %v", changes, skipped)
	}
}

func isolatedCore(t *testing.T, core string, ctx context.Context) (*Controller, string) {
	t.Helper()
	dir := t.TempDir()
	config := filepath.Join(dir, "config.yaml")
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	listener.Close()
	raw, _ := json.Marshal(map[string]interface{}{"external-controller": address, "secret": "synthetic-token", "mode": "rule", "rules": []string{"MATCH,DIRECT"}})
	if err = os.WriteFile(config, raw, 0600); err != nil {
		t.Fatal(err)
	}
	proc := exec.CommandContext(ctx, core, "-d", dir, "-f", config)
	if err = proc.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = proc.Process.Kill(); _, _ = proc.Process.Wait() })
	c := New(config, dir, xkeen.Runtime{Core: xkeen.CoreMihomo, XrayConfDir: filepath.Join(dir, "xray")}, func() []models.Server { return nil })
	c.validate = func(ctx context.Context, p string) error {
		return exec.CommandContext(ctx, core, "-t", "-d", dir, "-f", p).Run()
	}
	p, err := c.read()
	if err != nil {
		t.Fatal(err)
	}
	for !p.api.ruleMode(ctx) {
		if ctx.Err() != nil {
			t.Fatal(ctx.Err())
		}
		time.Sleep(20 * time.Millisecond)
	}
	return c, dir
}

// Against a real core: what one router exports, another applies and then
// exports the same.
func TestLiveSettingsTravelBetweenRouters(t *testing.T) {
	core := os.Getenv("MIHOMO_TEST_BINARY")
	if core == "" {
		t.Skip("real Mihomo fixture unavailable")
	}
	t.Cleanup(func() { xkeen.SetCustomServices(nil) })
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Second)
	defer cancel()
	file := Portable{
		KillSwitch: &PortableKillSwitch{Enabled: true, Cards: map[string]string{"youtube": "off", "custom:Банк": "inherit"}},
		// The fixture has no server for a common route, so the routing mode is left out.
		DNS:            &DNSSettings{Mode: dnsModeRouter},
		CustomServices: []PortableService{{Name: "Банк", Addresses: []string{"bank.example.org", "203.0.113.0/24"}}},
		Exclusions:     []PortableExclusion{{Value: "domain:direct.example.org", Comment: "напрямую"}, {Value: "pattern:www.shop.*", Disabled: true}},
		Routes:         map[string]PortableRoute{"steam": {Kind: "direct"}, "youtube": {Kind: "auto"}, "custom:Банк": {Kind: "direct"}},
	}
	c, dir := isolatedCore(t, core, ctx)
	sections, err := c.PreviewImport(dir, file)
	if err != nil {
		t.Fatal(err)
	}
	var all, weak []string
	for _, section := range sections {
		all = append(all, section.ID)
		if section.Weakens {
			weak = append(weak, section.ID)
		}
	}
	if !reflect.DeepEqual(weak, []string{"weak_kill_switch", "weak_routes"}) {
		t.Fatalf("weakening sections of the preview: %v (all %v)", weak, all)
	}
	// Without the weakening sections protection stays as it was.
	safe := []string{"custom_services", "exclusions", "routing_mode", "kill_switch", "dns", "routes"}
	results, err := c.ApplyImport(ctx, dir, file, safe)
	if err != nil {
		t.Fatal(err)
	}
	for _, result := range results {
		if len(result.Failed) > 0 {
			t.Fatalf("%s failed: %v", result.ID, result.Failed)
		}
	}
	state, err := c.ExportPortable(dir)
	if err != nil {
		t.Fatal(err)
	}
	if state.KillSwitch.Cards["youtube"] == "off" || state.Routes["custom:Банк"].Kind != "auto" {
		t.Fatalf("a weakening change slipped in with the safe sections: %+v %+v", state.KillSwitch, state.Routes)
	}
	if len(state.CustomServices) != 1 || len(state.Exclusions) != 2 || state.Routes["youtube"].Kind != "auto" || state.KillSwitch.Cards["custom:Банк"] != "inherit" {
		t.Fatalf("the safe sections were not applied: %+v", state)
	}
	// With them the router ends up exactly as the file describes.
	if results, err = c.ApplyImport(ctx, dir, file, all); err != nil {
		t.Fatal(err)
	}
	for _, result := range results {
		if len(result.Failed) > 0 {
			t.Fatalf("%s failed: %v", result.ID, result.Failed)
		}
	}
	if state, err = c.ExportPortable(dir); err != nil {
		t.Fatal(err)
	}
	if state.KillSwitch.Cards["youtube"] != "off" || state.KillSwitch.Cards["custom:Банк"] != "inherit" || state.Routes["custom:Банк"].Kind != "direct" || state.Routes["steam"].Kind != "direct" {
		t.Fatalf("after the full import: %+v %+v", state.KillSwitch, state.Routes)
	}
	if left, err := c.PreviewImport(dir, state); err != nil || len(left) != 0 {
		t.Fatalf("an export of this router still plans changes on it: %+v %v", left, err)
	}
	if left, err := c.PreviewImport(dir, file); err != nil || len(left) != 0 {
		t.Fatalf("the imported file still plans changes: %+v %v", left, err)
	}
	if view, err := c.View(ctx); err != nil || !view.Active {
		t.Fatalf("card routes are not active after the import: %v", err)
	}
}
