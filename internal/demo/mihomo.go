package demo

import "time"

// XKEEN_DEMO_CORE=mihomo shows the pages that exist only with the Mihomo core:
// service cards, the kill switch, protected routing and the address lists.
const mihomoCoreEnv = "XKEEN_DEMO_CORE"

func demoMihomoStatus(status object) object {
	next := object{}
	for key, value := range status {
		next[key] = value
	}
	next["core"] = "mihomo"
	next["mode"] = "Hybrid"
	next["current_server"] = "Стокгольм"
	next["latency_ms"] = 41
	return next
}

// Two made-up subscriptions with servers in several countries.
var demoMihomoServers = []struct {
	name, country, source string
	latency               int
}{
	{"Стокгольм", "SE", "Северный ветер", 41}, {"Хельсинки", "FI", "Северный ветер", 47}, {"Амстердам", "NL", "Северный ветер", 52},
	{"Франкфурт", "DE", "Северный ветер", 58}, {"Нью-Йорк", "US", "Северный ветер", 118}, {"Амстердам 2", "NL", "Южный мост", 55},
	{"Берлин", "DE", "Южный мост", 63}, {"Варшава", "PL", "Южный мост", 71}, {"Лондон", "GB", "Южный мост", 79}, {"Токио", "JP", "Южный мост", -1},
}

func demoServerRows() []object {
	rows := []object{}
	for i, server := range demoMihomoServers {
		row := object{"id": i, "name": server.name, "address": "server.example.com", "port": 443, "protocol": "vless", "active": i == 0, "latency_ms": server.latency,
			"country": server.country, "probe_kind": "https", "source_name": server.source, "target_id": "srv-" + server.country + "-" + string(rune('a'+i))}
		if i < 8 {
			row["pool_tag"] = "pool-" + string(rune('a'+i))
		}
		rows = append(rows, row)
	}
	return rows
}

func demoDeviceRows() []object {
	rows := []object{}
	add := func(name string, active, vpn bool) {
		n := len(rows) + 1
		rows = append(rows, object{"mac": "02:00:00:00:00:" + string("0123456789abcdef"[n/16]) + string("0123456789abcdef"[n%16]), "name": name,
			"ip": "192.0.2." + string(rune('0'+n/10)) + string(rune('0'+n%10)), "active": active, "registered": true, "vpn": vpn})
	}
	add("Мой компьютер", true, true)
	add("iPhone", true, true)
	add("Ноутбук", true, true)
	add("Телевизор", true, false)
	for _, name := range []string{"Планшет", "Умная колонка", "Приставка", "Рабочий ноутбук", "Часы", "Старый телефон", "Гостевой телефон"} {
		add(name, false, name != "Приставка" && name != "Умная колонка")
	}
	return rows
}

// demoMihomo answers the Mihomo-only requests; ok is false for every other path.
func demoMihomo(path string) (data interface{}, ok bool) {
	now := time.Now().UTC()
	server := object{"kind": "server", "name": "Амстердам", "country": "NL", "source": "Северный ветер"}
	card := func(id, name, target string, route object, domains ...string) object {
		return object{"id": id, "name": name, "domains": domains, "target": target, "blocked": false, "current_route": route}
	}
	switch path {
	case "/api/servers":
		return object{"servers": demoServerRows()}, true
	case "/api/sources":
		return object{"sources": []object{
			{"id": "north", "name": "Северный ветер", "kind": "subscription", "host": "north.example.com", "server_count": 5},
			{"id": "south", "name": "Южный мост", "kind": "subscription", "host": "south.example.com", "server_count": 5}}}, true
	case "/api/subscription":
		return object{"configured": true, "host": "north.example.com", "source_kind": "subscription", "can_refresh": true, "last_updated": now.Add(-12 * time.Minute).Format(time.RFC3339),
			"server_count": len(demoMihomoServers), "import_report": object{"imported": len(demoMihomoServers), "skipped_composite": 0, "skipped_unsupported": 0}}, true
	case "/api/pool":
		nodes := []object{}
		tags := []string{}
		for i, row := range demoServerRows()[:8] {
			tag := "pool-" + string(rune('a'+i))
			tags = append(tags, tag)
			nodes = append(nodes, object{"tag": tag, "server_id": i, "name": row["name"], "address": "server.example.com", "port": 443, "country": row["country"], "latency_ms": row["latency_ms"]})
		}
		return object{"mode": "pool", "core": "mihomo", "api_available": true, "selection_kind": "auto", "selection_name": "Все локации", "auto_scope_id": "pool-all",
			"current_tag": "pool-a", "current_name": "Стокгольм", "source_name": "Северный ветер", "pool_tags": tags, "proxy_tags": tags, "nodes": nodes}, true
	case "/api/devices":
		return object{"policy_found": true, "policy": object{"name": "xkeen", "description": "Устройства VPN"}, "new_devices_vpn": true, "devices": demoDeviceRows()}, true
	case "/api/service-routes":
		return object{"active": true, "guard_ready": true, "controller_ready": true, "scope": "mihomo", "default_service_target": "pool-all", "service_auto_default": true,
			"targets": []object{{"id": "pool-all", "name": "Все локации", "kind": "pool"}, {"id": "srv-nl", "name": "Амстердам", "kind": "server", "country": "NL", "sources": []string{"Северный ветер"}},
				{"id": "srv-de", "name": "Франкфурт", "kind": "server", "country": "DE", "sources": []string{"Северный ветер"}}, {"id": "srv-us", "name": "Нью-Йорк", "kind": "server", "country": "US", "sources": []string{"Северный ветер"}}},
			"services": []object{
				card("claude", "Claude / Anthropic", "srv-nl", server, "domain:claude.ai", "domain:anthropic.com"),
				card("openai", "ChatGPT / OpenAI", "srv-nl", server, "domain:chatgpt.com", "domain:openai.com"),
				card("ai", "AI", "srv-nl", server, "domain:perplexity.ai", "domain:gemini.google.com"),
				card("analytics", "Аналитика и диагностика", "srv-nl", server, "full:api3.siftscience.com"),
				card("youtube", "YouTube", "pool-all", server, "domain:youtube.com"),
				card("telegram", "Telegram", "pool-all", server, "domain:telegram.org"),
				card("discord", "Discord", "pool-all", server, "domain:discord.com"),
				card("github", "GitHub", "pool-all", server, "domain:github.com"),
				card("spotify", "Spotify", "pool-all", server, "domain:spotify.com"),
				card("netflix", "Netflix", "pool-all", server, "domain:netflix.com"),
				card("twitch", "Twitch", "pool-all", server, "domain:twitch.tv"),
				card("steam", "Steam", "direct", object{"kind": "direct"}, "domain:steampowered.com"),
				// A card the owner described.
				object{"id": "custom-0a1b2c3d", "name": "Рабочий портал", "custom": true, "domains": []string{"domain:portal.example.com", "full:files.example.net"},
					"networks": []string{"203.0.113.0/24"}, "target": "srv-de", "blocked": false,
					"current_route": object{"kind": "server", "name": "Франкфурт", "country": "DE", "source": "Северный ветер"}},
			}}, true
	case "/api/custom-services":
		return object{"limit": 30, "services": []object{{"id": "custom-0a1b2c3d", "name": "Рабочий портал", "addresses": []string{"portal.example.com", "full:files.example.net", "203.0.113.0/24"}}}}, true
	case "/api/kill-switch":
		// One card departs from the recommended setting, to show how that looks.
		return object{"enabled": true, "services": object{"steam": "inherit", "twitch": "off"}}, true
	case "/api/service-routes/claude-api-firewall":
		return object{"available": true, "installed": true, "ready": true}, true
	case "/api/routing/blocklist":
		return object{"enabled": false, "mode": "protected", "protected_fallback": true, "source": "Re:filter", "domains": 81234, "prefixes": 12345,
			"updated_at": now.Add(-36 * time.Hour).Format(time.RFC3339)}, true
	case "/api/routing/service-lists":
		return object{"enabled": true, "ready": true, "updating": false, "source": "v2fly/domain-list-community", "sources": 14, "domains": 4821, "voice_prefixes": 36,
			"updated_at": now.Add(-5 * time.Hour).Format(time.RFC3339), "checked_at": now.Add(-5 * time.Hour).Format(time.RFC3339),
			"next_check_at": now.Add(19 * time.Hour).Format(time.RFC3339), "shared_dependencies": ""}, true
	case "/api/components":
		return object{"supported": false, "settings_supported": true, "reason": "нужен установленный XKeen с активным Xray", "architecture": "arm64", "xkeen_version": "2.1 Stable",
			"mode": "Hybrid", "core": "mihomo", "router_time": now.Format(time.RFC3339), "geodata": object{"sources": []string{}, "auto": false, "day": -1, "hour": 4, "minute": 0},
			"sources": []object{}, "backups": []object{}, "notes": []string{}, "settings": demoSettings()}, true
	case "/api/dns":
		return object{"mode": "router", "foreign": false, "presets": []object{
			{"id": "cloudflare", "name": "Cloudflare", "servers": []string{"https://1.1.1.1/dns-query", "https://1.0.0.1/dns-query"}},
			{"id": "google", "name": "Google", "servers": []string{"https://8.8.8.8/dns-query", "https://8.8.4.4/dns-query"}},
			{"id": "quad9", "name": "Quad9", "servers": []string{"https://9.9.9.9/dns-query", "https://149.112.112.112/dns-query"}},
			{"id": "adguard", "name": "AdGuard", "servers": []string{"https://94.140.14.14/dns-query", "https://94.140.15.15/dns-query"}}}}, true
	case "/api/components/refilter":
		return object{"supported": true, "auto": true, "busy": false, "checked_at": now.Add(-3 * time.Hour).Format(time.RFC3339), "updated_at": now.Add(-27 * time.Hour).Format(time.RFC3339),
			"version": "21.11.2026", "files_changed_at": now.Add(-27 * time.Hour).Format(time.RFC3339)}, true
	case "/api/components/mihomo":
		return object{"supported": true, "installed": "v1.19.34", "latest": "v1.19.35", "checked_at": now.Add(-2 * time.Hour).Format(time.RFC3339), "staged": false, "busy": false}, true
	case "/api/multipools":
		return object{"pools": []object{{"id": "pool-video", "name": "Видео", "source_ids": []string{"north"}, "countries": []string{"NL", "SE"}, "member_count": 2}},
			"scopes": []object{{"id": "pool-all", "name": "Все локации", "kind": "all", "member_count": 8, "limit": 8, "eligible_count": 9},
				{"id": "country-SE", "name": "Швеция", "kind": "country", "country": "SE", "member_count": 1}, {"id": "country-NL", "name": "Нидерланды", "kind": "country", "country": "NL", "member_count": 2},
				{"id": "country-DE", "name": "Германия", "kind": "country", "country": "DE", "member_count": 2}, {"id": "pool-video", "name": "Видео", "kind": "custom", "member_count": 2}}}, true
	case "/api/account":
		return object{"username": "admin", "recovery_codes_left": 8, "passkeys": 0, "remember": true}, true
	case "/api/kill-switch/events":
		return object{"events": []object{}}, true
	case "/api/exclusions":
		return object{"entries": []object{{"id": "demo-bank", "type": "domain", "value": "domain:bank.example.com", "comment": "Банк — напрямую"},
			{"id": "demo-pattern", "type": "pattern", "value": "pattern:*.shop.example.com", "comment": "Магазин и его поддомены"},
			{"id": "demo-network", "type": "ip", "value": "192.0.2.0/24", "comment": "Пример подсети", "disabled": true}}, "covered": object{}}, true
	}
	return nil, false
}
