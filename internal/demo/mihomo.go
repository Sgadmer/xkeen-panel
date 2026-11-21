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
	next["mode"] = "TProxy"
	return next
}

// demoMihomo answers the Mihomo-only requests; ok is false for every other path.
func demoMihomo(path string) (data interface{}, ok bool) {
	now := time.Now().UTC()
	server := object{"kind": "server", "name": "Нидерланды · основной", "country": "NL", "source": "Пример подписки"}
	card := func(id, name, target string, route object, domains ...string) object {
		return object{"id": id, "name": name, "domains": domains, "target": target, "blocked": false, "current_route": route}
	}
	switch path {
	case "/api/service-routes":
		return object{"active": true, "guard_ready": true, "controller_ready": true, "scope": "mihomo", "default_service_target": "pool-all", "service_auto_default": true,
			"targets": []object{{"id": "pool-all", "name": "Все локации", "kind": "pool"}, {"id": "srv-nl", "name": "Нидерланды · основной", "kind": "server", "country": "NL", "sources": []string{"Пример подписки"}},
				{"id": "srv-de", "name": "Германия · резервный", "kind": "server", "country": "DE", "sources": []string{"Пример подписки"}}},
			"services": []object{
				card("claude", "Claude / Anthropic", "srv-nl", server, "domain:claude.ai", "domain:anthropic.com"),
				card("openai", "ChatGPT / OpenAI", "srv-nl", server, "domain:chatgpt.com", "domain:openai.com"),
				card("ai", "Другие AI-сервисы", "srv-nl", server, "domain:gemini.google.com"),
				card("analytics", "Аналитика приложений", "srv-nl", server, "domain:sentry.io"),
				card("youtube", "YouTube", "pool-all", server, "domain:youtube.com"),
				card("telegram", "Telegram", "pool-all", server, "domain:telegram.org"),
				card("discord", "Discord", "pool-all", server, "domain:discord.com"),
				card("github", "GitHub", "pool-all", server, "domain:github.com"),
				card("spotify", "Spotify", "pool-all", server, "domain:spotify.com"),
				card("netflix", "Netflix", "pool-all", server, "domain:netflix.com"),
				card("steam", "Steam", "direct", object{"kind": "direct"}, "domain:steampowered.com"),
				// A card the owner described.
				object{"id": "custom-0a1b2c3d", "name": "Рабочий портал", "custom": true, "domains": []string{"domain:portal.example.com", "full:files.example.net"},
					"networks": []string{"203.0.113.0/24"}, "target": "srv-de", "blocked": false,
					"current_route": object{"kind": "server", "name": "Германия · резервный", "country": "DE", "source": "Пример подписки"}},
			}}, true
	case "/api/custom-services":
		return object{"limit": 30, "services": []object{{"id": "custom-0a1b2c3d", "name": "Рабочий портал", "addresses": []string{"portal.example.com", "full:files.example.net", "203.0.113.0/24"}}}}, true
	case "/api/kill-switch":
		return object{"enabled": true, "services": object{"steam": "inherit"}}, true
	case "/api/service-routes/claude-api-firewall":
		return object{"available": true, "installed": true, "ready": true}, true
	case "/api/routing/blocklist":
		return object{"enabled": false, "mode": "protected", "protected_fallback": true, "source": "Re:filter", "domains": 81234, "prefixes": 12345,
			"updated_at": now.Add(-36 * time.Hour).Format(time.RFC3339)}, true
	case "/api/routing/service-lists":
		return object{"enabled": true, "ready": true, "updating": false, "source": "v2fly/domain-list-community", "sources": 14, "domains": 4821, "voice_prefixes": 36,
			"updated_at": now.Add(-5 * time.Hour).Format(time.RFC3339), "checked_at": now.Add(-5 * time.Hour).Format(time.RFC3339),
			"next_check_at": now.Add(19 * time.Hour).Format(time.RFC3339), "shared_dependencies": ""}, true
	case "/api/components/refilter":
		return object{"supported": true, "auto": true, "busy": false, "checked_at": now.Add(-3 * time.Hour).Format(time.RFC3339), "updated_at": now.Add(-27 * time.Hour).Format(time.RFC3339),
			"version": "21.11.2026", "files_changed_at": now.Add(-27 * time.Hour).Format(time.RFC3339)}, true
	case "/api/components/mihomo":
		return object{"supported": true, "installed": "v1.19.34", "latest": "v1.19.35", "checked_at": now.Add(-2 * time.Hour).Format(time.RFC3339), "staged": false, "busy": false}, true
	case "/api/multipools":
		return object{"pools": []object{}, "scopes": []object{{"id": "pool-all", "name": "Все локации", "kind": "all", "member_count": 2, "limit": 16, "eligible_count": 3},
			{"id": "country-NL", "name": "Нидерланды", "kind": "country", "country": "NL", "member_count": 1}, {"id": "country-DE", "name": "Германия", "kind": "country", "country": "DE", "member_count": 1}}}, true
	case "/api/exclusions":
		return object{"entries": []object{{"id": "demo-bank", "type": "domain", "value": "domain:bank.example.com", "comment": "Банк — напрямую"},
			{"id": "demo-pattern", "type": "pattern", "value": "pattern:*.shop.example.com", "comment": "Магазин и его поддомены"},
			{"id": "demo-network", "type": "ip", "value": "192.0.2.0/24", "comment": "Пример подсети", "disabled": true}}, "covered": object{}}, true
	}
	return nil, false
}
