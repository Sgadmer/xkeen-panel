package demo

import (
	"strings"
	"time"
)

var demoServices = []object{{"id": "claude", "name": "Claude / Anthropic"}, {"id": "youtube", "name": "YouTube"}, {"id": "telegram", "name": "Telegram"}, {"id": "google", "name": "Google"}}

func demoJournalSettings() object {
	return object{"supported": true, "enabled": false, "running": false, "path": "", "storage_id": "", "storage_available": false, "retention_hours": 24,
		"max_events": 200000, "max_device_events": 50000, "max_bytes": 256 << 20, "events": 0, "bytes": 0, "dropped": 0, "queued": 0, "storages": []object{},
		"recent_enabled": true, "recent_events": 5000, "recent_count": 6, "recent_minutes": 60}
}

// A few records of two devices: through the VPN, direct, and one blocked.
func demoJournal(device, service, kind, search string) []object {
	now := time.Now().UTC()
	at := func(seconds int) string { return now.Add(-time.Duration(seconds) * time.Second).Format(time.RFC3339) }
	vpn := object{"kind": "server", "name": "Нидерланды · основной", "country": "NL", "source": "Пример подписки"}
	pc, phone := object{"id": "mac:02:00:00:00:00:01", "ip": "192.0.2.10", "name": "Мой компьютер"}, object{"id": "mac:02:00:00:00:00:02", "ip": "192.0.2.11", "name": "iPhone"}
	row := func(id string, owner object, ago int, host, serviceID, recordKind string, exit object, route ...string) object {
		return object{"id": id, "at": at(ago), "kind": recordKind, "device_id": owner["id"], "device": owner["ip"], "device_name": owner["name"],
			"service_id": serviceID, "host": host, "port": "443", "network": "TCP", "route": route, "exit": exit, "count": 1}
	}
	all := []object{
		row("d1", pc, 4, "claude.ai", "claude", "connection", vpn, "Claude / Anthropic"),
		row("d2", pc, 9, "api.anthropic.com", "claude", "connection", vpn, "Claude / Anthropic"),
		row("d3", phone, 15, "www.youtube.com", "youtube", "connection", vpn, "YouTube"),
		row("d4", pc, 31, "bank.example.com", "", "connection", object{"kind": "direct"}, "Напрямую"),
		row("d5", phone, 48, "api.telegram.org", "telegram", "kill_switch", object{"kind": "reject"}),
		row("d6", pc, 70, "fonts.gstatic.com", "google", "connection", vpn, "Google"),
	}
	result := []object{}
	for _, entry := range all {
		if device != "" && entry["device_id"] != device || service != "" && entry["service_id"] != service || kind != "" && entry["kind"] != kind {
			continue
		}
		if search != "" && !strings.Contains(entry["host"].(string), strings.ToLower(search)) {
			continue
		}
		result = append(result, entry)
	}
	return result
}

func demoSites() []object {
	now := time.Now().UTC().Format(time.RFC3339)
	return []object{
		{"host": "claude.ai", "service_id": "claude", "count": 42, "vpn": 42, "direct": 0, "blocked": 0, "errors": 0, "last_at": now, "exit": "Нидерланды · основной", "devices": 1},
		{"host": "www.youtube.com", "service_id": "youtube", "count": 17, "vpn": 17, "direct": 0, "blocked": 0, "errors": 0, "last_at": now, "exit": "Нидерланды · основной", "devices": 2},
		{"host": "bank.example.com", "count": 6, "vpn": 0, "direct": 6, "blocked": 0, "errors": 0, "last_at": now, "devices": 1},
		{"host": "api.telegram.org", "service_id": "telegram", "count": 3, "vpn": 0, "direct": 0, "blocked": 3, "errors": 0, "last_at": now, "devices": 1},
	}
}

func demoDiagnostics() object {
	now := time.Now()
	history := []object{}
	for i := 60; i >= 0; i-- {
		history = append(history, object{"at": now.Add(-time.Duration(i*5) * time.Second).UTC().Format(time.RFC3339), "cpu_percent": 6 + float64(i%7), "cores": 4, "temperature_c": 54.5, "ram_total_kib": 1 << 20, "ram_used_kib": 520 << 10, "load": []float64{0.1, 0.1, 0.05}})
	}
	flow := func(id, device, host, service string, exit object, route ...string) object {
		return object{"id": id, "device": device, "host": host, "port": "443", "network": "TCP", "service_id": service, "route": route, "exit": exit, "start": now.Add(-20 * time.Second).UTC().Format(time.RFC3339)}
	}
	vpn := object{"kind": "server", "name": "Нидерланды · основной", "country": "NL", "source": "Пример подписки"}
	return object{"system": history[len(history)-1], "history": history, "services": demoServices,
		"connections": []object{flow("c1", "192.0.2.10", "claude.ai", "claude", vpn, "Claude / Anthropic"), flow("c2", "192.0.2.11", "www.youtube.com", "youtube", vpn, "YouTube"), flow("c3", "192.0.2.10", "bank.example.com", "", object{"kind": "direct"}, "Напрямую")},
		"guard":       object{"running": true, "complete": true, "events": []object{}}}
}
