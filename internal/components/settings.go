package components

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

type Setting struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Hint      string `json:"hint"`
	Enabled   bool   `json:"enabled"`
	Supported bool   `json:"supported"`
	flag      string
	variable  string
}

func (m *Manager) Settings() []Setting {
	result := []Setting{
		{ID: "autostart", Name: "Запускать XKeen вместе с роутером", Hint: "Сохраняет автозапуск после перезагрузки.", flag: "-auto", variable: "start_auto"},
		{ID: "dns", Name: "Направлять DNS через Xray", Hint: "Использует настроенный DNS-маршрут ядра.", flag: "-dns", variable: "proxy_dns"},
		{ID: "router_proxy", Name: "VPN для программ Entware", Hint: "Для реальных outbound нужны корректные sockopt.mark; пользовательские WAN/PBR-политики проверяются отдельно.", flag: "-pr", variable: "proxy_router"},
		{ID: "ipv6", Name: "Поддержка IPv6", Hint: "Меняет IPv6 для всего роутера. Возможна краткая потеря соединений.", flag: "-ipv6", variable: "ipv6_support"},
		{ID: "verbose", Name: "Подробные сообщения запуска", Hint: "Расширенные сообщения XKeen при запуске.", flag: "-extmsg", variable: "extended_msg"},
		{ID: "backup", Name: "Резервная копия при обновлении XKeen", Hint: "Дополняет резервные копии, которые создаёт панель.", flag: "-cbk", variable: "backup"},
	}
	rt := m.runtime()
	dispatcher, _ := os.ReadFile(rt.Dispatcher)
	init, _ := os.ReadFile(rt.InitScript)
	for i := range result {
		s := &result[i]
		flag := regexp.QuoteMeta(s.flag)
		s.Supported = regexp.MustCompile(`(?m)^\s*` + flag + `(?:\|[^)]*)?\)`).Match(dispatcher)
		match := regexp.MustCompile(`(?m)^` + regexp.QuoteMeta(s.variable) + `=["']?(on|off|true|false|yes|no)["']?\s*$`).FindSubmatch(init)
		if len(match) == 2 {
			s.Enabled = string(match[1]) == "on" || string(match[1]) == "true" || string(match[1]) == "yes"
		} else {
			s.Supported = false
		}
		if s.ID == "ipv6" {
			if _, e := os.Stat(m.path("/proc/sys/net/ipv6/conf")); e != nil {
				s.Supported = false
			}
		}
	}
	if regexp.MustCompile(`(?m)^\s*-dgc\)`).Match(dispatcher) {
		result = append(result, Setting{ID: "native_geodata_schedule", Name: "Штатное расписание геобаз XKeen", Hint: "Отключите перед включением расписания панели, чтобы два обновления не записывали одни файлы одновременно.", Enabled: m.externalGeoSchedule(), Supported: m.externalGeoSchedule(), flag: "-dgc"})
	}
	return result
}

func (m *Manager) externalGeoSchedule() bool {
	b, e := os.ReadFile(m.path("/opt/var/spool/cron/crontabs/root"))
	if e != nil {
		return false
	}
	for _, line := range strings.Split(string(b), "\n") {
		s := strings.TrimSpace(line)
		if !strings.HasPrefix(s, "#") && (strings.Contains(s, "xkeen -ug") || strings.Contains(s, "xkeen -gips")) {
			return true
		}
	}
	return false
}

func (m *Manager) setting(id string) (Setting, bool) {
	for _, s := range m.Settings() {
		if s.ID == id {
			return s, true
		}
	}
	return Setting{}, false
}

// The upstream IPv6 control changes live sysctl values in addition to its init
// setting. Preserve these values so rollback also restores the running router.
func (m *Manager) kernelIPv6() map[string]string {
	result := map[string]string{}
	files, _ := filepath.Glob(filepath.Join(m.path("/proc/sys/net/ipv6/conf"), "*", "disable_ipv6"))
	for _, path := range files {
		b, e := os.ReadFile(path)
		if e == nil && (strings.TrimSpace(string(b)) == "0" || strings.TrimSpace(string(b)) == "1") {
			result[path] = strings.TrimSpace(string(b))
		}
	}
	return result
}

func (m *Manager) restoreKernelIPv6(values map[string]string) error {
	root := m.path("/proc/sys/net/ipv6/conf")
	for path, value := range values {
		if value != "0" && value != "1" {
			return os.ErrInvalid
		}
		relative, e := filepath.Rel(root, path)
		if e != nil || strings.HasPrefix(relative, "..") || filepath.Base(path) != "disable_ipv6" || len(strings.Split(filepath.ToSlash(relative), "/")) != 2 {
			return os.ErrInvalid
		}
		if e = os.WriteFile(path, []byte(value), 0600); e != nil {
			return e
		}
	}
	return nil
}
