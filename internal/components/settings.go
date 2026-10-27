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

type SettingChange struct {
	SettingID string   `json:"setting_id"`
	Name      string   `json:"name"`
	Current   bool     `json:"current"`
	Desired   bool     `json:"desired"`
	Effects   []string `json:"effects"`
}

// DescribeSettingChange describes a setting without reading or changing the
// router. Callers must still check support and allowed directions before apply.
func DescribeSettingChange(setting Setting, desired bool) SettingChange {
	change := SettingChange{SettingID: setting.ID, Name: setting.Name, Current: setting.Enabled, Desired: desired, Effects: []string{}}
	switch setting.ID {
	case "autostart":
		if desired {
			change.Effects = []string{"После перезагрузки роутера XKeen будет запускаться автоматически."}
		} else {
			change.Effects = []string{"Автоматический запуск XKeen после перезагрузки роутера будет отключён.", "После перезагрузки XKeen потребуется запустить вручную, когда он понадобится."}
		}
	case "dns":
		if desired {
			change.Effects = []string{"XKeen начнёт перехватывать обычные DNS-запросы и направлять их в Xray своим старым механизмом.", "Шифрование DNS само по себе не включается; оно зависит от настроек Xray, роутера и устройств."}
		} else {
			change.Effects = []string{"XKeen перестанет перехватывать обычные DNS-запросы этим механизмом.", "Дальнейшая обработка DNS-запросов зависит от настроек роутера и устройств."}
		}
	case "router_proxy":
		if desired {
			change.Effects = []string{"Соединения программ на самом роутере, включая Entware, будут перехватываться и поступать в Xray.", "Дальше путь этих соединений определяют правила Xray и настройки маршрутизации роутера."}
		} else {
			change.Effects = []string{"XKeen прекратит этот перехват соединений программ на самом роутере.", "Их маршрут будет зависеть от остальных настроек роутера."}
		}
	case "ipv6":
		if desired {
			change.Effects = []string{"XKeen включит IPv6 на всём роутере. Это затронет и устройства домашней сети.", "Доступ по IPv6 зависит от провайдера и остальных настроек сети."}
		} else {
			change.Effects = []string{"XKeen отключит IPv6 на всём роутере. Это затронет и устройства домашней сети.", "Соединения по IPv6 могут прерваться. Доступ по IPv4 зависит от его наличия и настроек сети."}
		}
	case "verbose":
		if desired {
			change.Effects = []string{"При запуске XKeen будет выводить более подробные служебные сообщения."}
		} else {
			change.Effects = []string{"При запуске XKeen вернётся к обычному объёму служебных сообщений."}
		}
	case "backup":
		if desired {
			change.Effects = []string{"При обновлении XKeen будет создавать резервную копию файлов XKeen.", "Панель также продолжит создавать свои резервные копии перед изменениями."}
		} else {
			change.Effects = []string{"Штатное создание копии файлов XKeen при его обновлении будет отключено.", "Панель продолжит создавать свои резервные копии перед изменениями."}
		}
	case "native_geodata_schedule":
		if !desired {
			change.Effects = []string{"Штатное расписание обновления геобаз XKeen будет отключено.", "Установленные геобазы останутся на месте.", "Вернуть это штатное расписание через этот переключатель нельзя. Расписание геобаз панели можно включить отдельно."}
		}
	}
	return change
}

func (m *Manager) Settings() []Setting {
	result := []Setting{
		{ID: "autostart", Name: "Запускать XKeen вместе с роутером", Hint: "После перезагрузки роутера запускает XKeen без ручного нажатия кнопки запуска.", flag: "-auto", variable: "start_auto"},
		{ID: "dns", Name: "Направлять DNS через Xray", Hint: "Старый механизм XKeen для перехвата обычных DNS-запросов. Сам по себе не включает шифрование DNS; обработка зависит от настроек Xray, роутера и устройств.", flag: "-dns", variable: "proxy_dns"},
		{ID: "router_proxy", Name: "Направлять соединения программ роутера в Xray", Hint: "Перехватывает соединения программ на самом роутере, включая Entware, и передаёт их в Xray. Дальше действуют правила Xray и маршрутизации роутера.", flag: "-pr", variable: "proxy_router"},
		{ID: "ipv6", Name: "Поддержка IPv6", Hint: "Включает или отключает IPv6 для всего роутера и домашней сети. Соединения по IPv6 могут прерваться; доступность IPv6 зависит от провайдера.", flag: "-ipv6", variable: "ipv6_support"},
		{ID: "verbose", Name: "Подробные сообщения запуска", Hint: "Показывает больше служебных сообщений при запуске XKeen. Полезно при поиске причины ошибки запуска.", flag: "-extmsg", variable: "extended_msg"},
		{ID: "backup", Name: "Резервная копия при обновлении XKeen", Hint: "Включает копию файлов XKeen при его обновлении. Панель отдельно сохраняет копию перед своими изменениями.", flag: "-cbk", variable: "backup"},
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
		enabled := m.externalGeoSchedule()
		hint := "Здесь можно только отключить штатное расписание XKeen. Сделайте это перед включением расписания панели, чтобы два обновления не записывали одни файлы одновременно."
		if !enabled {
			hint = "Штатное расписание XKeen уже отключено, поэтому переключатель недоступен. Здесь доступно только отключение; для автообновления используйте расписание геобаз панели."
		}
		result = append(result, Setting{ID: "native_geodata_schedule", Name: "Штатное расписание геобаз XKeen", Hint: hint, Enabled: enabled, Supported: enabled, flag: "-dgc"})
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
