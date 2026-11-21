package components

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"

	"xkeen-panel/internal/xkeen"
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
	mihomo := rt.Core == xkeen.CoreMihomo
	if mihomo {
		shared := result[:0]
		for _, s := range result {
			if m.settingPath(s.ID) == "" {
				continue
			}
			switch s.ID {
			case "ipv6":
				s.Name = "Разрешать IPv6 после перезагрузки роутера"
				s.Hint = "Разрешает устройствам дома выходить в интернет по IPv6, если его поддерживает провайдер. Если выключить, после перезагрузки роутера XKeen при запуске отключит IPv6 для всей домашней сети."
			case "autostart":
				s.Hint = "При включении роутера XKeen сам запустит VPN. Если выключить, после перезагрузки VPN нужно будет запустить вручную."
			case "verbose":
				s.Hint = "При запуске XKeen запишет больше подробностей в журнал. По ним легче понять, почему VPN не запустился."
			case "backup":
				s.Hint = "При обновлении XKeen сохранит копию своих файлов. Она пригодится, если потребуется вернуть прежнюю версию."
			}
			shared = append(shared, s)
		}
		result = shared
	}
	for i := range result {
		s := &result[i]
		flag := regexp.QuoteMeta(s.flag)
		s.Supported = regexp.MustCompile(`(?m)^\s*` + flag + `(?:\|[^)]*)?\)`).Match(dispatcher)
		field := settingValue(init, s.variable)
		if field != nil {
			v := string(init[field[0]:field[1]])
			s.Enabled = v == "on" || v == "true" || v == "yes"
		} else {
			s.Supported = false
		}
		if s.ID == "ipv6" {
			if _, e := os.Stat(m.path("/proc/sys/net/ipv6/conf")); e != nil {
				s.Supported = false
			}
		}
		if mihomo && runtime.GOOS == "linux" && s.ID == "autostart" {
			if info, err := os.Stat(rt.InitScript); err != nil || info.Mode().Perm()&0100 == 0 {
				s.Supported = false
				s.Hint = "Сценарий запуска XKeen нельзя выполнить. Сначала восстановите права на его запуск."
			}
		}
	}
	if regexp.MustCompile(`(?m)^\s*-dgc\)`).Match(dispatcher) {
		enabled := m.externalGeoSchedule()
		if mihomo {
			content, _ := os.ReadFile(m.settingPath("native_geodata_schedule"))
			enabled = false
			for line := range strings.Lines(string(content)) {
				if nativeGeoJob(line) {
					enabled = true
					break
				}
			}
		}
		hint := "Здесь можно только отключить штатное расписание XKeen. Сделайте это перед включением расписания панели, чтобы два обновления не записывали одни файлы одновременно."
		if !enabled {
			hint = "Штатное расписание XKeen уже отключено, поэтому переключатель недоступен. Здесь доступно только отключение; для автообновления используйте расписание геобаз панели."
		}
		if mihomo {
			hint = "По этому расписанию XKeen сам скачивает свои базы. Список блокировок Re:filter панель обновляет и без него — см. блок выше. Здесь расписание можно только отключить."
			if !enabled {
				hint = "Штатное расписание выключено. Список блокировок Re:filter обновляет панель, если в блоке выше включено «Обновлять раз в сутки»."
			}
		}
		result = append(result, Setting{ID: "native_geodata_schedule", Name: "Штатное расписание геобаз XKeen", Hint: hint, Enabled: enabled, Supported: enabled, flag: "-dgc"})
	}
	return result
}

// Return the byte range of a single literal assignment. Leave comments,
// quoting, line endings and every other byte of the installed init intact.
func settingValue(body []byte, variable string) []int {
	re := regexp.MustCompile(`(?m)^` + regexp.QuoteMeta(variable) + `=(["']?)(on|off|true|false|yes|no)(["']?)[ \t]*\r?$`)
	rows := re.FindAllSubmatchIndex(body, 2)
	if len(rows) != 1 {
		return nil
	}
	row := rows[0]
	if !bytes.Equal(body[row[2]:row[3]], body[row[6]:row[7]]) {
		return nil
	}
	return row[4:6]
}

func (m *Manager) settingPath(id string) string {
	switch id {
	case "autostart", "verbose", "backup", "ipv6":
		return m.runtime().InitScript
	case "native_geodata_schedule":
		return m.path("/opt/var/spool/cron/crontabs/root")
	}
	return ""
}

// Only an actual, standalone XKeen geodata command is a managed schedule.
// A shell pipeline, a logger message or another updater must survive editing.
func nativeGeoJob(line string) bool {
	line = strings.TrimSpace(line)
	if line == "" || strings.HasPrefix(line, "#") {
		return false
	}
	f := strings.Fields(line)
	return len(f) == 7 && (f[5] == "xkeen" || f[5] == "/opt/sbin/xkeen") && (f[6] == "-ug" || f[6] == "-gips")
}

func (m *Manager) writeStartupSetting(setting Setting, enabled bool) error {
	path := m.settingPath(setting.ID)
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() {
		return fmt.Errorf("файл параметра XKeen недоступен")
	}
	body, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var next []byte
	if setting.ID == "native_geodata_schedule" {
		if enabled {
			return fmt.Errorf("доступно только отключение расписания")
		}
		for line := range strings.SplitAfterSeq(string(body), "\n") {
			if !nativeGeoJob(line) {
				next = append(next, line...)
			}
		}
	} else {
		field := settingValue(body, setting.variable)
		if field == nil {
			return fmt.Errorf("не удалось определить параметр XKeen")
		}
		value := "off"
		if enabled {
			value = "on"
		}
		next = append(next, body[:field[0]]...)
		next = append(next, value...)
		next = append(next, body[field[1]:]...)
	}
	if bytes.Equal(body, next) {
		return nil
	}
	return writeSettingFile(setting.ID, path, next, info.Mode().Perm())
}

func writeSettingFile(id, path string, body []byte, mode os.FileMode) error {
	if err := atomicWrite(path, body, mode); err != nil {
		return err
	}
	if id != "native_geodata_schedule" {
		return nil
	}
	// BusyBox crond consumes this queue when individual crontabs change.
	// Append to preserve other users' queued notifications.
	f, err := os.OpenFile(filepath.Join(filepath.Dir(path), "cron.update"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	_, err = f.WriteString("root\n")
	closeErr := f.Close()
	if err != nil {
		return err
	}
	return closeErr
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
