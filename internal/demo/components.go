package demo

import (
	"encoding/json"
	"net/http"
	"time"

	"xkeen-panel/internal/components"
)

// These fixtures contain no router state. Previewing never applies a change.
func demoSettings() []components.Setting {
	return []components.Setting{
		{ID: "autostart", Name: "Запускать XKeen вместе с роутером", Hint: "После перезагрузки роутера запускает XKeen без ручного нажатия кнопки запуска.", Enabled: true, Supported: true},
		{ID: "dns", Name: "Направлять DNS через Xray", Hint: "Старый механизм XKeen для перехвата обычных DNS-запросов. Сам по себе не включает шифрование DNS; обработка зависит от настроек Xray, роутера и устройств.", Enabled: true, Supported: true},
		{ID: "router_proxy", Name: "Направлять соединения программ роутера в Xray", Hint: "Перехватывает соединения программ на самом роутере, включая Entware, и передаёт их в Xray. Дальше действуют правила Xray и маршрутизации роутера.", Enabled: false, Supported: true},
		{ID: "ipv6", Name: "Поддержка IPv6", Hint: "Включает или отключает IPv6 для всего роутера и домашней сети. Соединения по IPv6 могут прерваться; доступность IPv6 зависит от провайдера.", Enabled: true, Supported: true},
		{ID: "verbose", Name: "Подробные сообщения запуска", Hint: "Показывает больше служебных сообщений при запуске XKeen. Полезно при поиске причины ошибки запуска.", Enabled: false, Supported: true},
		{ID: "backup", Name: "Резервная копия при обновлении XKeen", Hint: "Включает копию файлов XKeen при его обновлении. Панель отдельно сохраняет копию перед своими изменениями.", Enabled: true, Supported: true},
		{ID: "native_geodata_schedule", Name: "Штатное расписание геобаз XKeen", Hint: "Здесь можно только отключить штатное расписание XKeen. Сделайте это перед включением расписания панели, чтобы два обновления не записывали одни файлы одновременно.", Enabled: true, Supported: true},
	}
}

func demoSettingsPreview(w http.ResponseWriter, r *http.Request) {
	var req components.PlanRequest
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&req) != nil || req.Component != "settings" || req.Enabled == nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(object{"error": "Выберите параметр демонстрационной установки"})
		return
	}
	for _, setting := range demoSettings() {
		if req.Setting != setting.ID {
			continue
		}
		if setting.ID == "native_geodata_schedule" && *req.Enabled {
			break
		}
		change := components.DescribeSettingChange(setting, *req.Enabled)
		json.NewEncoder(w).Encode(object{
			"id": "synthetic-preview-" + setting.ID, "component": "settings", "version": setting.Name,
			"expires": time.Now().Add(10 * time.Minute), "artifacts": []object{}, "change": change,
			"required_bytes": 140 << 20,
			"warnings":       []string{"При применении панель кратко перезапустит работающий VPN и восстановит выбранный сервер и правила."},
		})
		return
	}
	w.WriteHeader(http.StatusBadRequest)
	json.NewEncoder(w).Encode(object{"error": "Этот параметр недоступен в демонстрации"})
}
