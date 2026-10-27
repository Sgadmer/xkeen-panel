package components

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func settingPreviewFiles(t *testing.T, root string) map[string]string {
	t.Helper()
	files := map[string]string{}
	if err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		value := info.Mode().String()
		if !entry.IsDir() {
			body, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			value += fmt.Sprintf(":%x", sha256.Sum256(body))
		}
		files[path] = value
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return files
}

func TestComponentsSettingPreviewChangeContractAndReadOnly(t *testing.T) {
	settings := []struct {
		id, variable, onEffect, offEffect string
	}{
		{"autostart", "start_auto", "запускаться автоматически", "запустить вручную"},
		{"dns", "proxy_dns", "начнёт перехватывать обычные DNS-запросы", "перестанет перехватывать обычные DNS-запросы"},
		{"router_proxy", "proxy_router", "поступать в Xray", "прекратит этот перехват"},
		{"ipv6", "ipv6_support", "включит IPv6 на всём роутере", "отключит IPv6 на всём роутере"},
		{"verbose", "extended_msg", "более подробные", "обычному объёму"},
		{"backup", "backup", "будет создавать резервную копию файлов XKeen", "будет отключено"},
	}
	for _, setting := range settings {
		for _, current := range []bool{false, true} {
			for _, desired := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/%t-to-%t", setting.id, current, desired), func(t *testing.T) {
					m, rt := testManager(t)
					value := "off"
					if current {
						value = "on"
					}
					writeTest(t, rt.InitScript, []byte(setting.variable+"="+value+"\n"))
					writeTest(t, m.path("/proc/sys/net/ipv6/conf/all/disable_ipv6"), []byte("0\n"))
					m.opts.Lock = func() { t.Fatal("preview acquired the mutation lock") }
					m.opts.Validate = func(context.Context, string) error { t.Fatal("preview validated live configuration"); return nil }
					m.opts.Restart = func(context.Context) error { t.Fatal("preview restarted the VPN"); return nil }
					before := settingPreviewFiles(t, m.opts.Root)
					plan, err := m.Preview(context.Background(), PlanRequest{Component: "settings", Setting: setting.id, Enabled: &desired})
					if err != nil {
						t.Fatal(err)
					}
					if after := settingPreviewFiles(t, m.opts.Root); !reflect.DeepEqual(before, after) {
						t.Fatal("preview modified files, directories or permissions")
					}
					discovered, _ := m.setting(setting.id)
					if plan.Change == nil || plan.Change.SettingID != setting.id || plan.Change.Name != discovered.Name || plan.Change.Current != current || plan.Change.Desired != desired {
						t.Fatalf("wrong current/desired change payload: %+v", plan.Change)
					}
					wantedEffect := setting.offEffect
					if desired {
						wantedEffect = setting.onEffect
					}
					if !strings.Contains(strings.Join(plan.Change.Effects, " "), wantedEffect) {
						t.Fatalf("effects do not describe requested direction: %+v", plan.Change.Effects)
					}
					if len(plan.Artifacts) != 0 || !strings.Contains(strings.Join(plan.Warnings, " "), "перезапустится") {
						t.Fatal("settings preview lost the restart warning or added a download")
					}
					body, err := json.Marshal(plan)
					if err != nil {
						t.Fatal(err)
					}
					var payload struct {
						Change map[string]json.RawMessage `json:"change"`
					}
					if err := json.Unmarshal(body, &payload); err != nil {
						t.Fatal(err)
					}
					if len(payload.Change) != 5 {
						t.Fatalf("wrong public change fields: %s", body)
					}
					for _, key := range []string{"setting_id", "name", "current", "desired", "effects"} {
						if _, ok := payload.Change[key]; !ok {
							t.Fatalf("missing public field %q", key)
						}
					}
					var decoded SettingChange
					if err := json.Unmarshal(mustJSON(t, payload.Change), &decoded); err != nil || !reflect.DeepEqual(decoded, *plan.Change) {
						t.Fatalf("change did not survive JSON encoding: %+v, %v", decoded, err)
					}
				})
			}
		}
	}
}

func mustJSON(t *testing.T, value any) []byte {
	t.Helper()
	body, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return body
}

func TestComponentsNativeGeodataSchedulePreviewOnlyDisables(t *testing.T) {
	for _, current := range []bool{false, true} {
		t.Run(fmt.Sprintf("enabled-%t", current), func(t *testing.T) {
			m, _ := testManager(t)
			if current {
				writeTest(t, m.path("/opt/var/spool/cron/crontabs/root"), []byte("0 4 * * * /opt/sbin/xkeen -ug\n"))
			}
			before := settingPreviewFiles(t, m.opts.Root)
			setting, found := m.setting("native_geodata_schedule")
			if !found || setting.Enabled != current || setting.Supported != current || !strings.Contains(setting.Hint, "только отключ") {
				t.Fatalf("wrong native schedule discovery: %+v", setting)
			}
			if !current && (!strings.Contains(setting.Hint, "уже отключено") || !strings.Contains(setting.Hint, "недоступен")) {
				t.Fatal("disabled native schedule lacks an explanation")
			}
			enable := true
			if _, err := m.Preview(context.Background(), PlanRequest{Component: "settings", Setting: setting.ID, Enabled: &enable}); err == nil || !strings.Contains(err.Error(), "только отключить") {
				t.Fatalf("native enable preview should be clearly rejected: %v", err)
			}
			disable := false
			plan, err := m.Preview(context.Background(), PlanRequest{Component: "settings", Setting: setting.ID, Enabled: &disable})
			if !current {
				if err == nil {
					t.Fatal("preview accepted a disabled, unsupported native schedule")
				}
			} else {
				if err != nil {
					t.Fatal(err)
				}
				if plan.Change == nil || plan.Change.SettingID != setting.ID || !plan.Change.Current || plan.Change.Desired {
					t.Fatalf("wrong native schedule change: %+v", plan.Change)
				}
				effects := strings.Join(plan.Change.Effects, " ")
				for _, detail := range []string{"расписание", "отключено", "останутся на месте", "через этот переключатель нельзя", "включить отдельно"} {
					if !strings.Contains(effects, detail) {
						t.Errorf("native schedule effect missing %q: %s", detail, effects)
					}
				}
			}
			if after := settingPreviewFiles(t, m.opts.Root); !reflect.DeepEqual(before, after) {
				t.Fatal("native schedule preview changed files")
			}
		})
	}
}

func TestComponentsSettingChangeDescriptionSharedWithPreview(t *testing.T) {
	m, _ := testManager(t)
	setting, _ := m.setting("verbose")
	desired := true
	plan, err := m.Preview(context.Background(), PlanRequest{Component: "settings", Setting: setting.ID, Enabled: &desired})
	if err != nil {
		t.Fatal(err)
	}
	if expected := DescribeSettingChange(setting, desired); plan.Change == nil || !reflect.DeepEqual(*plan.Change, expected) {
		t.Fatal("preview does not use the shared pure change description")
	}
	setting.Enabled = true
	if description := DescribeSettingChange(setting, desired); !description.Current || !description.Desired || !reflect.DeepEqual(description.Effects, plan.Change.Effects) {
		t.Fatal("description ignored the supplied current state or made effects depend on it")
	}
}

func TestComponentsOtherPreviewOmitsSettingChange(t *testing.T) {
	m, _ := testManager(t)
	body := []byte("synthetic-geodata")
	geoServer(t, m, body, digestOf(body))
	if err := m.SetGeodata(GeoSettings{Sources: []string{"geosite-v2fly"}, Day: -1}); err != nil {
		t.Fatal(err)
	}
	plan, err := m.Preview(context.Background(), PlanRequest{Component: "geodata"})
	if err != nil {
		t.Fatal(err)
	}
	if plan.Change != nil || strings.Contains(string(mustJSON(t, plan)), `"change"`) {
		t.Fatal("non-setting plan included a setting change")
	}
}

func TestComponentsSettingsHintsExplainScope(t *testing.T) {
	m, _ := testManager(t)
	for id, details := range map[string][]string{
		"dns":          {"Старый механизм", "не включает шифрование", "зависит"},
		"router_proxy": {"на самом роутере", "передаёт их в Xray", "правила Xray"},
		"ipv6":         {"всего роутера", "домашней сети", "провайдера"},
		"backup":       {"Панель отдельно"},
	} {
		setting, ok := m.setting(id)
		if !ok {
			t.Fatalf("missing setting %s", id)
		}
		for _, detail := range details {
			if !strings.Contains(setting.Hint, detail) {
				t.Errorf("%s hint missing %q: %s", id, detail, setting.Hint)
			}
		}
	}
}
