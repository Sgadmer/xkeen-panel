package keenetic

import (
	"context"
	"encoding/json"
	"errors"
	"maps"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
)

func TestNativeDeviceRegistration(t *testing.T) {
	const mac = "02:00:00:00:00:0a"
	const other = "02:00:00:00:00:0b"
	const name = "Телефон • 🏠"
	for _, tc := range []struct {
		label, old, rename, refuse string
		seen, wantError            bool
		want                       []string
	}{
		{label: "rename online or offline", old: "Old", rename: name, want: []string{"rename", "save"}},
		{label: "register and inherit segment", seen: true, rename: name, want: []string{"rename", "conform", "save"}},
		{label: "forget online device", old: "Old", seen: true, want: []string{"forget", "save"}},
		{label: "repeat forget", seen: true, want: []string{"save"}},
		{label: "retry after unsaved rename", old: name, rename: name, want: []string{"save"}},
		{label: "unknown MAC", rename: name, wantError: true},
		{label: "duplicate name", old: "Old", rename: "Other", wantError: true},
		{label: "ndm rejected rename", old: "Old", rename: name, refuse: "rename", wantError: true, want: []string{"rename"}},
		{label: "accepted without effect", old: "Old", rename: name, refuse: "noop", wantError: true, want: []string{"rename"}},
		{label: "preserve inherited route on failure", seen: true, rename: name, refuse: "conform", wantError: true, want: []string{"rename", "conform", "forget"}},
		{label: "preserve inherited route on silent no-op", seen: true, rename: name, refuse: "noop-conform", wantError: true, want: []string{"rename", "conform", "forget"}},
		{label: "save refused", old: "Old", rename: name, refuse: "save", wantError: true, want: []string{"rename", "save"}},
	} {
		t.Run(tc.label, func(t *testing.T) {
			type entry struct {
				MAC string `json:"mac"`
			}
			running := map[string]entry{"Other": {other}}
			if tc.old != "" {
				running[tc.old] = entry{mac}
			}
			saved := map[string]entry{}
			var commands []string
			reads := 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				path := strings.TrimPrefix(r.URL.Path, "/rci/")
				if r.Method == "GET" {
					switch path {
					case "show/rc/ip/hotspot":
						json.NewEncoder(w).Encode(map[string]any{"host": []map[string]any{{"mac": mac, "conform": tc.refuse != "noop-conform"}}})
					case "show/ip/hotspot":
						hosts := []Host{}
						if tc.seen {
							hosts = append(hosts, Host{MAC: mac, Active: true})
						}
						json.NewEncoder(w).Encode(map[string]any{"host": hosts})
					case "show/rc/known/host":
						json.NewEncoder(w).Encode(running)
					case "show/sc/known/host":
						// Permit the native asynchronous save to lag behind running config.
						if reads > 0 {
							saved = maps.Clone(running)
						}
						reads++
						json.NewEncoder(w).Encode(saved)
					default:
						http.NotFound(w, r)
					}
					return
				}
				var args map[string]any
				if err := json.NewDecoder(r.Body).Decode(&args); err != nil {
					t.Error(err)
				}
				action := ""
				switch {
				case path == "known/host" && args["mac"] == mac && args["no"] == true && len(args) == 2:
					action = "forget"
				case path == "known/host" && args["mac"] == mac && args["name"] == tc.rename && len(args) == 2:
					action = "rename"
				case path == "ip/hotspot/host" && args["mac"] == mac && args["conform"] == true && len(args) == 2:
					action = "conform"
				case path == "system/configuration/save" && len(args) == 0:
					action = "save"
				default:
					t.Errorf("unexpected write %s %v", path, args)
				}
				commands = append(commands, action)
				if tc.refuse == action {
					json.NewEncoder(w).Encode(map[string]string{"status": "error", "message": "refused"})
					return
				}
				if tc.refuse != "noop" {
					if action == "rename" || action == "forget" {
						for name, h := range running {
							if h.MAC == mac {
								delete(running, name)
							}
						}
					}
					if action == "rename" {
						running[tc.rename] = entry{mac}
					}
				}
				w.Write([]byte("{}"))
			}))
			defer server.Close()
			client := NewClient(server.URL, "")
			var err error
			if tc.rename != "" {
				err = client.RenameHost(context.Background(), strings.ToUpper(mac), tc.rename)
			} else {
				err = client.ForgetHost(context.Background(), strings.ToUpper(mac))
			}
			if (err != nil) != tc.wantError || !slices.Equal(commands, tc.want) {
				t.Fatalf("err=%v commands=%v want %v", err, commands, tc.want)
			}
			if running["Other"].MAC != other || (!tc.wantError && reads == 0) || (tc.refuse == "conform" && len(running) != 1) {
				t.Fatal("unrelated host, rollback, or persistence verification failed")
			}
		})
	}
}

func TestNativeDeviceValidationBeforeDispatch(t *testing.T) {
	c := NewClient("", "")
	for _, mac := range []string{"", "*", "00", "02:00:00:00:00:0a;"} {
		if !errors.Is(c.ForgetHost(context.Background(), mac), ErrDeviceMAC) {
			t.Fatalf("unqualified removal allowed with %q", mac)
		}
	}
	for _, name := range []string{"", "  ", "host\nname"} {
		if !errors.Is(c.RenameHost(context.Background(), "02:00:00:00:00:0a", name), ErrDeviceName) {
			t.Fatalf("invalid name %q accepted", name)
		}
	}
}
