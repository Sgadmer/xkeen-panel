package keenetic

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestFaceIDLANProvisioning(t *testing.T) {
	const label = "test-delete-this"
	const ip = "192.168.2.1"
	origin := "https://panel." + label + "." + panelDNSZone + ":8443"
	private, booked, proxy, host := false, false, false, false
	bookCount, proxyCount := 0, 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var args map[string]any
		if r.Method == "POST" {
			if err := json.NewDecoder(r.Body).Decode(&args); err != nil {
				t.Error(err)
			}
		}
		var result any = map[string]any{}
		switch strings.TrimPrefix(r.URL.Path, "/rci/") {
		case "show/ndns":
			if booked {
				result = map[string]any{"name": label, "booked": true, "domain": panelDNSZone}
			}
		case "show/rc/ip/http":
			result = map[string]any{"ssl": map[string]any{"enable": true, "port": "8443"}, "security-level": map[string]bool{"public": !private, "private": private}}
		case "show/sc/ip/http/proxy":
			if proxy {
				result = map[string]any{"panel": map[string]any{"upstream": map[string]any{"proto": "http", "upstream": ip, "port": "3000"}, "domain": map[string]bool{"ndns": true}, "security-level": map[string]bool{"private": true}, "preserve-host": true}}
			}
		case "show/rc/ip/host":
			result = []any{}
			if host {
				result = []any{map[string]any{"domain": "panel." + label + "." + panelDNSZone, "address": ip}}
			}
		case "ndns/check-name":
			result = map[string]any{"list": map[string]any{"item": []any{map[string]any{"name": label, "domain": panelDNSZone, "available": true, "acme": true}}}}
		case "ip/http/security-level":
			if args["private"] != true {
				t.Error("missing private level")
			}
			private = true
		case "ndns/book-name":
			if !private || r.Method == "POST" && (args["name"] != label || args["domain"] != panelDNSZone) {
				t.Error("booking before private scope or wrong domain")
			}
			if r.Method == "POST" {
				bookCount++
				result = map[string]any{"continued": true}
			} else {
				booked = true
			}
		case "ip/http/proxy":
			if args["security-level"].(map[string]any)["private"] != "private" || args["domain"].(map[string]any)["ndns"] != true || args["preserve-host"] != true {
				t.Error("not LAN-only")
			}
			u := args["upstream"].(map[string]any)
			if u["upstream"] != ip || u["proto"] != "http" || u["port"] != "3000" {
				t.Errorf("incorrect upstream: %v", u)
			}
			proxyCount++
			proxy = true
		case "ip/host":
			if args["address"] != ip {
				t.Error("invalid DNS target")
			}
			host = true
		case "system/configuration/save":
			result = []any{map[string]any{"status": "message", "message": "saved"}}
		default:
			t.Errorf("unexpected %s", r.URL.Path)
		}
		_ = json.NewEncoder(w).Encode(result)
	}))
	defer srv.Close()
	c := NewClient(srv.URL, "")
	planned, public, err := c.PanelHTTPSPlan(context.Background(), label)
	if err != nil || planned != origin || !public {
		t.Fatalf("plan %q %t %v", planned, public, err)
	}
	if _, err = c.PreparePanelHTTPS(context.Background(), label, ip, 3000); err == nil || private || booked {
		t.Fatal("admin consent missing")
	}
	for i := 0; i < 2; i++ {
		url, err := c.PreparePanelHTTPS(context.Background(), label, ip, 3000, "private")
		if err != nil || url != origin {
			t.Fatalf("prepare: %q %v", url, err)
		}
	}
	if bookCount != 1 || proxyCount != 1 {
		t.Fatalf("duplicate provisioning %d %d", bookCount, proxyCount)
	}
}

func TestProxyAccessAndPartialCreation(t *testing.T) {
	for _, scope := range []string{`{"private":"private"}`, `{"private":true}`, `{"private":true,"public":false}`, `{}`, `{"private":false}`, `{"public":true}`, `{"private":true,"protected":true}`} {
		var p proxyRule
		if err := json.Unmarshal([]byte(scope), &p.Level); err != nil {
			t.Fatal(err)
		}
		if expected := strings.HasPrefix(scope, `{"private":"private"`) || scope == `{"private":true}` || scope == `{"private":true,"public":false}`; expected != p.private() {
			t.Errorf("scope %s private %t", scope, p.private())
		}
	}
	for _, address := range []string{"", "192.168.2.3"} {
		deleted := false
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodGet {
				_ = json.NewEncoder(w).Encode(map[string]any{"panel": map[string]any{"security-level": map[string]bool{"private": true}, "domain": map[string]bool{"ndns": true}, "upstream": map[string]any{"upstream": address}}})
				return
			}
			var args map[string]any
			_ = json.NewDecoder(r.Body).Decode(&args)
			if args["no"] == true {
				deleted = true
			}
			_ = json.NewEncoder(w).Encode([]any{})
		}))
		err := NewClient(srv.URL, "").createPanelProxy(context.Background(), "192.168.2.1", 3000)
		srv.Close()
		if err == nil || deleted != (address == "") {
			t.Fatalf("address %q deleted %t err %v", address, deleted, err)
		}
	}
}

func TestRCIPort(t *testing.T) {
	for _, raw := range []string{`8443`, `"8443"`} {
		var p rciPort
		if err := json.Unmarshal([]byte(raw), &p); err != nil || p != 8443 {
			t.Errorf("%s: %d %v", raw, p, err)
		}
	}
	for _, raw := range []string{`0`, `"65536"`, `"abc"`, `1.2`, `null`, `"-1"`} {
		var p rciPort
		if err := json.Unmarshal([]byte(raw), &p); err == nil {
			t.Errorf("invalid port accepted: %s", raw)
		}
	}
}
