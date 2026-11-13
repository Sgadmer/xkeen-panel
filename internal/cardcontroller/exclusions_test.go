package cardcontroller

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"xkeen-panel/internal/models"
	"xkeen-panel/internal/xkeen"
)

func TestLiveCardExclusions(t *testing.T) {
	core := os.Getenv("MIHOMO_TEST_BINARY")
	if core == "" {
		t.Skip("real Mihomo fixture unavailable")
	}
	dir := t.TempDir()
	config := filepath.Join(dir, "config.yaml")
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	listener.Close()
	base := map[string]interface{}{"external-controller": address, "secret": "synthetic-token", "mode": "rule", "proxy-groups": []interface{}{map[string]interface{}{"name": "ChatGPT", "type": "select", "proxies": []string{"DIRECT", "REJECT"}}}, "rules": []string{"DOMAIN-SUFFIX,example.com,DIRECT", "DOMAIN-SUFFIX,openai.com,ChatGPT", "MATCH,DIRECT"}}
	raw, err := json.Marshal(base)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(config, raw, 0600); err != nil {
		t.Fatal(err)
	}
	old, _ := xkeen.NormalizeExclusion("example.com", "old comment")
	if err := xkeen.SaveExclusions(dir, xkeen.Exclusions{Entries: []xkeen.Exclusion{old}}); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	proc := exec.CommandContext(ctx, core, "-d", dir, "-f", config)
	if err := proc.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { cancel(); proc.Wait() }()
	c := New(config, dir, xkeen.Runtime{Core: xkeen.CoreMihomo, XrayConfDir: filepath.Join(dir, "xray")}, func() []models.Server { return nil })
	c.validate = func(ctx context.Context, p string) error {
		return exec.CommandContext(ctx, core, "-t", "-d", dir, "-f", p).Run()
	}
	p, e := c.read()
	if e != nil {
		t.Fatal(e)
	}
	for !p.api.ruleMode(ctx) {
		if ctx.Err() != nil {
			t.Fatal(ctx.Err())
		}
		time.Sleep(20 * time.Millisecond)
	}
	r := chi.NewRouter()
	r.Route("/api", func(r chi.Router) { c.MountExclusions(r, dir) })
	ask := func(method, path, body string) (int, xkeen.Exclusions) {
		w := httptest.NewRecorder()
		r.ServeHTTP(w, httptest.NewRequest(method, path, strings.NewReader(body)))
		var v xkeen.Exclusions
		_ = json.Unmarshal(w.Body.Bytes(), &v)
		return w.Code, v
	}
	if code, s := ask(http.MethodGet, "/api/exclusions", ""); code != 200 || len(s.Entries) != 1 || s.Entries[0] != old {
		t.Fatal("failed to import existing rule and comment")
	}
	if _, err = c.Set(ctx, "openai", directTarget); err != nil {
		t.Fatal(err)
	}
	code, s := ask("POST", "/api/exclusions", `{"value":"https://direct.example.org/path", "comment":"test"}`)
	if code != 200 || len(s.Entries) != 2 {
		t.Fatal("failed to add", code, s)
	}
	saved, _ := c.read()
	claudePos, directPos, ordinaryPos := -1, -1, -1
	for i, rule := range list(saved.doc["rules"]) {
		switch str(rule) {
		case "DOMAIN-SUFFIX,claude.ai,XKP-card-claude":
			claudePos = i
		case "DOMAIN-SUFFIX,direct.example.org,DIRECT":
			directPos = i
		case "DOMAIN-SUFFIX,openai.com,XKP-card-openai":
			ordinaryPos = i
		}
	}
	if claudePos < 0 || directPos <= claudePos || ordinaryPos <= directPos {
		t.Fatal("priority was not preserved")
	}
	if code, _ := ask("POST", "/api/exclusions", `{"value":"direct.example.org"}`); code == 200 {
		t.Fatal("accepted duplicate")
	}
	if err = c.Reconcile(ctx); err != nil {
		t.Fatal(err)
	}
	if code, s := ask("DELETE", "/api/exclusions/"+old.ID, ""); code != 200 || len(s.Entries) != 1 {
		t.Fatal("failed to delete", code, s)
	}
	v, err := xkeen.LoadExclusions(dir)
	if err != nil || len(v.Entries) != 1 || v.Entries[0].Comment != "test" {
		t.Fatal("legacy mirror incomplete", v, err)
	}
	previous, _ := os.ReadFile(config)
	previousMirror, _ := os.ReadFile(xkeen.ExclusionsPath(dir))
	c.validate = func(context.Context, string) error { return os.ErrInvalid }
	if code, _ := ask("POST", "/api/exclusions", `{"value":"other.example.org"}`); code == 200 {
		t.Fatal("accepted invalid candidate")
	}
	after, _ := os.ReadFile(config)
	afterMirror, _ := os.ReadFile(xkeen.ExclusionsPath(dir))
	if !bytes.Equal(after, previous) || !bytes.Equal(afterMirror, previousMirror) {
		t.Fatal("modified state after failure")
	}
}
