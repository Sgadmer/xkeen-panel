package cardcontroller

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"xkeen-panel/internal/models"
	"xkeen-panel/internal/xkeen"
)

func TestMihomoDetachOnlySelectedNativeSource(t *testing.T) {
	core := os.Getenv("MIHOMO_TEST_BINARY")
	if core == "" {
		t.Skip("requires local Mihomo")
	}
	dir := t.TempDir()
	socket, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := socket.Addr().String()
	socket.Close()
	proxy := func(name string) string {
		return fmt.Sprintf("proxies:\n  - {name: %q, type: socks5, server: 127.0.0.1, port: 39990}\n", name)
	}
	remote := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, proxy("remote-node")) }))
	defer remote.Close()
	if err := os.WriteFile(filepath.Join(dir, "second.yaml"), []byte(proxy("other-node")), 0600); err != nil {
		t.Fatal(err)
	}
	providers := map[string]interface{}{"first": map[string]interface{}{"type": "http", "url": remote.URL + "/unit-test", "path": "first.yaml"}, "second": map[string]interface{}{"type": "file", "path": "second.yaml"}}
	group := func(name, kind string, refs ...string) map[string]interface{} {
		return map[string]interface{}{"name": name, "type": kind, "use": refs, "url": "http://127.0.0.1:39991", "interval": 3600, "lazy": true}
	}
	manual := group("Main", "select", "first", "second")
	manual["proxies"] = []string{"Auto", "DIRECT"}
	rules := []string{"MATCH,Main"}
	config := map[string]interface{}{"mode": "rule", "external-controller": addr, "secret": "test-local-controller", "proxy-providers": providers, "proxy-groups": []interface{}{group("Auto", "url-test", "first"), group("Other", "fallback", "second"), manual}, "rules": rules}
	original, _ := json.Marshal(config)
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, original, 0600); err != nil {
		t.Fatal(err)
	}
	c := New(path, dir, xkeen.Runtime{}, func() []models.Server { return nil })
	c.validate = func(ctx context.Context, path string) error {
		return exec.CommandContext(ctx, core, "-t", "-d", dir, "-f", path).Run()
	}
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, core, "-d", dir, "-f", path)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { cancel(); cmd.Wait() }()
	p, err := c.read()
	if err != nil {
		t.Fatal(err)
	}
	for {
		current, err := p.api.providers(ctx)
		if err == nil && len(current["first"].Proxies) == 1 {
			break
		}
		if ctx.Err() != nil {
			t.Fatal(ctx.Err())
		}
		time.Sleep(20 * time.Millisecond)
	}
	selectManual := func(name string) {
		if err := p.api.request(ctx, "PUT", "/proxies/"+url.PathEscape("Main"), map[string]string{"name": name}, nil); err != nil {
			t.Fatal(err)
		}
	}
	// Removing the subscription whose server is selected is allowed. The group
	// blocks until the owner chooses again; it must not move to Auto or DIRECT.
	selectManual("remote-node")
	undo, err := c.DetachSource(ctx, remote.URL+"/unit-test")
	if err != nil {
		t.Fatal(err)
	}
	live, err := p.api.selectors(ctx)
	if err != nil || live["Main"].Now != "REJECT" || live["Auto"].Now != "REJECT" || live["Other"].Now != "other-node" {
		t.Fatalf("removing the selected server did not block its groups: %v %v %v", live["Main"], live["Auto"], live["Other"])
	}
	if undo == nil {
		t.Fatal("missing rollback")
	}
	blocked, err := c.read()
	if err != nil {
		t.Fatal(err)
	}
	for _, raw := range list(blocked.doc["proxy-groups"]) {
		if group := object(raw); str(group["name"]) == "Main" && (group[removedSelectionKey] != true || !reflect.DeepEqual(namesOf(group["proxies"]), []string{"REJECT", "Auto", "DIRECT"})) {
			t.Fatalf("the added REJECT is not first or not marked: %v", group["proxies"])
		}
	}
	if err := undo(ctx); err != nil {
		t.Fatal(err)
	}
	checkDisk, _ := os.ReadFile(path)
	if !bytes.Equal(original, checkDisk) {
		t.Fatal("rollback did not restore the profile with the selected server")
	}
	if live, err = p.api.selectors(ctx); err != nil || live["Main"].Now != "remote-node" {
		t.Fatalf("rollback lost the manual selection: %v", live["Main"])
	}
	// A choice that does not depend on the removed subscription stays as it is.
	selectManual("Auto")
	undo, err = c.DetachSource(ctx, remote.URL+"/unit-test")
	if err != nil {
		t.Fatal(err)
	}
	updated, err := c.read()
	if err != nil {
		t.Fatal(err)
	}
	live, err = p.api.selectors(ctx)
	if err != nil || live["Auto"].Now != "REJECT" || live["Main"].Now != "Auto" || live["Other"].Now != "other-node" {
		t.Fatalf("route mismatch after removal: %v %v %v", live["Auto"], live["Main"], live["Other"])
	}
	if _, present := object(updated.doc["proxy-providers"])["first"]; present || !reflect.DeepEqual(p.doc["rules"], updated.doc["rules"]) || !reflect.DeepEqual(object(p.doc["proxy-providers"])["second"], object(updated.doc["proxy-providers"])["second"]) {
		t.Fatal("profile ownership or rules changed")
	}
	if undo == nil {
		t.Fatal("missing rollback")
	}
	if err := undo(ctx); err != nil {
		t.Fatal(err)
	}
	restored, _ := os.ReadFile(path)
	if !bytes.Equal(restored, original) {
		t.Fatal("provider rollback did not restore exact original file")
	}
}
