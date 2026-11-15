package cardcontroller

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"xkeen-panel/internal/models"
	"xkeen-panel/internal/xkeen"
)

func TestAIGroupRejectsDirectAndInvalidTargetsBeforeReadingConfig(t *testing.T) {
	c := New(filepath.Join(t.TempDir(), "missing.yaml"), t.TempDir(), xkeen.Runtime{}, func() []models.Server { return nil })
	for _, target := range []string{directTarget, "DIRECT", "unknown", strings.Repeat("z", 64)} {
		if _, err := c.SetAIGroup(context.Background(), target); err == nil || !strings.Contains(err.Error(), "группы AI") {
			t.Fatalf("target %q was not rejected before configuration access: %v", target, err)
		}
	}
}

func TestAIGroupRealMihomoAtomicAssignmentAndRollback(t *testing.T) {
	core := os.Getenv("MIHOMO_TEST_BINARY")
	if core == "" {
		t.Skip("set MIHOMO_TEST_BINARY")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	controller := l.Addr().String()
	l.Close()
	servers := []models.Server{
		{Name: "first", RawURI: "vless://aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee@127.0.0.1:9989?type=tcp"},
		{Name: "second", RawURI: "vless://aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee@127.0.0.1:9990?type=tcp"},
	}
	first, second := xkeen.ServiceTargetID(servers[0]), xkeen.ServiceTargetID(servers[1])
	base := map[string]interface{}{
		"external-controller": controller, "secret": "synthetic-ai-group", "mode": "rule",
		"rules":       []string{"DOMAIN-SUFFIX,direct.fixture,DIRECT", "MATCH,DIRECT"},
		stateKey:      map[string]string{"claude": first, "openai": first, "ai": first, "analytics": first, "youtube": first},
		killSwitchKey: map[string]interface{}{"version": 1, "enabled": true, "services": map[string]string{"openai": "off", "analytics": "on"}},
	}
	raw, _ := json.Marshal(base)
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, core, "-d", dir, "-f", path)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { cancel(); _ = cmd.Wait() }()
	c := New(path, dir, xkeen.Runtime{Core: xkeen.CoreMihomo, XrayConfDir: filepath.Join(dir, "configs")}, func() []models.Server { return servers })
	c.validate = func(ctx context.Context, path string) error {
		return exec.CommandContext(ctx, core, "-t", "-d", dir, "-f", path).Run()
	}
	var failedWorker string
	c.prepare = func(_ xkeen.Runtime, id string, _ models.Server) (xkeen.CardProxy, error) {
		if id == failedWorker {
			return xkeen.CardProxy{}, errors.New("synthetic worker failure")
		}
		return xkeen.CardProxy{Port: 59999, UUID: "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", ServerName: "test.invalid", Fingerprint: strings.Repeat("a", 64)}, nil
	}
	p, err := c.read()
	if err != nil {
		t.Fatal(err)
	}
	for !p.api.ruleMode(ctx) {
		if ctx.Err() != nil {
			t.Fatal(ctx.Err())
		}
		time.Sleep(20 * time.Millisecond)
	}
	if _, err := c.SetAIGroup(ctx, first); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(path)
	unchanged := func() {
		t.Helper()
		after, _ := os.ReadFile(path)
		if string(after) != string(before) {
			t.Fatal("failed group change partially changed persistent assignments")
		}
		live, _ := p.api.selectors(ctx)
		for _, id := range aiGroupServices {
			if live[cardPrefix+id].Now != nodePrefix+first && !strings.HasPrefix(live[cardPrefix+id].Now, failoverPrefix) {
				t.Fatal("failed group change partially changed live assignments", id, live[cardPrefix+id].Now)
			}
		}
	}
	priorValidate := c.validate
	c.validate = func(context.Context, string) error { return errors.New("synthetic candidate rejection") }
	if _, err := c.SetAIGroup(ctx, second); err == nil {
		t.Fatal("invalid group candidate was accepted")
	}
	unchanged()
	c.validate = priorValidate
	failedWorker = second
	if _, err := c.SetAIGroup(ctx, second); err == nil {
		t.Fatal("selected worker failure was accepted")
	}
	unchanged()
	// A good new group target must not hide failure to preserve an unrelated
	// currently working route while preparing the shared configuration.
	failedWorker = first
	if _, err := c.SetAIGroup(ctx, second); err == nil {
		t.Fatal("an unrelated working route was silently dropped")
	}
	unchanged()
	failedWorker = ""
	transport := c.http.Transport
	var rejectReload atomic.Bool
	rejectReload.Store(true)
	c.http.Transport = serviceListRoundTrip(func(r *http.Request) (*http.Response, error) {
		if r.Method == http.MethodPut && r.URL.Path == "/configs" && rejectReload.Swap(false) {
			return &http.Response{StatusCode: http.StatusInternalServerError, Header: http.Header{}, Body: io.NopCloser(strings.NewReader("synthetic rejected reload"))}, nil
		}
		return transport.RoundTrip(r)
	})
	if _, err := c.SetAIGroup(ctx, second); err == nil {
		t.Fatal("rejected live reload was accepted")
	}
	unchanged()
	var reloads atomic.Int32
	c.http.Transport = serviceListRoundTrip(func(r *http.Request) (*http.Response, error) {
		if r.Method == http.MethodPut && r.URL.Path == "/configs" {
			reloads.Add(1)
		}
		return transport.RoundTrip(r)
	})
	if _, err := c.SetAIGroup(ctx, second); err != nil {
		t.Fatal(err)
	}
	if reloads.Load() != 1 {
		t.Fatal("group was not published with a single reload", reloads.Load())
	}
	after, err := c.read()
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range aiGroupServices {
		if after.assigned[id] != second {
			t.Fatal("group member did not receive the selected target", id)
		}
	}
	if after.assigned["youtube"] != first || !reflect.DeepEqual(after.doc[killSwitchKey], p.doc[killSwitchKey]) {
		t.Fatal("batch changed an unrelated assignment or kill-switch preferences")
	}
}
