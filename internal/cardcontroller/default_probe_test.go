package cardcontroller

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"xkeen-panel/internal/models"
	"xkeen-panel/internal/xkeen"
)

func TestProbeDefaultDistinguishesControllerErrorsFromRouteFailure(t *testing.T) {
	tests := []struct {
		name      string
		route     string
		selectors int
		delay     []int
		checked   bool
		success   bool
	}{
		{"success via selected outbound", "Group", 200, []int{200}, true, true},
		{"transient timeout", "Node", 200, []int{504, 200}, true, true},
		{"two failed probes", "Node", 200, []int{503, 504}, true, false},
		{"controller lost before confirmation", "Node", 200, []int{503, 401}, false, false},
		{"route disappeared", "Node", 200, []int{404}, false, false},
		{"controller unavailable at lookup", "Node", 503, nil, false, false},
		{"ordinary direct route", "DIRECT", 200, nil, false, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var calls atomic.Int32
			api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/proxies":
					w.WriteHeader(tc.selectors)
					fmt.Fprint(w, `{"proxies":{"Node":{"type":"Vmess"},"DIRECT":{"type":"Direct"},"Group":{"type":"Fallback","now":"Node","all":["Node","DIRECT"]}}}`)
				case "/configs":
					fmt.Fprint(w, `{"mode":"rule"}`)
				case "/proxies/Node/delay":
					i := int(calls.Add(1)) - 1
					if i >= len(tc.delay) {
						t.Error("unexpected delay probe")
						w.WriteHeader(http.StatusBadRequest)
						return
					}
					w.WriteHeader(tc.delay[i])
					fmt.Fprint(w, `{"delay":32}`)
				default:
					t.Errorf("unexpected API path %q", r.URL.Path)
					w.WriteHeader(http.StatusNotFound)
				}
			}))
			defer api.Close()
			dir := t.TempDir()
			config := filepath.Join(dir, "config.yaml")
			content := fmt.Sprintf("mode: rule\nexternal-controller: %s\nsecret: test-only\nrules:\n  - MATCH,%s\n", strings.TrimPrefix(api.URL, "http://"), tc.route)
			if err := os.WriteFile(config, []byte(content), 0600); err != nil {
				t.Fatal(err)
			}
			ctrl := New(config, dir, xkeen.Runtime{}, func() []models.Server { return nil })
			probe, err := ctrl.ProbeDefault(context.Background(), "https://test.example/")
			if (err == nil) != tc.success || probe.Checked != tc.checked || int(calls.Load()) != len(tc.delay) {
				t.Errorf("probe=%+v err=%v delay probes=%d", probe, err, calls.Load())
			}
			if tc.success && probe.Latency != 32 {
				t.Errorf("latency = %d, want 32", probe.Latency)
			}
		})
	}
}

func TestDirectFallbackIsUnverifiedForManualAndPoolRoutes(t *testing.T) {
	ctrl := &Controller{catalog: func() []models.Server { return nil }}
	for _, selected := range []string{strings.Repeat("a", 64), allPoolID, ""} {
		root, fallback := cardPrefix+defaultID, failoverPrefix+"default"
		p := profile{
			doc: map[string]interface{}{
				killSwitchKey: map[string]interface{}{"enabled": false, "services": map[string]interface{}{}},
				"rules":       []interface{}{"MATCH," + fallback, "MATCH,Auto"},
			},
			assigned: map[string]string{defaultID: selected},
		}
		live := map[string]selector{
			root:     {Type: "Selector", Now: fallback, All: []string{fallback}},
			fallback: {Type: "Fallback", Now: "DIRECT", All: []string{"Node", "DIRECT"}},
			"DIRECT": {Type: "Direct"},
			"Node":   {Type: "Vmess"},
		}
		state := ctrl.defaultRoute(p, live)
		if state.Name != "DIRECT" || state.probeTarget != "" {
			t.Errorf("selection %q resolved to name %q and probe target %q", selected, state.Name, state.probeTarget)
		}
	}
}

func TestSelectiveDefaultFollowsBlocklistGroupThroughDirectCatchAll(t *testing.T) {
	ctrl := &Controller{catalog: func() []models.Server { return nil }}
	root := cardPrefix + defaultID
	live := map[string]selector{
		"Auto":                {Type: "URLTest", Now: "Node", All: []string{"Node"}},
		"Node":                {Type: "Vmess"},
		"DIRECT":              {Type: "Direct"},
		cardPrefix + "direct": {Type: "Selector", Now: "DIRECT", All: []string{"DIRECT"}},
		root:                  {Type: "Selector", Now: "Auto", All: []string{"Auto"}},
	}
	p := profile{
		doc: map[string]interface{}{
			refilterKey: map[string]interface{}{"enabled": true},
			"rules":     []interface{}{"RULE-SET,XKP-refilter-domains," + root, "MATCH," + cardPrefix + "direct", "MATCH,Auto"},
		},
		assigned: map[string]string{},
	}
	for _, assignment := range []string{"", allPoolID, strings.Repeat("c", 64)} {
		p.assigned[defaultID] = assignment
		state := ctrl.defaultRoute(p, live)
		if !state.Selective || state.Group != root || state.probeTarget != "Node" {
			t.Fatalf("selective route: %+v", state)
		}
		if assignment == allPoolID && (state.ScopeID != allPoolID || state.SelectionKind != "auto") {
			t.Errorf("selected pool lost under selective routing: %+v", state)
		}
	}
	live[root] = selector{Type: "Fallback", Now: "DIRECT", All: []string{"Auto", "DIRECT"}}
	state := ctrl.defaultRoute(p, live)
	if !state.Selective || state.Name != "DIRECT" || state.probeTarget != "" {
		t.Errorf("direct fallback must not be probed or reported as VPN: %+v", state)
	}
}
