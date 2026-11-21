package cardcontroller

import (
	"context"
	"encoding/json"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"xkeen-panel/internal/models"
	"xkeen-panel/internal/xkeen"
)

func TestDNSServerAddresses(t *testing.T) {
	accepted := map[string]string{
		"https://dns.example.org/dns-query":        "https://dns.example.org/dns-query",
		" HTTPS://DNS.Example.org ":                "https://dns.example.org/dns-query",
		"https://dns.example.org:8443/custom/id":   "https://dns.example.org:8443/custom/id",
		"tls://dns.example.org":                    "tls://dns.example.org",
		"tls://1.1.1.1:853":                        "tls://1.1.1.1:853",
		"quic://dns.example.org":                   "quic://dns.example.org",
		"8.8.8.8":                                  "8.8.8.8",
		"2001:4860:4860::8888":                     "2001:4860:4860::8888",
		"https://[2606:4700:4700::1111]/dns-query": "https://[2606:4700:4700::1111]/dns-query",
	}
	for value, want := range accepted {
		if got, err := normalizeDNSServer(value); err != nil || got != want {
			t.Errorf("%q: got %q %v, want %q", value, got, err, want)
		}
	}
	for _, value := range []string{"", "dns.example.org", "http://dns.example.org/dns-query", "udp://1.1.1.1", "https://user:pass@dns.example.org/dns-query",
		"https://dns.example.org/dns-query?id=1", "https://localhost/dns-query", "tls://dns.example.org/path", "1.1.1.1#proxy", "1.1.1.1, 8.8.8.8", "https://dns exa.org"} {
		if got, err := normalizeDNSServer(value); err == nil {
			t.Errorf("%q was accepted as %q", value, got)
		}
	}
}

func TestDNSChoiceIsNormalisedAndRead(t *testing.T) {
	if settings, servers, err := normalizeDNS(DNSSettings{Mode: dnsModeRouter, Preset: "google", Servers: []string{"x"}}); err != nil || settings.Preset != "" || len(settings.Servers) != 0 || servers != nil {
		t.Fatalf("the router mode keeps nothing else: %+v %v %v", settings, servers, err)
	}
	settings, servers, err := normalizeDNS(DNSSettings{Mode: dnsModeSecure, Preset: "cloudflare", Servers: []string{"ignored"}})
	if err != nil || settings.Preset != "cloudflare" || len(settings.Servers) != 0 || !slices.Equal(servers, presetServers("cloudflare")) {
		t.Fatalf("preset: %+v %v %v", settings, servers, err)
	}
	settings, servers, err = normalizeDNS(DNSSettings{Mode: dnsModeSecure, Preset: dnsCustom, Servers: []string{" tls://dns.example.org ", "", "9.9.9.9", "tls://dns.example.org"}})
	if err != nil || !slices.Equal(servers, []string{"tls://dns.example.org", "9.9.9.9"}) || !slices.Equal(settings.Servers, servers) {
		t.Fatalf("own servers: %+v %v %v", settings, servers, err)
	}
	for name, bad := range map[string]DNSSettings{
		"no mode":              {},
		"unknown service":      {Mode: dnsModeSecure, Preset: "nobody"},
		"no servers":           {Mode: dnsModeSecure, Preset: dnsCustom},
		"only plain servers":   {Mode: dnsModeSecure, Preset: dnsCustom, Servers: []string{"8.8.8.8", "1.1.1.1"}},
		"too many servers":     {Mode: dnsModeSecure, Preset: dnsCustom, Servers: []string{"tls://a.example", "tls://b.example", "tls://c.example", "tls://d.example", "tls://e.example"}},
		"a malformed address":  {Mode: dnsModeSecure, Preset: dnsCustom, Servers: []string{"tls://a.example", "nonsense"}},
		"a mode of its own":    {Mode: "fake-ip"},
		"a preset as a server": {Mode: dnsModeSecure, Preset: dnsCustom, Servers: []string{"cloudflare"}},
	} {
		if _, _, err := normalizeDNS(bad); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}

	doc := map[string]interface{}{}
	if view := readDNS(doc); view.Mode != dnsModeRouter || view.Foreign || len(view.Presets) == 0 {
		t.Fatalf("a profile without DNS: %+v", view)
	}
	writeDNS(doc, DNSSettings{Mode: dnsModeSecure, Preset: dnsCustom, Servers: []string{"tls://dns.example.org"}}, []string{"tls://dns.example.org"})
	section := object(doc["dns"])
	if section["enable"] != true || section["listen"] != nil || section["enhanced-mode"] != nil {
		t.Fatalf("the core must use the DNS itself without serving the home network: %v", section)
	}
	// The round trip through the stored configuration keeps the choice.
	raw, _ := json.Marshal(doc)
	var stored map[string]interface{}
	_ = json.Unmarshal(raw, &stored)
	if view := readDNS(stored); view.Mode != dnsModeSecure || view.Preset != dnsCustom || !slices.Equal(view.Servers, []string{"tls://dns.example.org"}) || view.Foreign {
		t.Fatalf("the saved choice was not read back: %+v", view)
	}
	writeDNS(doc, DNSSettings{Mode: dnsModeRouter}, nil)
	if _, left := doc["dns"]; left || doc[dnsKey] != nil {
		t.Fatal("returning to the router left DNS settings behind")
	}
	// Settings the panel did not write are shown without what could identify the owner.
	foreign := map[string]interface{}{"dns": map[string]interface{}{"enable": true, "nameserver": []interface{}{"https://dns.example.org/personal-id-123", "8.8.8.8#proxy"}}}
	view := readDNS(foreign)
	if !view.Foreign || !slices.Equal(view.ForeignServers, []string{"https://dns.example.org", "8.8.8.8"}) {
		t.Fatalf("foreign settings: %+v", view)
	}
}

// answerDNS is a DNS server that gives every name one address.
func answerDNS(t *testing.T) string {
	t.Helper()
	conn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	go func() {
		buf := make([]byte, 1500)
		for {
			n, peer, err := conn.ReadFrom(buf)
			if err != nil {
				return
			}
			if n < 17 {
				continue
			}
			query := buf[:n]
			end := 12
			for end < n && query[end] != 0 {
				end += int(query[end]) + 1
			}
			end += 5 // the closing zero, the type and the class
			if end > n {
				continue
			}
			reply := append([]byte{}, query[:end]...)
			reply[2], reply[3] = 0x81, 0x80 // a response, recursion available, no error
			reply[6], reply[7] = 0, 0
			reply[8], reply[9], reply[10], reply[11] = 0, 0, 0, 0
			if query[end-4] == 0 && query[end-3] == 1 { // an A question gets an address
				reply[7] = 1
				reply = append(reply, 0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 203, 0, 113, 9)
			}
			_, _ = conn.WriteTo(reply, peer)
		}
	}()
	return conn.LocalAddr().String()
}

// Against a real core: a DNS that answers is kept, one that does not is
// replaced by the previous choice at once.
func TestLiveDNSChoiceIsKeptOnlyWhenItResolves(t *testing.T) {
	core := os.Getenv("MIHOMO_TEST_BINARY")
	if core == "" {
		t.Skip("real Mihomo fixture unavailable")
	}
	working := answerDNS(t)
	dead, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	silent := dead.LocalAddr().String()
	dead.Close()
	saved := dnsPresets
	t.Cleanup(func() { dnsPresets = saved })
	dnsPresets = append(slices.Clone(saved), dnsPreset{"answers", "Test", []string{working}}, dnsPreset{"silent", "Test", []string{silent}})

	dir := t.TempDir()
	config := filepath.Join(dir, "config.yaml")
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	listener.Close()
	raw, _ := json.Marshal(map[string]interface{}{"external-controller": address, "secret": "synthetic-token", "mode": "rule", "rules": []string{"MATCH,DIRECT"}})
	if err = os.WriteFile(config, raw, 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	proc := exec.CommandContext(ctx, core, "-d", dir, "-f", config)
	if err = proc.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { cancel(); proc.Wait() }()
	c := New(config, dir, xkeen.Runtime{Core: xkeen.CoreMihomo, XrayConfDir: filepath.Join(dir, "xray")}, func() []models.Server { return nil })
	c.validate = func(ctx context.Context, p string) error {
		return exec.CommandContext(ctx, core, "-t", "-d", dir, "-f", p).Run()
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

	view, err := c.SetDNS(ctx, DNSSettings{Mode: dnsModeSecure, Preset: "answers"})
	if err != nil || view.Mode != dnsModeSecure || view.Preset != "answers" {
		t.Fatalf("a DNS that answers was not kept: %+v %v", view, err)
	}
	if !p.api.dnsAnswers(ctx, "probe.example.org") {
		t.Fatal("the core does not resolve through the chosen DNS")
	}
	// A DNS that does not answer must not stay: the previous one returns.
	view, err = c.SetDNS(ctx, DNSSettings{Mode: dnsModeSecure, Preset: "silent"})
	if err == nil || !strings.Contains(err.Error(), "возвращены") {
		t.Fatalf("a silent DNS was accepted: %+v %v", view, err)
	}
	current, err := c.DNS()
	if err != nil || current.Preset != "answers" || !p.api.dnsAnswers(ctx, "again.example.org") {
		t.Fatalf("the previous DNS was not put back: %+v %v", current, err)
	}
	// Back to the router: the core has no DNS of its own again.
	if view, err = c.SetDNS(ctx, DNSSettings{Mode: dnsModeRouter}); err != nil || view.Mode != dnsModeRouter {
		t.Fatalf("returning to the router failed: %+v %v", view, err)
	}
	if stored, err := c.read(); err != nil || stored.doc["dns"] != nil || stored.doc[dnsKey] != nil {
		t.Fatalf("DNS settings were left in the profile: %v", err)
	}
	// A profile with DNS settings of its own is left alone.
	stored, _ := c.read()
	stored.doc["dns"] = map[string]interface{}{"enable": false}
	body, _ := json.Marshal(stored.doc)
	if err = os.WriteFile(config, body, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = c.SetDNS(ctx, DNSSettings{Mode: dnsModeSecure, Preset: "answers"}); err == nil {
		t.Fatal("the DNS settings of the profile were overwritten")
	}
}
