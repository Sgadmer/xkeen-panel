package cardcontroller

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
)

// How the core itself finds addresses: the servers of a provider profile, the
// sites a card's own proxy is asked for by name, its downloads.
//
// By default Mihomo has no DNS of its own and asks the router, like any
// program on it. The owner can make it ask an encrypted DNS service instead.
// The devices of the home network are not affected either way: they ask the
// router, and the core reads the name of a site from the connection itself.
//
// A wrong DNS would leave the core unable to reach its servers, so a change is
// checked right after it is applied: when the core can not resolve a name
// through the new servers, the previous settings are put back at once.

const (
	dnsKey        = "x-xkeen-panel-dns"
	dnsModeRouter = "router"
	dnsModeSecure = "secure"
	dnsCustom     = "custom"
	maxDNSServers = 4
)

type dnsPreset struct {
	ID      string   `json:"id"`
	Name    string   `json:"name"`
	Servers []string `json:"servers"`
}

// Every preset is addressed by IP, so reaching it needs no other DNS first.
var dnsPresets = []dnsPreset{
	{"cloudflare", "Cloudflare", []string{"https://1.1.1.1/dns-query", "https://1.0.0.1/dns-query"}},
	{"google", "Google", []string{"https://8.8.8.8/dns-query", "https://8.8.4.4/dns-query"}},
	{"quad9", "Quad9", []string{"https://9.9.9.9/dns-query", "https://149.112.112.112/dns-query"}},
	{"adguard", "AdGuard", []string{"https://94.140.14.14/dns-query", "https://94.140.15.15/dns-query"}},
}

// Plain resolvers used only to find the address of a DNS service that is
// given by name.
var dnsBootstrap = []string{"1.1.1.1", "8.8.8.8", "9.9.9.9"}

type DNSSettings struct {
	Mode    string   `json:"mode"`
	Preset  string   `json:"preset,omitempty"`
	Servers []string `json:"servers,omitempty"` // of the owner's own choice
}

type DNSView struct {
	DNSSettings
	Presets []dnsPreset `json:"presets"`
	// The profile carries DNS settings the panel did not write. They are shown
	// and left alone.
	Foreign        bool     `json:"foreign"`
	ForeignServers []string `json:"foreign_servers,omitempty"`
}

func presetServers(id string) []string {
	for _, preset := range dnsPresets {
		if preset.ID == id {
			return slices.Clone(preset.Servers)
		}
	}
	return nil
}

// normalizeDNSServer accepts an encrypted DNS address — https://, tls:// or
// quic:// — or a plain IP address, and returns the form Mihomo reads.
func normalizeDNSServer(value string) (string, error) {
	value = strings.TrimSpace(value)
	bad := fmt.Errorf("«%s»: укажите адрес DNS вида https://dns.example/dns-query, tls://dns.example или IP-адрес", value)
	if value == "" || len(value) > 200 || strings.ContainsAny(value, " \t\r\n#,") {
		return "", bad
	}
	if addr, err := netip.ParseAddr(value); err == nil && addr.Zone() == "" {
		return addr.Unmap().String(), nil
	}
	parsed, err := url.Parse(value)
	if err != nil || parsed.User != nil || parsed.Hostname() == "" || parsed.Fragment != "" || parsed.RawQuery != "" {
		return "", bad
	}
	switch parsed.Scheme {
	case "https":
		if parsed.Path == "" || parsed.Path == "/" {
			parsed.Path = "/dns-query"
		}
	case "tls", "quic":
		if parsed.Path != "" && parsed.Path != "/" {
			return "", bad
		}
		parsed.Path = ""
	default:
		return "", bad
	}
	host := strings.ToLower(parsed.Hostname())
	if _, err := netip.ParseAddr(host); err != nil && (!strings.Contains(host, ".") || !validServiceDomain(host)) {
		return "", bad
	}
	if port := parsed.Port(); port != "" {
		host = host + ":" + port
		if strings.Contains(parsed.Hostname(), ":") {
			host = "[" + parsed.Hostname() + "]:" + port
		}
	} else if strings.Contains(parsed.Hostname(), ":") {
		host = "[" + parsed.Hostname() + "]"
	}
	return parsed.Scheme + "://" + host + parsed.Path, nil
}

func normalizeDNS(settings DNSSettings) (DNSSettings, []string, error) {
	switch settings.Mode {
	case dnsModeRouter:
		return DNSSettings{Mode: dnsModeRouter}, nil, nil
	case dnsModeSecure:
	default:
		return DNSSettings{}, nil, errors.New("выберите, кого ядро спрашивает об адресах: роутер или зашифрованный DNS")
	}
	if settings.Preset != dnsCustom {
		servers := presetServers(settings.Preset)
		if servers == nil {
			return DNSSettings{}, nil, errors.New("неизвестная служба DNS")
		}
		return DNSSettings{Mode: dnsModeSecure, Preset: settings.Preset}, servers, nil
	}
	var servers []string
	for _, raw := range settings.Servers {
		if strings.TrimSpace(raw) == "" {
			continue
		}
		server, err := normalizeDNSServer(raw)
		if err != nil {
			return DNSSettings{}, nil, err
		}
		if !slices.Contains(servers, server) {
			servers = append(servers, server)
		}
	}
	if len(servers) == 0 || len(servers) > maxDNSServers {
		return DNSSettings{}, nil, fmt.Errorf("укажите от одного до %d адресов DNS", maxDNSServers)
	}
	encrypted := false
	for _, server := range servers {
		encrypted = encrypted || strings.Contains(server, "://")
	}
	if !encrypted {
		return DNSSettings{}, nil, errors.New("нужен хотя бы один зашифрованный адрес (https:// или tls://): обычный DNS виден провайдеру")
	}
	return DNSSettings{Mode: dnsModeSecure, Preset: dnsCustom, Servers: servers}, servers, nil
}

// dnsSection is what the core reads. It has no listener: the core does not
// become the DNS server of the home network.
func dnsSection(servers []string) map[string]interface{} {
	return map[string]interface{}{
		"enable":                  true,
		"ipv6":                    false,
		"default-nameserver":      slices.Clone(dnsBootstrap),
		"nameserver":              slices.Clone(servers),
		"proxy-server-nameserver": slices.Clone(servers),
	}
}

func readDNS(doc map[string]interface{}) DNSView {
	view := DNSView{DNSSettings: DNSSettings{Mode: dnsModeRouter}, Presets: dnsPresets}
	section, present := doc["dns"]
	marker := object(doc[dnsKey])
	if marker == nil {
		if present && section != nil {
			view.Foreign = true
			for _, key := range []string{"nameserver", "fallback"} {
				for _, item := range list(object(section)[key]) {
					view.ForeignServers = append(view.ForeignServers, dnsHost(str(item)))
				}
			}
		}
		return view
	}
	settings := DNSSettings{Mode: str(marker["mode"]), Preset: str(marker["preset"])}
	for _, item := range list(marker["servers"]) {
		settings.Servers = append(settings.Servers, str(item))
	}
	if normal, _, err := normalizeDNS(settings); err == nil && present {
		view.DNSSettings = normal
	}
	return view
}

// dnsHost shows where a DNS address leads without the rest of it: a path can
// carry a personal identifier.
func dnsHost(server string) string {
	if parsed, err := url.Parse(server); err == nil && parsed.Hostname() != "" {
		return parsed.Scheme + "://" + parsed.Hostname()
	}
	server, _, _ = strings.Cut(server, "#")
	return server
}

func (c *Controller) DNS() (DNSView, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	p, err := c.read()
	if err != nil {
		return DNSView{}, err
	}
	return readDNS(p.doc), nil
}

func writeDNS(doc map[string]interface{}, settings DNSSettings, servers []string) {
	if settings.Mode != dnsModeSecure {
		delete(doc, "dns")
		delete(doc, dnsKey)
		return
	}
	marker := map[string]interface{}{"mode": settings.Mode, "preset": settings.Preset}
	if len(settings.Servers) > 0 {
		items := make([]interface{}, len(settings.Servers))
		for i, server := range settings.Servers {
			items[i] = server
		}
		marker["servers"] = items
	}
	doc[dnsKey] = marker
	doc["dns"] = dnsSection(servers)
}

// dnsAnswers asks the running core to resolve a name through its own DNS.
func (a coreAPI) dnsAnswers(ctx context.Context, name string) bool {
	var answer struct {
		Status int
		Answer []json.RawMessage
	}
	if a.request(ctx, "GET", "/dns/query?type=A&name="+url.QueryEscape(name), nil, &answer) != nil {
		return false
	}
	return answer.Status == 0 && len(answer.Answer) > 0
}

func (c *Controller) dnsProbeName() string {
	if parsed, err := url.Parse(c.probeURL); err == nil && strings.Contains(parsed.Hostname(), ".") {
		if _, isIP := netip.ParseAddr(parsed.Hostname()); isIP != nil {
			return parsed.Hostname()
		}
	}
	return "www.gstatic.com"
}

// SetDNS applies the choice and keeps it only if the core can still resolve.
func (c *Controller) SetDNS(ctx context.Context, wanted DNSSettings) (DNSView, error) {
	settings, servers, err := normalizeDNS(wanted)
	if err != nil {
		return DNSView{}, err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	p, err := c.read()
	if err != nil {
		return DNSView{}, err
	}
	before := readDNS(p.doc)
	if before.Foreign {
		return before, errors.New("в профиле Mihomo уже есть свои настройки DNS; панель их не меняет")
	}
	previous, _, _ := normalizeDNS(before.DNSSettings)
	previousServers := previous.Servers
	if previous.Mode == dnsModeSecure && previous.Preset != dnsCustom {
		previousServers = presetServers(previous.Preset)
	}
	apply := func(settings DNSSettings, servers []string) error {
		_, err := c.apply(ctx, "", "", func(next *profile) error {
			if readDNS(next.doc).Foreign {
				return errors.New("в профиле Mihomo уже есть свои настройки DNS; панель их не меняет")
			}
			writeDNS(next.doc, settings, servers)
			return nil
		})
		return err
	}
	if err = apply(settings, servers); err != nil {
		return before, err
	}
	if settings.Mode == dnsModeSecure {
		works := false
		name := c.dnsProbeName()
		for attempt := 0; attempt < 3 && !works; attempt++ {
			probe, cancel := context.WithTimeout(ctx, 5*time.Second)
			works = p.api.dnsAnswers(probe, name)
			cancel()
		}
		if !works {
			// The core must not stay with a DNS it can not use.
			restore, cancel := context.WithTimeout(context.Background(), 60*time.Second)
			defer cancel()
			ctx = restore
			if err = apply(previous, previousServers); err != nil {
				return before, errors.New("зашифрованный DNS не ответил, а вернуть прежние настройки не удалось: выберите «Как у роутера» ещё раз")
			}
			return before, errors.New("этот DNS не ответил с вашего роутера. Прежние настройки возвращены")
		}
	}
	current, err := c.read()
	if err != nil {
		return DNSView{}, err
	}
	return readDNS(current.doc), nil
}

// MountDNS exposes the DNS choice of the core.
func (c *Controller) MountDNS(r chi.Router) {
	answer := func(w http.ResponseWriter, status int, body interface{}) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(body)
	}
	r.Get("/dns", func(w http.ResponseWriter, r *http.Request) {
		view, err := c.DNS()
		if err != nil {
			answer(w, http.StatusServiceUnavailable, map[string]string{"error": err.Error()})
			return
		}
		answer(w, http.StatusOK, view)
	})
	r.Put("/dns", func(w http.ResponseWriter, r *http.Request) {
		var wanted DNSSettings
		r.Body = http.MaxBytesReader(w, r.Body, 8<<10)
		if json.NewDecoder(r.Body).Decode(&wanted) != nil {
			answer(w, http.StatusBadRequest, map[string]string{"error": "некорректный запрос"})
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 120*time.Second)
		defer cancel()
		view, err := c.SetDNS(ctx, wanted)
		if err != nil {
			answer(w, http.StatusBadRequest, map[string]interface{}{"error": err.Error(), "dns": view})
			return
		}
		answer(w, http.StatusOK, view)
	})
}
