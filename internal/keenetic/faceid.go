package keenetic

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const panelDNSZone = "netcraze.link"
const panelProxyName = "panel"

var dnsLabel = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)

type proxyRule struct {
	Name   string `json:"name"`
	Domain struct {
		NDNS bool `json:"ndns"`
	} `json:"domain"`
	Upstream struct {
		HTTP bool   `json:"http"`
		IP   string `json:"ip"`
		Port int    `json:"port"`
	} `json:"upstream"`
	Level struct {
		Public bool `json:"public"`
	} `json:"security-level"`
	PreserveHost bool `json:"preserve-host"`
}

type routerHTTP struct {
	Proxy []proxyRule `json:"proxy"`
	SSL   struct {
		Enable bool
		Port   int
	} `json:"ssl"`
	Level struct{ Public, Private, Protected bool } `json:"security-level"`
}

func (c *Client) readPanelHTTP(ctx context.Context) (routerHTTP, error) {
	var h routerHTTP
	err := c.doContext(ctx, http.MethodGet, "show/rc/ip/http", nil, &h)
	if err != nil {
		return h, err
	}
	if !h.SSL.Enable || h.SSL.Port < 1 || h.SSL.Port > 65535 {
		return h, errors.New("в Netcraze не настроен порт управления по HTTPS")
	}
	return h, nil
}

// show/ndns is the latest confirmed name. No domain is inferred solely from
// a Host request header, nor by looking up a similarly named DNS record.
func (c *Client) panelDomain(ctx context.Context) (string, error) {
	var s struct{ Name, Booked, Domain string }
	if err := c.doContext(ctx, http.MethodGet, "show/ndns", nil, &s); err != nil {
		return "", err
	}
	if s.Name == "" && s.Booked == "" && s.Domain == "" {
		return "", nil
	}
	label := s.Booked
	if label == "" {
		label = s.Name
	}
	if s.Domain == "" || !dnsLabel.MatchString(label) {
		return "", errors.New("роутер не подтвердил имя CrazeDNS")
	}
	switch s.Domain {
	case "netcraze.link", "netcraze.pro", "netcraze.club", "crazedns.ru", "keenetic.link", "keenetic.pro", "keenetic.name", "keenetic.io", "keenetic.net", "mykeenetic.net", "mykeenetic.com":
		return label + "." + s.Domain, nil
	}
	return "", errors.New("роутер вернул неизвестную доменную зону CrazeDNS")
}

func panelOrigin(domain string, port int) string {
	host := panelProxyName + "." + domain
	if port != 443 {
		host = net.JoinHostPort(host, strconv.Itoa(port))
	}
	return "https://" + host
}

func (c *Client) PanelHTTPSPlan(ctx context.Context, label string) (string, bool, error) {
	if !dnsLabel.MatchString(label) {
		return "", false, errors.New("некорректное имя для CrazeDNS")
	}
	h, err := c.readPanelHTTP(ctx)
	if err != nil {
		return "", false, err
	}
	domain, err := c.panelDomain(ctx)
	if err != nil {
		return "", false, err
	}
	if domain == "" {
		domain = label + "." + panelDNSZone
	}
	return panelOrigin(domain, h.SSL.Port), h.Level.Public || h.Level.Protected, nil
}

// Some NDMS commands return {"continued":true} while their cloud request is
// pending. Never repeat the initial POST while polling its result.
func (c *Client) panelCommand(ctx context.Context, path string, args any) (map[string]any, error) {
	raw, err := json.Marshal(args)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	method := http.MethodPost
	for {
		var result any
		if err := c.doContext(ctx, method, path, raw, &result); err != nil {
			return nil, err
		}
		if msg := statusError(result); msg != "" {
			return nil, fmt.Errorf("Netcraze: %s", msg)
		}
		data, isMap := result.(map[string]any)
		if !isMap {
			if _, isList := result.([]any); isList {
				return nil, nil
			}
			return nil, errors.New("неожиданный ответ Netcraze")
		}
		if failed, exists := data["failed"]; exists && failed != false {
			return data, fmt.Errorf("CrazeDNS отклонил команду %s", path)
		}
		if data["continued"] != true {
			return data, nil
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(500 * time.Millisecond):
		}
		method, raw = http.MethodGet, nil
	}
}

func isCandidateAvailable(d map[string]any, name string) bool {
	list, _ := d["list"].(map[string]any)
	items, _ := list["item"].([]any)
	for _, i := range items {
		v, _ := i.(map[string]any)
		if v["name"] == name && v["domain"] == panelDNSZone && v["available"] == true && v["acme"] == true {
			return true
		}
	}
	return false
}

func proxyConfigured(h routerHTTP, ip string, port int) (bool, error) {
	for _, p := range h.Proxy {
		if p.Name != panelProxyName {
			continue
		}
		if !p.Domain.NDNS || !p.Upstream.HTTP || p.Upstream.IP != ip || p.Upstream.Port != port || p.Level.Public {
			return false, errors.New("имя panel уже занято другим правилом доступа Netcraze")
		}
		return true, nil
	}
	return false, nil
}

type hostRecord struct{ Domain, Address string }

func (c *Client) hostRecord(ctx context.Context, host, ip string) (bool, error) {
	var records []hostRecord
	if err := c.doContext(ctx, http.MethodGet, "show/rc/ip/host", nil, &records); err != nil {
		return false, err
	}
	present := false
	for _, record := range records {
		if !strings.EqualFold(strings.TrimSuffix(record.Domain, "."), host) {
			continue
		}
		if record.Address != ip {
			return false, errors.New("домашнее DNS-имя уже указывает на другое устройство")
		}
		present = true
	}
	return present, nil
}

func (c *Client) PreparePanelHTTPS(ctx context.Context, label, lanIP string, port int, admin ...string) (string, error) {
	if !dnsLabel.MatchString(label) {
		return "", errors.New("некорректное имя для CrazeDNS")
	}
	ip, err := netip.ParseAddr(lanIP)
	if err != nil || !ip.IsPrivate() || !ip.Is4() || port < 1 || port > 65535 {
		return "", errors.New("нужен адрес панели в домашней сети")
	}
	h, err := c.readPanelHTTP(ctx)
	if err != nil {
		return "", err
	}
	domain, err := c.panelDomain(ctx)
	if err != nil {
		return "", err
	}
	needsBooking := domain == ""
	if needsBooking {
		domain = label + "." + panelDNSZone
	}
	origin := panelOrigin(domain, h.SSL.Port)
	host := panelProxyName + "." + domain
	setProxy, err := proxyConfigured(h, lanIP, port)
	if err != nil {
		return origin, err
	}
	setHost, err := c.hostRecord(ctx, host, lanIP)
	if err != nil {
		return origin, err
	}
	restrict := h.Level.Public || h.Level.Protected
	if restrict && (len(admin) != 1 || admin[0] != "private") {
		return origin, errors.New("подтвердите ограничение доступа к управлению роутером домашней сетью")
	}
	if needsBooking {
		d, err := c.panelCommand(ctx, "ndns/check-name", map[string]string{"name": label})
		if err != nil {
			return origin, err
		}
		if !isCandidateAvailable(d, label) {
			return origin, errors.New("имя недоступно или CrazeDNS не подтвердил выпуск сертификата")
		}
	}
	save := func() error { _, err := c.panelCommand(ctx, "system/configuration/save", map[string]any{}); return err }
	if restrict {
		if _, err = c.panelCommand(ctx, "ip/http/security-level", map[string]bool{"private": true}); err != nil {
			return origin, err
		}
		updated, err := c.readPanelHTTP(ctx)
		if err != nil || updated.Level.Public || updated.Level.Protected || !updated.Level.Private {
			return origin, errors.New("роутер не подтвердил доступ к управлению только из домашней сети")
		}
		// Persist the approved boundary before booking a public name, even if
		// the user disconnects or the router reboots during certificate issue.
		if err = save(); err != nil {
			return origin, err
		}
	}
	if needsBooking {
		if _, err = c.panelCommand(ctx, "ndns/book-name", map[string]string{"name": label, "domain": panelDNSZone, "access": "cloud"}); err != nil {
			return origin, err
		}
		registered, err := c.panelDomain(ctx)
		if err != nil || registered != domain {
			return origin, errors.New("CrazeDNS обрабатывает регистрацию. Повторите проверку через минуту")
		}
	}
	if !setProxy {
		args := map[string]any{
			"name": panelProxyName, "domain": map[string]any{"ndns": true},
			"upstream":       map[string]any{"http": true, "ip": lanIP, "port": port},
			"security-level": map[string]bool{"private": true}, "preserve-host": true,
		}
		if _, err = c.panelCommand(ctx, "ip/http/proxy", args); err != nil {
			return origin, err
		}
	}
	if !setHost {
		if _, err = c.panelCommand(ctx, "ip/host", map[string]string{"domain": host, "address": lanIP}); err != nil {
			return origin, err
		}
	}
	h, err = c.readPanelHTTP(ctx)
	if err != nil {
		return origin, err
	}
	ok, err := proxyConfigured(h, lanIP, port)
	if err != nil || !ok {
		return origin, errors.New("роутер не подтвердил локальную привязку HTTPS к панели")
	}
	ok, err = c.hostRecord(ctx, host, lanIP)
	if err != nil || !ok {
		return origin, errors.New("роутер не подтвердил домашний адрес DNS панели")
	}
	// Also persist successful partial work from an interrupted earlier retry.
	if err = save(); err != nil {
		return origin, err
	}
	return origin, nil
}
