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

// Configurator output may quote integer arguments even when JSON commands
// accept a numeric port. Both representations denote the same TCP port.
type rciPort uint16

func (p *rciPort) UnmarshalJSON(raw []byte) error {
	var value json.Number
	if err := json.Unmarshal(raw, &value); err != nil {
		return err
	}
	port, err := strconv.ParseUint(string(value), 10, 16)
	if err != nil || port == 0 {
		return errors.New("некорректный номер порта в ответе Netcraze")
	}
	*p = rciPort(port)
	return nil
}

type proxyRule struct {
	Domain struct {
		NDNS   bool   `json:"ndns"`
		Domain string `json:"domain"`
	} `json:"domain"`
	Upstream struct {
		Protocol string  `json:"proto"`
		Address  string  `json:"upstream"`
		Port     rciPort `json:"port"`
	} `json:"upstream"`
	Level        map[string]json.RawMessage `json:"security-level"`
	PreserveHost bool                       `json:"preserve-host"`
}

type routerHTTP struct {
	SSL struct {
		Enable bool
		Port   rciPort
	} `json:"ssl"`
	Level struct{ Public, Private, Protected bool } `json:"security-level"`
}

func (c *Client) readPanelHTTP(ctx context.Context) (routerHTTP, error) {
	var h routerHTTP
	err := c.doContext(ctx, http.MethodGet, "show/rc/ip/http", nil, &h)
	if err != nil {
		return h, err
	}
	if !h.SSL.Enable || h.SSL.Port == 0 {
		return h, errors.New("в Netcraze не настроен порт управления по HTTPS")
	}
	return h, nil
}

// show/ndns is the latest confirmed name. No domain is inferred solely from
// a Host request header, nor by looking up a similarly named DNS record.
func (c *Client) panelDomain(ctx context.Context) (string, error) {
	var s struct {
		Name, Domain string
		Booked       json.RawMessage
	}
	if err := c.doContext(ctx, http.MethodGet, "show/ndns", nil, &s); err != nil {
		return "", err
	}
	if s.Name == "" && s.Domain == "" && (len(s.Booked) == 0 || string(s.Booked) == `""` || string(s.Booked) == "false" || string(s.Booked) == "null") {
		return "", nil
	}
	if s.Domain == "" || !dnsLabel.MatchString(s.Name) {
		return "", errors.New("роутер не подтвердил имя CrazeDNS")
	}
	switch s.Domain {
	case "netcraze.link", "netcraze.pro", "netcraze.club", "crazedns.ru", "keenetic.link", "keenetic.pro", "keenetic.name", "keenetic.io", "keenetic.net", "mykeenetic.net", "mykeenetic.com":
		return s.Name + "." + s.Domain, nil
	}
	return "", errors.New("роутер вернул неизвестную доменную зону CrazeDNS")
}

func panelOrigin(domain string, port rciPort) string {
	host := panelProxyName + "." + domain
	if port != 443 {
		host = net.JoinHostPort(host, strconv.Itoa(int(port)))
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

func (c *Client) panelProxy(ctx context.Context) (*proxyRule, error) {
	var rules map[string]proxyRule
	if err := c.doContext(ctx, http.MethodGet, "show/sc/ip/http/proxy", nil, &rules); err != nil {
		return nil, err
	}
	p, exists := rules[panelProxyName]
	if !exists {
		return nil, nil
	}
	return &p, nil
}

func (p *proxyRule) private() bool {
	private := string(p.Level["private"])
	if private != "true" && private != `"private"` {
		return false
	}
	for _, key := range []string{"public", "protected"} {
		if value := p.Level[key]; len(value) != 0 && string(value) != "false" {
			return false
		}
	}
	return true
}

func (p *proxyRule) matches(ip string, port int) bool {
	return p != nil && p.private() && p.Domain.NDNS && p.Domain.Domain == "" && p.Upstream.Protocol == "http" && p.Upstream.Address == ip && int(p.Upstream.Port) == port
}

func (c *Client) createPanelProxy(ctx context.Context, ip string, port int) error {
	args := map[string]any{
		"name": panelProxyName, "domain": map[string]any{"ndns": true, "no": false},
		"upstream":       map[string]any{"proto": "http", "upstream": ip, "port": strconv.Itoa(port)},
		"security-level": map[string]any{"private": "private", "no": false},
		"preserve-host":  true, "auth": false,
	}
	_, commandErr := c.panelCommand(ctx, "ip/http/proxy", args)
	check, cancel := context.WithTimeout(context.WithoutCancel(ctx), 6*time.Second)
	defer cancel()
	p, err := c.panelProxy(check)
	if err != nil {
		return errors.Join(commandErr, err)
	}
	if p.matches(ip, port) {
		return nil
	}
	err = errors.New("роутер не подтвердил локальную привязку HTTPS к панели")
	// A multi-field RCI write can leave only some subcommands applied. Remove
	// our new incomplete rule if it still carries our LAN-only boundaries.
	if p != nil && p.private() && p.Domain.NDNS && p.Domain.Domain == "" &&
		(p.Upstream.Protocol == "" || p.Upstream.Protocol == "http") &&
		(p.Upstream.Address == "" || p.Upstream.Address == ip) &&
		(p.Upstream.Port == 0 || int(p.Upstream.Port) == port) {
		_, cleanupErr := c.panelCommand(check, "ip/http/proxy", map[string]any{"name": panelProxyName, "no": true})
		err = errors.Join(err, cleanupErr)
	}
	return errors.Join(commandErr, err)
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
	p, err := c.panelProxy(ctx)
	if err != nil {
		return origin, err
	}
	if p != nil && !p.matches(lanIP, port) {
		return origin, errors.New("имя panel уже занято другим правилом доступа Netcraze")
	}
	hasHost, err := c.hostRecord(ctx, host, lanIP)
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
	if p == nil {
		if err = c.createPanelProxy(ctx, lanIP, port); err != nil {
			return origin, err
		}
	}
	if !hasHost {
		if _, err = c.panelCommand(ctx, "ip/host", map[string]string{"domain": host, "address": lanIP}); err != nil {
			return origin, err
		}
	}
	p, err = c.panelProxy(ctx)
	if err != nil {
		return origin, err
	}
	if !p.matches(lanIP, port) {
		return origin, errors.New("роутер не подтвердил локальную привязку HTTPS к панели")
	}
	ok, err := c.hostRecord(ctx, host, lanIP)
	if err != nil || !ok {
		return origin, errors.New("роутер не подтвердил домашний адрес DNS панели")
	}
	// Also persist successful partial work from an interrupted earlier retry.
	if err = save(); err != nil {
		return origin, err
	}
	return origin, nil
}
