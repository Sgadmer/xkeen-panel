package cardcontroller

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"time"

	"xkeen-panel/internal/xkeen"
)

// ProxyAccess is returned only to the authenticated caller explicitly enabling
// a service's dedicated proxy. Never send it with the catalogue or in a log.
type ProxyAccess struct {
	Address  string `json:"address"`
	Username string `json:"username"`
	Password string `json:"password"`
}

func (c *Controller) EnableClaudeProxy(ctx context.Context, lanIP string) (ProxyAccess, error) {
	return c.EnableServiceProxy(ctx, lanIP, "claude")
}

func serviceInbound(id string) string {
	if id == "claude" {
		return xkeen.ClaudeClientInbound
	}
	return "xkp-" + id + "-client"
}

func dedicatedGroup(id string) string { return cardPrefix + "bound-" + id }

func (c *Controller) EnableServiceProxy(ctx context.Context, lanIP, id string) (ProxyAccess, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if groupNames[id] == "" {
		return ProxyAccess{}, errors.New("неизвестная карточка")
	}
	ip, err := netip.ParseAddr(lanIP)
	if err != nil || (!ip.IsPrivate() && !ip.IsLoopback()) {
		return ProxyAccess{}, errors.New("нужен локальный IP этого роутера")
	}
	var access ProxyAccess
	_, err = c.apply(ctx, "", "", func(p *profile) error {
		if !validHash(p.assigned[id]) {
			return errors.New("сначала назначьте карточке VPN из подписки")
		}
		if raw, exists := p.doc["listeners"]; exists && list(raw) == nil {
			return errors.New("неподдерживаемый список входов Mihomo")
		}
		for _, raw := range list(p.doc["listeners"]) {
			m := object(raw)
			if str(m["name"]) != serviceInbound(id) {
				continue
			}
			users := list(m["users"])
			port, ok := m["port"].(int)
			forced := str(m["proxy"])
			legacy := id == "claude" && forced == cardPrefix+"claude"
			if str(m["listen"]) != ip.String() || str(m["type"]) != "http" || (forced != dedicatedGroup(id) && !legacy) || !ok || port < 1 || port > 65535 || len(users) != 1 {
				return errors.New("выделенный вход карточки занят другой конфигурацией")
			}
			account := object(users[0])
			if str(account["username"]) != id || len(str(account["password"])) < 32 {
				return errors.New("выделенный вход карточки требует отдельной учётной записи")
			}
			access = ProxyAccess{net.JoinHostPort(ip.String(), strconv.Itoa(port)), id, str(account["password"])}
			return nil
		}
		// Ask the OS for a currently free port bound to the actual LAN IP. The
		// core later owns the listener. No user-supplied hostname or wildcard.
		listener, err := net.Listen("tcp", net.JoinHostPort(ip.String(), "0"))
		if err != nil {
			return errors.New("этот локальный адрес недоступен на роутере")
		}
		port := listener.Addr().(*net.TCPAddr).Port
		listener.Close()
		var key [32]byte
		if _, err = rand.Read(key[:]); err != nil {
			return err
		}
		access = ProxyAccess{net.JoinHostPort(ip.String(), strconv.Itoa(port)), id, base64.RawURLEncoding.EncodeToString(key[:])}
		p.doc["listeners"] = append(list(p.doc["listeners"]), map[string]interface{}{"name": serviceInbound(id), "type": "http", "listen": ip.String(), "port": port, "proxy": dedicatedGroup(id), "users": []interface{}{map[string]interface{}{"username": access.Username, "password": access.Password}}})
		return nil
	})
	if err != nil {
		return ProxyAccess{}, err
	}
	// Require the proxy to reject an unauthenticated CONNECT before showing its
	// login. Use a synthetic target and never send the account to this probe.
	conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", access.Address)
	if err != nil {
		return ProxyAccess{}, errors.New("выделенный вход карточки не открыл порт")
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err = conn.Write([]byte("CONNECT invalid.invalid:443 HTTP/1.1\r\nHost: invalid.invalid:443\r\n\r\n")); err != nil {
		return ProxyAccess{}, err
	}
	res, err := http.ReadResponse(bufio.NewReader(conn), &http.Request{Method: "CONNECT"})
	if err != nil || res.StatusCode != http.StatusProxyAuthRequired {
		return ProxyAccess{}, errors.New("запрос без пароля не получил обязательный ответ 407")
	}
	res.Body.Close()
	return access, nil
}
