package keenetic

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

var (
	ErrDeviceName     = errors.New("укажите имя устройства без управляющих символов")
	ErrDeviceMAC      = errors.New("неверный MAC-адрес устройства")
	ErrDeviceMissing  = errors.New("устройство больше не отображается на роутере")
	ErrDeviceNameUsed = errors.New("это имя уже используется другим устройством")
)

// On current KeeneticOS, the keys in show/{rc,sc}/known/host are the
// user-entered names. MAC addresses, which identify the device, are values.
func (c *Client) registeredNames(ctx context.Context, path string) (map[string]string, error) {
	var raw json.RawMessage
	if err := c.doContext(ctx, http.MethodGet, path, nil, &raw); err != nil {
		return nil, err
	}
	type host struct{ Name, MAC string }
	byMAC := map[string]string{}
	add := func(h host) error {
		if !validDeviceMAC(h.MAC) || h.Name == "" {
			return errors.New("роутер вернул неполную запись о регистрации устройства")
		}
		byMAC[strings.ToLower(h.MAC)] = h.Name
		return nil
	}
	if len(raw) > 0 && raw[0] == '[' {
		var hosts []host
		if err := json.Unmarshal(raw, &hosts); err != nil {
			return nil, err
		}
		for _, h := range hosts {
			if err := add(h); err != nil {
				return nil, err
			}
		}
		return byMAC, nil
	}
	var hosts map[string]host
	if err := json.Unmarshal(raw, &hosts); err != nil || hosts == nil {
		return nil, errors.New("роутер вернул неизвестный формат реестра устройств")
	}
	for name, h := range hosts {
		if h.Name == "" {
			h.Name = name
		}
		if err := add(h); err != nil {
			return nil, err
		}
	}
	return byMAC, nil
}

func validDeviceMAC(mac string) bool {
	addr, err := net.ParseMAC(mac)
	return err == nil && len(addr) == 6 && strings.EqualFold(mac, addr.String())
}

// RenameHost also registers an observed, unregistered device. Its policy
// continues to follow its network segment, as it did before registration.
func (c *Client) RenameHost(ctx context.Context, mac, name string) error {
	if !validDeviceMAC(mac) {
		return ErrDeviceMAC
	}
	if strings.IndexFunc(name, unicode.IsControl) != -1 {
		return ErrDeviceName
	}
	name = strings.TrimSpace(name)
	if name == "" || !utf8.ValidString(name) {
		return ErrDeviceName
	}
	mac = strings.ToLower(mac)
	names, err := c.registeredNames(ctx, "show/rc/known/host")
	if err != nil {
		return err
	}
	for other, used := range names {
		if used == name && other != mac {
			return ErrDeviceNameUsed
		}
	}
	if names[mac] == "" {
		hosts, err := c.Hosts()
		if err != nil {
			return err
		}
		found := false
		for _, h := range hosts {
			if strings.EqualFold(h.MAC, mac) {
				found = true
				break
			}
		}
		if !found {
			return ErrDeviceMissing
		}
	}
	if names[mac] != name {
		if err := c.post("known/host", map[string]any{"mac": mac, "name": name}); err != nil {
			return err
		}
		if names[mac] == "" {
			if err := c.followSegment(mac); err != nil {
				if undo := c.post("known/host", map[string]any{"mac": mac, "no": true}); undo != nil {
					return fmt.Errorf("роутер не принял политику сегмента: %v; отменить регистрацию не удалось: %w", err, undo)
				}
				return fmt.Errorf("не удалось сохранить политику сегмента при регистрации: %w", err)
			}
		}
	}
	return c.saveHostRegistration(ctx, mac, name)
}

func (c *Client) followSegment(mac string) error {
	if err := c.post("ip/hotspot/host", map[string]any{"mac": mac, "conform": true}); err != nil {
		return err
	}
	cfg, err := c.HotspotConfig()
	if err != nil {
		return err
	}
	for _, host := range cfg.Host {
		if strings.EqualFold(host.MAC, mac) && host.Conform && policyName(host.Policy) == "" {
			return nil
		}
	}
	return errors.New("роутер не подтвердил политику сегмента")
}

func (c *Client) ForgetHost(ctx context.Context, mac string) error {
	// An unqualified "no known host" clears every saved host.
	if !validDeviceMAC(mac) {
		return ErrDeviceMAC
	}
	mac = strings.ToLower(mac)
	names, err := c.registeredNames(ctx, "show/rc/known/host")
	if err != nil {
		return err
	}
	if names[mac] != "" {
		if err := c.post("known/host", map[string]any{"mac": mac, "no": true}); err != nil {
			return err
		}
	}
	return c.saveHostRegistration(ctx, mac, "")
}

func (c *Client) saveHostRegistration(ctx context.Context, mac, want string) error {
	// A view can close immediately after the native command. Finish persisting
	// an accepted change even when its original HTTP request goes away.
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 12*time.Second)
	defer cancel()
	// RCI may accept a command without applying it. Check running config
	// before saving; a still-connected forgotten device can remain in Hosts.
	running, err := c.registeredNames(ctx, "show/rc/known/host")
	if err != nil {
		return err
	}
	if running[mac] != want {
		return errors.New("роутер не подтвердил изменение регистрации устройства")
	}
	if err := c.post("system/configuration/save", map[string]any{}); err != nil {
		return fmt.Errorf("изменение применено, но роутер не подтвердил сохранение: %w", err)
	}
	// Save runs asynchronously. Check only this client's startup record.
	for {
		saved, err := c.registeredNames(ctx, "show/sc/known/host")
		if err != nil {
			return fmt.Errorf("не удалось проверить сохранение регистрации: %w", err)
		}
		if saved[mac] == want {
			return nil
		}
		select {
		case <-ctx.Done():
			return errors.New("роутер пока не подтвердил сохранение регистрации")
		case <-time.After(150 * time.Millisecond):
		}
	}
}
