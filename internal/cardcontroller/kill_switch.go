package cardcontroller

import (
	"context"
	"errors"
	"strings"
	"time"

	"xkeen-panel/installer"
	"xkeen-panel/internal/xkeen"
)

const killSwitchKey = "x-xkeen-panel-kill-switch"
const failoverPrefix = cardPrefix + "failover-"

func fallbackSelection(name string, live map[string]selector) string {
	if strings.HasPrefix(name, failoverPrefix) {
		return live[name].Now
	}
	return name
}

type KillSwitch struct {
	Enabled  bool              `json:"enabled" yaml:"enabled"`
	Services map[string]string `json:"services" yaml:"services"`
}

func readKillSwitch(doc map[string]interface{}) (KillSwitch, error) {
	policy := KillSwitch{Enabled: true, Services: map[string]string{}}
	raw, ok := doc[killSwitchKey]
	if !ok {
		return policy, nil
	}
	config := object(raw)
	enabled, ok := config["enabled"].(bool)
	services, valid := config["services"].(map[string]interface{})
	if !ok || !valid {
		return policy, errors.New("повреждены настройки Kill switch")
	}
	policy.Enabled = enabled
	for id, value := range services {
		mode := str(value)
		if xkeen.CustomServiceID(id) && !xkeen.IsCustomService(id) {
			continue // The owner's card was removed; its setting goes with the next save.
		}
		if !knownCard(id) || (mode != "on" && mode != "off" && mode != "inherit") {
			return policy, errors.New("повреждена настройка Kill switch сервиса")
		}
		policy.Services[id] = mode
	}
	return policy, nil
}

// A service follows the router setting only when the user chooses inherit.
func (p KillSwitch) Protects(id string) bool {
	if !knownCard(id) || p.Services[id] == "inherit" {
		return p.Enabled
	}
	return p.Services[id] != "off"
}

func (p KillSwitch) hasProtectedRoute(config profile) bool {
	// An unassigned Claude card blocks its traffic until a VPN is selected.
	// Removing interception would release those blocked connections.
	if p.Enabled || p.Protects("claude") {
		return true
	}
	inherited := false
	for _, card := range xkeen.ServiceNames() {
		id := card.ID
		if !p.Protects(id) || config.assigned[id] == directTarget {
			continue
		}
		if config.assigned[id] != "" {
			return true
		}
		inherited = true
	}
	if !inherited {
		return false
	}
	registry, err := readRefilter(config.doc)
	if err != nil || registry.Enabled || config.assigned[defaultID] != "" {
		return true
	}
	// Generated rules have an owner rule or card assignment as their source.
	// A profile whose owner rules all lead directly to MATCH,DIRECT offers no
	// VPN route to its unassigned cards. Treat ambiguous profiles conservatively.
	hasDirectDefault := false
	for _, rule := range namesOf(config.doc["rules"]) {
		fields, end := targetPart(rule)
		switch {
		case end < 1:
			return true
		case strings.HasPrefix(fields[end], cardPrefix):
			continue
		case fields[end] != "DIRECT":
			return true
		case end == 1 && fields[0] == "MATCH":
			hasDirectDefault = true
		}
	}
	return !hasDirectDefault
}

func (c *Controller) KillSwitch() (KillSwitch, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	p, err := c.read()
	if err != nil {
		return KillSwitch{}, err
	}
	return readKillSwitch(p.doc)
}

// Only the requested field is edited while holding the same lock as route
// assignments, subscription updates and health-driven reconfiguration.
func (c *Controller) SetKillSwitch(ctx context.Context, enabled *bool, id, mode string) (KillSwitch, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if enabled != nil && (id != "" || mode != "") || enabled == nil && (!knownCard(id) || mode != "on" && mode != "off" && mode != "inherit") {
		return KillSwitch{}, errors.New("неверная настройка Kill switch")
	}
	p, err := c.read()
	if err != nil {
		return KillSwitch{}, err
	}
	policy, err := readKillSwitch(p.doc)
	if err != nil {
		return KillSwitch{}, err
	}
	before := policy.Protects("claude")
	if enabled != nil {
		policy.Enabled = *enabled
	} else {
		policy.Services[id] = mode
	}
	values := map[string]interface{}{}
	for service, setting := range policy.Services {
		values[service] = setting
	}
	after := policy.Protects("claude")
	if id != "" && policy.Protects(id) {
		c.pending[id] = true
	}
	if after && !before {
		if err := installer.SetInstalledClaudeFirewall(ctx, true); err != nil {
			return KillSwitch{}, err
		}
	}
	view, err := c.apply(ctx, "", "", func(p *profile) error {
		p.doc[killSwitchKey] = map[string]interface{}{"enabled": policy.Enabled, "services": values}
		return nil
	})
	if err != nil {
		if after && !before {
			// c.apply can fail after publishing its validated configuration.
			// Restore the packet filter only if the disk policy is still OFF.
			if disk, readErr := c.read(); readErr == nil {
				live, parseErr := readKillSwitch(disk.doc)
				if parseErr == nil && !live.Protects("claude") {
					recovery, cancel := context.WithTimeout(context.Background(), 20*time.Second)
					defer cancel()
					if firewallErr := installer.SetInstalledClaudeFirewall(recovery, false); firewallErr != nil {
						return KillSwitch{}, firewallErr
					}
				}
			}
		}
		return KillSwitch{}, err
	}
	// Changing OFF is intentionally last. A crash at this boundary leaves
	// stricter kernel rules until the next reconciliation.
	if !after && (before || installer.ClaudeFirewallNeedsSync(false)) {
		err = installer.SetInstalledClaudeFirewall(ctx, false)
	}
	if err == nil && view.ActiveConnectionsPending {
		err = errors.New("правила обновлены, завершение прежних соединений пока не подтверждено")
	}
	return policy, err
}
