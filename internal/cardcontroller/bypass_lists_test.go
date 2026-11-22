package cardcontroller

import (
	"path/filepath"
	"strings"
	"testing"

	"xkeen-panel/internal/models"
	"xkeen-panel/internal/xkeen"
)

func TestBypassListCanNotCarryAProtectedCardPastTheCore(t *testing.T) {
	dir := t.TempDir()
	c := New(filepath.Join(dir, "config.yaml"), dir, xkeen.Runtime{}, func() []models.Server { return nil })
	guard := c.newExclusionGuard(profile{assigned: map[string]string{}, doc: map[string]interface{}{}})

	refused := map[string][]string{
		"port_exclude": {"443\n", "80\n", "27015\n400:500\n", "1:65535\n"},
		// Inside, equal to and around a published Claude network.
		"ip_exclude": {"160.79.104.10/32\n", "160.79.104.0/23\n", "160.0.0.0/8\n", "203.0.113.0/24\n2607:6bc0::1/128\n"},
	}
	for name, lists := range refused {
		for _, list := range lists {
			if err := guard.bypassConflict(name, list); err == nil {
				t.Errorf("%s accepted %q", name, list)
			}
		}
	}
	if err := guard.bypassConflict("ip_exclude", "160.79.104.10/32\n"); err == nil || !strings.Contains(err.Error(), "Claude") {
		t.Errorf("the refusal does not name the card: %v", err)
	}

	allowed := map[string]string{
		"port_exclude":  "#443\n27015\n596:599\n",
		"ip_exclude":    "#160.79.104.0/23\n203.0.113.0/24\n2001:db8::/32\n",
		"port_proxying": "80\n443\n", // checked elsewhere, whatever the cards say
	}
	for name, list := range allowed {
		if err := guard.bypassConflict(name, list); err != nil {
			t.Errorf("%s refused %q: %v", name, list, err)
		}
	}
}

func TestBypassListIsFreeWhenNoCardIsProtected(t *testing.T) {
	dir := t.TempDir()
	c := New(filepath.Join(dir, "config.yaml"), dir, xkeen.Runtime{}, func() []models.Server { return nil })
	services := map[string]interface{}{}
	for _, card := range xkeen.ServiceNames() {
		services[card.ID] = "off"
	}
	guard := c.newExclusionGuard(profile{assigned: map[string]string{}, doc: map[string]interface{}{
		killSwitchKey: map[string]interface{}{"enabled": false, "services": services},
	}})
	for name, list := range map[string]string{"port_exclude": "443\n80\n", "ip_exclude": "160.79.104.0/23\n"} {
		if err := guard.bypassConflict(name, list); err != nil {
			t.Errorf("%s refused with every kill switch off: %v", name, err)
		}
	}
}
