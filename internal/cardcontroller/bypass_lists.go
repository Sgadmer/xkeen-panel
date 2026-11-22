package cardcontroller

import (
	"fmt"

	"xkeen-panel/internal/xkeen"
)

// The XKeen lists send traffic to the provider before the core sees it: no
// rule, card or kill switch applies to it. A list that would carry the traffic
// of a card with kill switch on past the core is refused, by the same rule as
// an exclusion:
//
//   - port_exclude may not name 443 or 80, the ports of ordinary sites and
//     applications, while any card is protected;
//   - ip_exclude may not overlap the networks of a protected card.

// CheckBypassList is called before an XKeen list is written.
func (c *Controller) CheckBypassList(name, content string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	p, err := c.read()
	if err != nil {
		return err
	}
	return c.newExclusionGuard(p).bypassConflict(name, content)
}

func (g exclusionGuard) bypassConflict(name, content string) error {
	switch name {
	case "port_exclude":
		for _, card := range g.cards {
			if !card.protected {
				continue
			}
			for _, port := range []int{443, 80} {
				if xkeen.PortListCovers(content, port) {
					return fmt.Errorf("порт %d — это обычные сайты и приложения. Пока хотя бы у одной карточки включён kill switch (сейчас — «%s»), пустить его в обход VPN нельзя. Уберите порт из списка или сначала выключите kill switch", port, card.name)
				}
			}
			break
		}
	case "ip_exclude":
		for _, entry := range xkeen.ListEntries(content) {
			exclusion := xkeen.Exclusion{Type: "ip", Value: entry}
			for _, card := range g.cards {
				if card.protected && card.touches(exclusion) {
					return fmt.Errorf("адрес %s относится к карточке «%s», у которой включён kill switch. В обход VPN его пустить нельзя: выберите маршрут в карточке или сначала выключите её kill switch", entry, card.name)
				}
			}
		}
	}
	return nil
}
