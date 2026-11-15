package cardcontroller

import (
	"context"
	"errors"
)

// This is a fixed policy group, not a caller-provided list: Claude must never
// be omitted when the client asks for one consistent AI/telemetry exit.
var aiGroupServices = [...]string{"claude", "openai", "ai", "analytics"}

// SetAIGroup prepares all four assignments in one candidate and publishes one
// verified reload. Any validation/preparation/reload failure keeps the previous
// complete configuration rather than leaving a partially changed group.
func (c *Controller) SetAIGroup(ctx context.Context, target string) (View, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if target == "" {
		target = defaultServiceTarget("claude")
	}
	for _, id := range aiGroupServices {
		if !validAssignment(id, target) {
			return View{}, errors.New("для группы AI и аналитики выберите VPN-сервер или пул; прямой маршрут недоступен")
		}
	}
	// A required-target metadata transaction also refuses to discard an
	// unrelated working route if its worker cannot be prepared during reload.
	return c.apply(ctx, "", target, func(p *profile) error {
		if countryPoolCodes[target] != "" && len(p.pool(target).members(c.poolNodes(c.catalog()))) == 0 {
			return errors.New("в выбранном пуле страны нет доступных серверов")
		}
		if _, managed := p.doc[stateKey]; !managed {
			p.doc[serviceAutoKey] = true
		}
		for _, id := range aiGroupServices {
			p.assigned[id] = target
		}
		return nil
	})
}
