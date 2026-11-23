package cardcontroller

import (
	"context"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"xkeen-panel/internal/models"
	"xkeen-panel/internal/xkeen"
)

type ServiceRouteHealth = models.ServiceRouteHealth

// ProbeServiceRoutes checks every distinct VPN route the cards use now, once
// per route and the way ProbeDefault checks the default one: a URL test
// through the card's own proxy in Mihomo. A route the default route shares is
// left out, its check already covers it. Controller errors yield no results:
// they say nothing about the routes themselves.
func (c *Controller) ProbeServiceRoutes(ctx context.Context, checkURL string) []ServiceRouteHealth {
	c.mu.Lock()
	p, err := c.read()
	var live map[string]selector
	if err == nil {
		live, err = p.api.selectors(ctx)
	}
	skip := ""
	if err == nil {
		skip = c.defaultRoute(p, live).probeTarget
	}
	c.mu.Unlock()
	if err != nil {
		return nil
	}
	routes := map[string]*ServiceRouteHealth{}
	order := []string{}
	for service, key := range p.assigned {
		if service == defaultID || key == directTarget {
			continue
		}
		endpoint := live[cardPrefix+service].Now
		if !strings.HasPrefix(endpoint, nodePrefix) || endpoint == skip {
			continue
		}
		route := routes[endpoint]
		if route == nil {
			route = &ServiceRouteHealth{Pool: p.pool(key) != nil, Latency: -1}
			routes[endpoint] = route
			order = append(order, endpoint)
		}
		route.Services = append(route.Services, serviceTitle(service))
	}
	sort.Strings(order)
	results := make([]ServiceRouteHealth, len(order))
	var wg sync.WaitGroup
	for i, endpoint := range order {
		wg.Add(1)
		go func(i int, endpoint string) {
			defer wg.Done()
			route := *routes[endpoint]
			sort.Strings(route.Services)
			path := "/proxies/" + url.PathEscape(endpoint) + "/delay?timeout=8000&url=" + url.QueryEscape(checkURL)
			for attempt := 0; attempt < 2 && !route.OK; attempt++ {
				// A miss during a reload of Mihomo fails at once; the second
				// try waits for the reload to finish instead of failing too.
				if attempt > 0 {
					select {
					case <-ctx.Done():
						results[i] = route
						return
					case <-time.After(3 * time.Second):
					}
				}
				var result struct{ Delay int }
				if p.api.request(ctx, "GET", path, nil, &result) == nil && result.Delay > 0 {
					route.OK, route.Latency = true, result.Delay
				}
			}
			results[i] = route
		}(i, endpoint)
	}
	wg.Wait()
	return results
}

func serviceTitle(id string) string {
	if name := groupNames[id]; name != "" {
		return name
	}
	for _, service := range xkeen.CustomServices() {
		if service.ID == id {
			return service.Name
		}
	}
	return id
}
