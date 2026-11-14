package cardcontroller

import (
	"context"
	"strings"

	"xkeen-panel/internal/models"
	"xkeen-panel/internal/xkeen"
)

type workerSelection struct {
	label       string
	pool        bool
	poolCountry string
	exit        ConnectionExit
}

// Each call samples each distinct Xray worker at most once, even when many
// service rules share the default outbound. Generation and port identify the
// running worker's private observatory socket.
type workerSocket struct {
	generation string
	port       int
}

type workerSnapshot struct {
	ctx     context.Context
	rt      xkeen.Runtime
	profile profile
	proxies map[string]map[string]interface{}
	servers func() []models.Server
	catalog map[string]ConnectionExit
	members map[workerSocket]string
	read    func(context.Context, xkeen.Runtime, string, int) string
}

func newWorkerSnapshot(ctx context.Context, rt xkeen.Runtime, p profile, servers func() []models.Server, read func(context.Context, xkeen.Runtime, string, int) string) *workerSnapshot {
	proxies := map[string]map[string]interface{}{}
	for _, raw := range list(p.doc["proxies"]) {
		proxy := object(raw)
		proxies[str(proxy["name"])] = proxy
	}
	return &workerSnapshot{ctx: ctx, rt: rt, profile: p, proxies: proxies, servers: servers, read: read, members: map[workerSocket]string{}}
}

func (w *workerSnapshot) lookup(id string) ConnectionExit {
	if w.catalog == nil {
		w.catalog = diagnosticCatalog(w.servers())
	}
	return w.catalog[id]
}

func (w *workerSnapshot) resolve(tag string) workerSelection {
	rest, managed := strings.CutPrefix(tag, nodePrefix)
	id, generation, grouped := strings.Cut(rest, "-")
	if !managed || !validHash(id) {
		return workerSelection{}
	}
	if !grouped {
		exit := w.lookup(id)
		return workerSelection{label: exit.Name, exit: exit}
	}
	pool := w.profile.pool(id)
	if pool == nil || !validHash(generation) {
		return workerSelection{}
	}
	selection := workerSelection{label: publicRouteName(pool.Name, nil), pool: true, poolCountry: countryPoolCodes[id]}
	proxy := w.proxies[tag]
	port, _ := proxy["port"].(int)
	if str(proxy["server"]) != "127.0.0.1" || port <= 0 || port > 65535 {
		return selection
	}
	key := workerSocket{generation, port}
	member, cached := w.members[key]
	if !cached && w.ctx.Err() == nil {
		member = w.read(w.ctx, w.rt, generation, port)
		w.members[key] = member
	}
	if member != "" {
		selection.exit = w.lookup(member)
	}
	return selection
}

// Follow the reported active path. A load balancer chooses per connection;
// its Now field is insufficient to identify the next connection's exit.
func (w *workerSnapshot) current(group string, live map[string]selector, providerNode func(string) selector) *xkeen.CurrentServiceRoute {
	if group == "" {
		return nil
	}
	route := &xkeen.CurrentServiceRoute{Kind: "unknown"}
	seen := map[string]bool{}
	for tag := group; tag != "" && !seen[tag]; {
		seen[tag] = true
		node, ok := live[tag]
		if !ok && tag != group {
			node = providerNode(tag)
		}
		switch strings.ToLower(node.Type) {
		case "loadbalance", "load-balance", "relay":
			route.Pool = publicRouteName(tag, nil)
			return route
		case "urltest", "url-test", "fallback":
			if label := publicRouteName(tag, nil); label != "" {
				route.Pool = label
			}
		case "selector", "select":
		default:
			if node.Now != "" || len(node.All) != 0 {
				return route
			}
			exit := nativeConnectionExit(tag, node.Type)
			if strings.HasPrefix(tag, nodePrefix) && exit.Kind == "server" {
				worker := w.resolve(tag)
				if worker.pool || worker.exit.Kind != "server" {
					route.Pool = worker.label
					route.PoolCountry = worker.poolCountry
				}
				exit = worker.exit
			}
			switch exit.Kind {
			case "server":
				if label := publicRouteName(exit.Name, nil); label != "" {
					route.Kind, route.Name, route.Country, route.Source = "server", label, exit.Country, exit.Source
					route.DeclaredCountryPath = exit.DeclaredCountryPath
				}
			case "direct", "reject":
				route.Kind = exit.Kind
			}
			return route
		}
		tag = node.Now
	}
	return route
}
