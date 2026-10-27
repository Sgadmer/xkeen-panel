package xkeen

import (
	"encoding/json"
	"sort"
	"strconv"
	"strings"

	"xkeen-panel/internal/models"
)

// endpoint identifies the complete upstream configuration. Address and UUID
// alone cannot distinguish two transports or a provider changing its REALITY
// key, TLS name or gRPC service on the same listening socket.
type endpoint struct {
	Address  string
	Port     int
	UUID     string
	Identity string
}

func endpointOfServer(server models.Server) (endpoint, bool) {
	if len(server.RawProfile) > 0 {
		identity := ProfileIdentity(server)
		return endpoint{Identity: identity}, identity != ""
	}
	ob, err := BuildServerOutbound(server, "", nil)
	if err != nil {
		return endpoint{}, false
	}
	return endpointOfOutbound(ob)
}

func endpointOfOutbound(ob map[string]interface{}) (endpoint, bool) {
	if identity := ProfileEndpointIdentity(ob); identity != "" {
		return endpoint{Identity: identity}, true
	}
	if ob == nil || isServiceOutbound(ob) {
		return endpoint{}, false
	}
	raw, err := json.Marshal(ob)
	if err != nil {
		return endpoint{}, false
	}
	identity := ServerIdentity(models.Server{RawOutbound: raw})
	if identity == "" {
		return endpoint{}, false
	}
	address, port, _, err := outboundMetadata(ob)
	if err != nil {
		return endpoint{}, false
	}
	_, _, uuid, _ := readProxyEndpoint(ob)
	return endpoint{Address: address, Port: port, UUID: uuid, Identity: identity}, true
}

// Key renders an endpoint as a stable string, so a pin can be stored as the
// node it means and not merely as the tag that happens to carry it.
func (e endpoint) Key() string {
	if e.Identity != "" {
		return e.Identity
	}
	return e.Address + ":" + strconv.Itoa(e.Port) + ":" + e.UUID
}

// PoolLayout is the tag→endpoint mapping currently written to the config.
//
// Keeping a server on the tag it already has is what makes a refresh cheap: a
// tag whose endpoint is unchanged does not need to be touched in the running
// core, and the traffic flowing through it is not interrupted.
type PoolLayout map[string]endpoint

// ReadPoolLayout reads the pool's current tag assignment.
func ReadPoolLayout(outboundsPath, selector string) (PoolLayout, error) {
	if selector == "" {
		selector = DefaultPoolSelector
	}

	config, err := ReadOutboundsConfig(outboundsPath)
	if err != nil {
		return nil, err
	}

	layout := PoolLayout{}
	for _, raw := range asSlice(config["outbounds"]) {
		ob, ok := raw.(map[string]interface{})
		if !ok || isServiceOutbound(ob) {
			continue
		}
		tag, _ := ob["tag"].(string)
		if !strings.HasPrefix(tag, selector) {
			continue
		}
		if ep, ok := endpointOfOutbound(ob); ok {
			layout[tag] = ep
		}
	}

	return layout, nil
}

// Endpoints returns the set of endpoints the layout covers.
func (l PoolLayout) Endpoints() map[endpoint]bool {
	set := make(map[endpoint]bool, len(l))
	for _, ep := range l {
		set[ep] = true
	}
	return set
}

// tagOf finds which tag currently carries an endpoint.
func (l PoolLayout) tagOf(ep endpoint) (string, bool) {
	for tag, current := range l {
		if current == ep {
			return tag, true
		}
	}
	return "", false
}

// assignTags maps servers onto pool tags, keeping every server that is already
// in the pool on the tag it already has.
//
// Without this the tags are handed out in latency order, so ordinary ping jitter
// reshuffles the whole pool on every refresh: each tag points at a different
// server, every outbound has to be replaced in the running core, and every
// connection through them is dropped. A pinned tag would also silently come to
// mean a different server.
func assignTags(servers []models.Server, selector string, existing PoolLayout) []taggedServer {
	if selector == "" {
		selector = DefaultPoolSelector
	}

	assigned := make([]taggedServer, 0, len(servers))
	taken := map[string]bool{}
	seen := map[endpoint]bool{}
	var pending []taggedServer

	for _, server := range servers {
		ep, ok := endpointOfServer(server)
		if !ok {
			continue
		}
		if seen[ep] {
			continue
		}
		seen[ep] = true

		if tag, found := existing.tagOf(ep); found && !taken[tag] {
			taken[tag] = true
			assigned = append(assigned, taggedServer{Tag: tag, Server: server, Endpoint: ep})
			continue
		}

		pending = append(pending, taggedServer{Server: server, Endpoint: ep})
	}

	// Newcomers take the lowest free slots, so tags stay a dense 1..N range
	next := 1
	for i := range pending {
		for {
			tag := selector + strconv.Itoa(next)
			next++
			if !taken[tag] {
				taken[tag] = true
				pending[i].Tag = tag
				break
			}
		}
	}

	assigned = append(assigned, pending...)
	sort.SliceStable(assigned, func(i, j int) bool {
		return tagIndex(assigned[i].Tag, selector) < tagIndex(assigned[j].Tag, selector)
	})

	return assigned
}

type taggedServer struct {
	Tag      string
	Server   models.Server
	Endpoint endpoint
}

func tagIndex(tag, selector string) int {
	n, err := strconv.Atoi(strings.TrimPrefix(tag, selector))
	if err != nil {
		return 1 << 30
	}
	return n
}
