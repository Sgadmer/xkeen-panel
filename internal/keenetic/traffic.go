package keenetic

import (
	"context"
	"net/http"
	"net/url"
)

type TrafficCounters struct {
	Received uint64
	Sent     uint64
}

// WANCounters reads the statistics of the router's active default uplinks.
// Interface IDs stay separate: summing an Ethernet parent and a logical WAN
// (or its VPN) would count the same bytes twice.
func (c *Client) WANCounters(ctx context.Context) map[string]TrafficCounters {
	var interfaces map[string]struct {
		ID        string `json:"id"`
		DefaultGW bool   `json:"defaultgw"`
		Global    bool   `json:"global"`
		Connected string `json:"connected"`
		State     string `json:"state"`
		Link      string `json:"link"`
	}
	if err := c.doContext(ctx, http.MethodGet, "show/interface", nil, &interfaces); err != nil {
		return nil
	}
	counters := make(map[string]TrafficCounters)
	for name, iface := range interfaces {
		if !iface.DefaultGW || !iface.Global || iface.Connected == "no" || iface.State == "down" || iface.Link == "down" {
			continue
		}
		id := iface.ID
		if id == "" {
			id = name
		}
		var stat struct {
			RX *uint64 `json:"rxbytes"`
			TX *uint64 `json:"txbytes"`
		}
		err := c.doContext(ctx, http.MethodGet, "show/interface/stat?name="+url.QueryEscape(id), nil, &stat)
		if err == nil && stat.RX != nil && stat.TX != nil {
			counters[id] = TrafficCounters{Received: *stat.RX, Sent: *stat.TX}
		}
	}
	return counters
}
