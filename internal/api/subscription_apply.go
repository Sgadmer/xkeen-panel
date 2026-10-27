package api

import (
	"context"
	"fmt"
	"net/url"
	"time"
	"xkeen-panel/internal/models"
	"xkeen-panel/internal/xkeen"
)

func publicServer(server models.Server) models.Server {
	server.RawURI = ""
	server.RawOutbound = nil
	server.RawProfile = nil
	return server
}

func publicServers(servers []models.Server) []models.Server {
	result := make([]models.Server, len(servers))
	for i, server := range servers {
		result[i] = publicServer(server)
	}
	return result
}

func subscriptionView(data models.SubscriptionData, report xkeen.ImportReport) map[string]interface{} {
	host := ""
	if parsed, err := url.Parse(data.URL); err == nil {
		host = parsed.Hostname()
	}
	kind := data.SourceKind
	if kind == "" {
		kind = "subscription"
	}
	return map[string]interface{}{"configured": data.URL != "" || len(data.Servers) > 0, "host": host, "source_kind": kind, "can_refresh": data.URL != "", "last_updated": data.LastUpdated, "server_count": len(data.Servers), "import_report": report}
}

// importSubscription serializes import, real probes, and routing changes. A
// rejected input cannot replace the last usable saved subscription.
func (h *Handlers) importSubscription(ctx context.Context, source string, refresh bool) (response map[string]interface{}, err error) {
	return h.withSubscriptionTransaction(func(transaction *subscriptionApplySnapshot) (map[string]interface{}, error) {
		return h.importSubscriptionLocked(ctx, source, refresh, transaction)
	})
}

func (h *Handlers) importSubscriptionLocked(ctx context.Context, source string, refresh bool, transaction *subscriptionApplySnapshot) (response map[string]interface{}, err error) {
	var servers []models.Server
	if refresh {
		servers, err = h.subscription.Refresh()
	} else {
		servers, err = h.subscription.UpdateURL(source)
	}
	if err != nil {
		return nil, err
	}
	return h.verifyAndApplySource(ctx, servers, transaction)
}

func (h *Handlers) verifyAndApplySource(ctx context.Context, servers []models.Server, transaction *subscriptionApplySnapshot) (response map[string]interface{}, err error) {
	rt := h.detector.Runtime()
	if rt.Core == xkeen.CoreXray {
		checked, probeErr := xkeen.CheckServersHTTPS(rt, servers, xkeen.ProbeOptions{Context: ctx, Timeout: 8 * time.Second, Concurrency: 3, StateDir: h.config.DataDir})
		if probeErr != nil {
			return nil, probeErr
		}
		h.subscription.UpdateLatencies(checked)
		servers = h.subscription.GetServers()
		working := 0
		for _, s := range servers {
			if s.ProbeKind == "https" && s.Latency >= 0 {
				working++
			}
		}
		if working == 0 {
			return nil, fmt.Errorf("ни один сервер подписки не прошёл HTTPS-проверку; прежняя подписка сохранена")
		}
	}
	response = map[string]interface{}{"server_count": len(servers), "servers": publicServers(servers), "import_report": h.subscription.GetImportReport()}
	if err = h.applySubscription(servers, response, transaction); err != nil {
		return nil, err
	}
	response["servers"] = publicServers(h.subscription.GetServers())
	return response, nil
}

func (h *Handlers) RefreshManaged(ctx context.Context) error {
	if !h.subscription.CanRefresh() {
		return nil
	}
	_, err := h.importSubscription(ctx, "", true)
	return err
}
