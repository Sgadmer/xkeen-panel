package api

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"time"
	"xkeen-panel/internal/models"
	"xkeen-panel/internal/xkeen"
)

func publicServer(server models.Server) serverView {
	path := xkeen.ServerCountryPath(server)
	server.Country = xkeen.ServerCountry(server)
	server.RawURI = ""
	server.RawOutbound = nil
	server.RawProfile = nil
	return serverView{Server: server, DeclaredCountryPath: path}
}

func publicServers(servers []models.Server) []serverView {
	result := make([]serverView, len(servers))
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
	canRefresh := data.URL != ""
	for _, s := range data.Sources {
		canRefresh = canRefresh || s.Kind == "subscription" && s.URL != ""
	}
	return map[string]interface{}{"configured": len(data.Sources) > 0 || data.URL != "" || len(data.Servers) > 0, "host": host, "source_kind": kind, "can_refresh": canRefresh, "last_updated": data.LastUpdated, "server_count": len(data.Servers), "source_count": len(data.Sources), "import_report": report}
}

// importSubscription serializes import, real probes, and routing changes. A
// rejected input cannot replace the last usable saved subscription.
func (h *Handlers) importSubscription(ctx context.Context, source string) (map[string]interface{}, error) {
	return h.withSubscriptionTransaction(func(transaction *subscriptionApplySnapshot) (map[string]interface{}, error) {
		if err := h.checkFirstSourceReplacement(transaction, source); err != nil {
			return nil, err
		}
		servers, err := h.subscription.UpdateURL(source)
		if err != nil {
			return nil, err
		}
		return h.verifyAndApplySource(ctx, servers, transaction)
	})
}

func (h *Handlers) verifyAndApplySource(ctx context.Context, servers []models.Server, transaction *subscriptionApplySnapshot) (response map[string]interface{}, err error) {
	rt := h.detector.Runtime()
	if rt.Core == xkeen.CoreXray {
		checked, probeErr := xkeen.CheckServersHTTPS(rt, servers, xkeen.ProbeOptions{Context: ctx, Timeout: 8 * time.Second, Concurrency: 3, StateDir: h.config.DataDir})
		if probeErr != nil {
			return nil, probeErr
		}
		h.subscription.UpdateLatencies(checked)
		working := 0
		for _, s := range checked {
			if s.ProbeKind == "https" && s.Latency >= 0 {
				working++
			}
		}
		if working == 0 {
			return nil, fmt.Errorf("ни один сервер подписки не прошёл HTTPS-проверку; прежняя подписка сохранена")
		}
	}
	return h.applyCatalog(ctx, transaction)
}

func (h *Handlers) applyCatalog(ctx context.Context, transaction *subscriptionApplySnapshot) (map[string]interface{}, error) {
	servers := h.subscription.GetServers()
	response := h.catalogResponse()
	if h.Cards != nil {
		transaction.runtimeTouched = true
		if err := h.Cards.Reconcile(ctx); err != nil {
			return nil, err
		}
		h.watchdog.CheckNow()
		return response, nil
	}
	if err := h.applySubscription(servers, response, transaction); err != nil {
		return nil, err
	}
	response["servers"] = publicServers(h.subscription.GetServers())
	return response, nil
}

func (h *Handlers) RefreshManaged(ctx context.Context) error {
	_, err := h.refreshSources(ctx)
	return err
}

func (h *Handlers) refreshSources(ctx context.Context) (map[string]interface{}, error) {
	var failures []error
	updated := 0
	for _, source := range h.subscription.GetSources() {
		if !source.CanRefresh {
			continue
		}
		if err := ctx.Err(); err != nil {
			failures = append(failures, err)
			break
		}
		_, err := h.refreshSource(ctx, source.ID)
		if errors.Is(err, xkeen.ErrSourceNotFound) {
			continue
		}
		if err != nil {
			failures = append(failures, fmt.Errorf("%s: %w", source.Name, err))
			continue
		}
		updated++
	}
	response := h.catalogResponse()
	response["updated_sources"] = updated
	if len(failures) > 0 {
		return response, fmt.Errorf("обновлено источников: %d; ошибки: %w", updated, errors.Join(failures...))
	}
	return response, nil
}
