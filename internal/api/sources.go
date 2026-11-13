package api

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"

	"github.com/go-chi/chi/v5"
	"xkeen-panel/internal/models"
	"xkeen-panel/internal/xkeen"
)

func (h *Handlers) catalogResponse() map[string]interface{} {
	data := h.subscription.GetData()
	return map[string]interface{}{"sources": xkeen.SourceSummaries(data), "servers": publicServers(data.Servers), "server_count": len(data.Servers), "import_report": h.subscription.GetImportReport()}
}

func readSourceRequest(w http.ResponseWriter, r *http.Request, dst interface{}) bool {
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 6<<20))
	decoder.DisallowUnknownFields()
	if decoder.Decode(dst) == nil && decoder.Decode(new(interface{})) == io.EOF {
		return true
	}
	writeJSON(w, http.StatusBadRequest, map[string]string{"error": "проверьте поля источника и размер файла"})
	return false
}

func writeSourceResponse(w http.ResponseWriter, response map[string]interface{}, err error) {
	if err == nil {
		writeJSON(w, http.StatusOK, response)
		return
	}
	code := http.StatusBadRequest
	if errors.Is(err, xkeen.ErrSourceNotFound) {
		code = http.StatusNotFound
	}
	writeJSON(w, code, map[string]string{"error": err.Error()})
}

func (h *Handlers) HandleSources(w http.ResponseWriter, r *http.Request) {
	data := h.subscription.GetData()
	sources := xkeen.SourceSummaries(data)
	if h.Cards != nil {
		matched, err := h.Cards.NativeSourceLinks(data.Sources)
		if err != nil {
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "не удалось проверить встроенные источники Mihomo"})
			return
		}
		for i := range sources {
			sources[i].NativeProvider = matched[sources[i].ID]
		}
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"sources": sources})
}

func (h *Handlers) HandleAddSource(w http.ResponseWriter, r *http.Request) {
	var input xkeen.SourceInput
	if !readSourceRequest(w, r, &input) {
		return
	}
	response, err := h.withSubscriptionTransaction(func(tx *subscriptionApplySnapshot) (map[string]interface{}, error) {
		tx.sourceScoped = true
		servers, err := h.subscription.AddSource(r.Context(), input)
		if err != nil {
			return nil, err
		}
		return h.verifyAndApplySource(r.Context(), servers, tx)
	})
	writeSourceResponse(w, response, err)
}

func (h *Handlers) HandleRenameSource(w http.ResponseWriter, r *http.Request) {
	var input struct {
		Name string `json:"name"`
	}
	if !readSourceRequest(w, r, &input) {
		return
	}
	h.watchdog.LockChanges()
	defer h.watchdog.UnlockChanges()
	err := h.subscription.RenameSource(chi.URLParam(r, "id"), input.Name)
	writeSourceResponse(w, h.catalogResponse(), err)
}

func sourceFromSnapshot(tx *subscriptionApplySnapshot, id string) (models.SubscriptionSource, error) {
	for _, source := range tx.data.Sources {
		if source.ID == id {
			return source, nil
		}
	}
	return models.SubscriptionSource{}, xkeen.ErrSourceNotFound
}

func (h *Handlers) refreshSource(ctx context.Context, id string) (map[string]interface{}, error) {
	return h.withSubscriptionTransaction(func(tx *subscriptionApplySnapshot) (map[string]interface{}, error) {
		tx.sourceScoped = true
		source, err := sourceFromSnapshot(tx, id)
		if err != nil {
			return nil, err
		}
		fresh, err := h.subscription.RefreshSource(ctx, id)
		if err != nil {
			return nil, err
		}
		if h.Cards != nil {
			if err = h.Cards.RefreshMatchingProviders(ctx, []string{source.URL}); err != nil {
				return nil, err
			}
		}
		return h.verifyAndApplySource(ctx, fresh, tx)
	})
}

func (h *Handlers) HandleRefreshSource(w http.ResponseWriter, r *http.Request) {
	response, err := h.refreshSource(r.Context(), chi.URLParam(r, "id"))
	writeSourceResponse(w, response, err)
}

func (h *Handlers) checkFirstSourceReplacement(tx *subscriptionApplySnapshot, newURL string) error {
	if h.Cards != nil && tx.data.URL != "" && tx.data.URL != newURL {
		return h.Cards.CheckSourceRemoval(tx.data.URL)
	}
	return nil
}

func (h *Handlers) HandleDeleteSource(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	response, err := h.withSubscriptionTransaction(func(tx *subscriptionApplySnapshot) (map[string]interface{}, error) {
		tx.sourceScoped = true
		source, err := sourceFromSnapshot(tx, id)
		if err != nil {
			return nil, err
		}
		if h.Cards != nil && source.URL != "" {
			tx.restoreNative, err = h.Cards.DetachSource(r.Context(), source.URL)
			if err != nil {
				return nil, err
			}
		}
		if err := h.subscription.DeleteSource(id); err != nil {
			return nil, err
		}
		return h.applyCatalog(r.Context(), tx)
	})
	writeSourceResponse(w, response, err)
}
