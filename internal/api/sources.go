package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

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
		tx.takeMoves(h)
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
		tx.takeMoves(h)
		if h.Cards != nil {
			if err = h.Cards.RefreshMatchingProviders(ctx, []string{source.URL}); err != nil {
				return nil, err
			}
		}
		response, err := h.verifyAndApplySource(ctx, fresh, tx)
		if err == nil {
			h.logMoves(source.Name, tx)
		}
		return response, err
	})
}

// The journal shows why a selected server kept its place although the
// provider replaced its parameters. It names the changed settings, never
// their values, servers or addresses. An unchanged note is not repeated on
// every refresh unless a selection actually followed a server this time.
func (h *Handlers) logMoves(source string, tx *subscriptionApplySnapshot) {
	if len(tx.moves) == 0 {
		return
	}
	note := fmt.Sprintf("%s: провайдер изменил параметры серверов (%d) под прежними названиями", source, len(tx.moves))
	if len(tx.fields) > 0 {
		note += "; изменились настройки: " + strings.Join(tx.fields, ", ")
	}
	if tx.rebound == 0 && h.reissueNotes[source] == note {
		return
	}
	if h.reissueNotes == nil {
		h.reissueNotes = map[string]string{}
	}
	h.reissueNotes[source] = note
	h.watchdog.Log("[SUBSCRIPTION] %s; сохранено выборов: %d", note, tx.rebound)
}

// HandleReplaceSourceURL — POST /api/sources/{id}/url
func (h *Handlers) HandleReplaceSourceURL(w http.ResponseWriter, r *http.Request) {
	var input struct {
		URL string `json:"url"`
	}
	if !readSourceRequest(w, r, &input) {
		return
	}
	id := chi.URLParam(r, "id")
	response, err := h.withSubscriptionTransaction(func(tx *subscriptionApplySnapshot) (map[string]interface{}, error) {
		tx.sourceScoped = true
		source, err := sourceFromSnapshot(tx, id)
		if err != nil {
			return nil, err
		}
		// The profile's own provider keeps downloading the address written in
		// the profile. Swapping it under a running core is a separate, riskier
		// operation than replacing a link in the panel's catalogue.
		if h.Cards != nil && source.URL != "" {
			linked, err := h.Cards.NativeSourceLinks([]models.SubscriptionSource{source})
			if err != nil {
				return nil, err
			}
			if linked[source.ID] {
				return nil, errors.New("эту подписку использует встроенный провайдер профиля Mihomo. Добавьте новую ссылку отдельным источником и удалите этот: выбранные серверы с теми же параметрами останутся на месте")
			}
		}
		fresh, err := h.subscription.ReplaceSourceURL(r.Context(), id, input.URL)
		if err != nil {
			return nil, err
		}
		tx.takeMoves(h)
		response, err := h.verifyAndApplySource(r.Context(), fresh, tx)
		if err == nil {
			h.logMoves(source.Name, tx)
		}
		return response, err
	})
	writeSourceResponse(w, response, err)
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
