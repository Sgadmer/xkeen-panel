package cardcontroller

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"xkeen-panel/internal/xkeen"
)

// The owner's cards behave like the built-in ones: a route, a kill switch, a
// place in the journal. Two things keep them from weakening the others:
//
//   - their rules follow the rules of every built-in card (they come last in
//     the list of services and are never promoted above an earlier card);
//   - an address that already belongs to another card is refused, checked
//     against the built-in domains, the downloaded lists and the networks.

// knownCard reports whether the identifier names a card that exists now.
func knownCard(id string) bool { return groupNames[id] != "" || xkeen.IsCustomService(id) }

// serviceOfTag names the card a Mihomo group belongs to.
func serviceOfTag(tag string) string {
	if id := diagnosticServiceTags[tag]; id != "" {
		return id
	}
	rest, ok := strings.CutPrefix(tag, cardPrefix)
	if !ok {
		return ""
	}
	rest = strings.TrimSuffix(strings.TrimPrefix(rest, "guard-"), "-inherited")
	if xkeen.IsCustomService(rest) {
		return rest
	}
	return ""
}

type customServiceView struct {
	ID        string   `json:"id"`
	Name      string   `json:"name"`
	Addresses []string `json:"addresses"`
}

func customServiceViews() []customServiceView {
	views := []customServiceView{}
	for _, service := range xkeen.CustomServices() {
		views = append(views, customServiceView{service.ID, service.Name, service.Addresses()})
	}
	return views
}

// customConflict names the first address of the service that another card
// already owns.
func (c *Controller) customConflict(p profile, service xkeen.CustomService) error {
	guard := c.newExclusionGuard(p)
	check := func(kind, value, shown string) error {
		for _, card := range guard.cards {
			if card.id != service.ID && card.touches(xkeen.Exclusion{Type: kind, Value: value}) {
				return fmt.Errorf("адрес %s уже относится к карточке «%s». Один адрес не может принадлежать двум карточкам", shown, card.name)
			}
		}
		return nil
	}
	for _, domain := range service.Domains {
		kind, host, _ := strings.Cut(domain, ":")
		if err := check(kind, domain, host); err != nil {
			return err
		}
	}
	for _, network := range service.Networks {
		if err := check("ip", network, network); err != nil {
			return err
		}
	}
	return nil
}

// saveCustomServices replaces the registry and its file, re-renders the rules
// and puts everything back when the core refuses the result.
func (c *Controller) saveCustomServices(ctx context.Context, dataDir string, next []xkeen.CustomService, id, target string, edit func(*profile) error) error {
	previous := xkeen.CustomServices()
	restore := func() {
		xkeen.SetCustomServices(previous)
		_ = xkeen.SaveCustomServices(dataDir, previous)
	}
	xkeen.SetCustomServices(next)
	if err := xkeen.SaveCustomServices(dataDir, next); err != nil {
		xkeen.SetCustomServices(previous)
		return errors.New("не удалось сохранить список своих сервисов")
	}
	if _, err := c.apply(ctx, id, target, edit); err != nil {
		restore()
		return err
	}
	return nil
}

func (c *Controller) createCustomService(ctx context.Context, dataDir, name string, addresses []string) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	p, err := c.read()
	if err != nil {
		return "", err
	}
	list := xkeen.CustomServices()
	if len(list) >= xkeen.MaxCustomServices {
		return "", fmt.Errorf("своих сервисов может быть не больше %d", xkeen.MaxCustomServices)
	}
	id, err := xkeen.NewCustomServiceID()
	for attempt := 0; err == nil && knownCard(id) && attempt < 8; attempt++ {
		id, err = xkeen.NewCustomServiceID()
	}
	if err != nil || knownCard(id) {
		return "", errors.New("не удалось создать сервис, повторите")
	}
	service, err := xkeen.NormalizeCustomService(id, name, addresses)
	if err != nil {
		return "", err
	}
	if err = uniqueCardName(service); err != nil {
		return "", err
	}
	if err = c.customConflict(p, service); err != nil {
		return "", err
	}
	// A new card starts on the automatic pool, like the built-in ones.
	return id, c.saveCustomServices(ctx, dataDir, append(list, service), id, defaultServiceTarget(id), func(p *profile) error {
		if _, managed := p.doc[stateKey]; !managed {
			p.doc[serviceAutoKey] = true
		}
		return nil
	})
}

func (c *Controller) updateCustomService(ctx context.Context, dataDir, id, name string, addresses []string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	p, err := c.read()
	if err != nil {
		return err
	}
	list := xkeen.CustomServices()
	index := -1
	for i := range list {
		if list[i].ID == id {
			index = i
		}
	}
	if index < 0 {
		return errCustomServiceMissing
	}
	service, err := xkeen.NormalizeCustomService(id, name, addresses)
	if err != nil {
		return err
	}
	if err = uniqueCardName(service); err != nil {
		return err
	}
	if err = c.customConflict(p, service); err != nil {
		return err
	}
	list[index] = service
	// Addresses that left the card must not keep its route: their open
	// connections are closed like after any change of the card.
	c.pending[id] = true
	return c.saveCustomServices(ctx, dataDir, list, "", "", nil)
}

func (c *Controller) deleteCustomService(ctx context.Context, dataDir, id string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	list := xkeen.CustomServices()
	next := list[:0:0]
	for _, service := range list {
		if service.ID != id {
			next = append(next, service)
		}
	}
	if len(next) == len(list) {
		return errCustomServiceMissing
	}
	return c.saveCustomServices(ctx, dataDir, next, "", "", func(p *profile) error {
		delete(p.assigned, id)
		// The saved kill switch choice of the card goes with it.
		if policy, err := readKillSwitch(p.doc); err == nil {
			if _, kept := policy.Services[id]; kept {
				delete(policy.Services, id)
				values := map[string]interface{}{}
				for service, mode := range policy.Services {
					values[service] = mode
				}
				p.doc[killSwitchKey] = map[string]interface{}{"enabled": policy.Enabled, "services": values}
			}
		}
		return nil
	})
}

var errCustomServiceMissing = errors.New("такого сервиса нет")

func uniqueCardName(service xkeen.CustomService) error {
	for _, other := range xkeen.ServiceNames() {
		if other.ID != service.ID && strings.EqualFold(other.Name, service.Name) {
			return fmt.Errorf("карточка «%s» уже есть — выберите другое название", other.Name)
		}
	}
	return nil
}

// MountCustomServices exposes the owner's cards. dataDir keeps their list.
func (c *Controller) MountCustomServices(r chi.Router, dataDir string) {
	answer := func(w http.ResponseWriter, status int, body interface{}) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(body)
	}
	list := func(w http.ResponseWriter) {
		answer(w, http.StatusOK, map[string]interface{}{"services": customServiceViews(), "limit": xkeen.MaxCustomServices})
	}
	fail := func(w http.ResponseWriter, err error) {
		status := http.StatusBadRequest
		if errors.Is(err, errCustomServiceMissing) {
			status = http.StatusNotFound
		}
		answer(w, status, map[string]string{"error": err.Error()})
	}
	read := func(w http.ResponseWriter, r *http.Request) (string, []string, bool) {
		var request struct {
			Name      string   `json:"name"`
			Addresses []string `json:"addresses"`
		}
		r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
		if json.NewDecoder(r.Body).Decode(&request) != nil {
			fail(w, errors.New("некорректный запрос"))
			return "", nil, false
		}
		return request.Name, request.Addresses, true
	}
	r.Get("/custom-services", func(w http.ResponseWriter, r *http.Request) { list(w) })
	r.Post("/custom-services", func(w http.ResponseWriter, r *http.Request) {
		name, addresses, ok := read(w, r)
		if !ok {
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 90*time.Second)
		defer cancel()
		if _, err := c.createCustomService(ctx, dataDir, name, addresses); err != nil {
			fail(w, err)
			return
		}
		list(w)
	})
	r.Put("/custom-services/{id}", func(w http.ResponseWriter, r *http.Request) {
		name, addresses, ok := read(w, r)
		if !ok {
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 90*time.Second)
		defer cancel()
		if err := c.updateCustomService(ctx, dataDir, chi.URLParam(r, "id"), name, addresses); err != nil {
			fail(w, err)
			return
		}
		list(w)
	})
	r.Delete("/custom-services/{id}", func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 90*time.Second)
		defer cancel()
		if err := c.deleteCustomService(ctx, dataDir, chi.URLParam(r, "id")); err != nil {
			fail(w, err)
			return
		}
		list(w)
	})
}
