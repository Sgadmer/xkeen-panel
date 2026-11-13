package cardcontroller

import (
	"bytes"
	"context"
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

type providerInfo struct {
	Proxies []struct{ Name string }
}

func (a coreAPI) providers(ctx context.Context) (map[string]providerInfo, error) {
	var result struct{ Providers map[string]providerInfo }
	if err := a.request(ctx, "GET", "/providers/proxies", nil, &result); err != nil {
		return nil, err
	}
	if result.Providers == nil {
		return nil, errors.New("Mihomo не подтвердил состав провайдеров")
	}
	return result.Providers, nil
}

func unsafeFallback(name string, live map[string]selector, seen map[string]bool) bool {
	switch strings.ToUpper(name) {
	case "DIRECT", "COMPATIBLE", "PASS", "PASS-RULE":
		return true
	}
	if seen[name] {
		return false
	}
	seen[name] = true
	if kind := strings.ToUpper(live[name].Type); kind == "DIRECT" || kind == "PASS" || kind == "COMPATIBLE" {
		return true
	}
	for _, member := range live[name].All {
		if unsafeFallback(member, live, seen) {
			return true
		}
	}
	return false
}

func detachProviderGroups(p profile, names []string, removed map[string]bool, live map[string]selector) (map[string]bool, error) {
	affected := map[string]bool{}
	for _, value := range list(p.doc["proxy-groups"]) {
		group := object(value)
		id := str(group["name"])
		uses := list(group["use"])
		keep := make([]interface{}, 0, len(uses))
		for _, ref := range uses {
			if !slices.Contains(names, str(ref)) {
				keep = append(keep, ref)
			}
		}
		all := group["include-all"] == true || group["include-all-providers"] == true
		if !all && len(uses) == len(keep) {
			continue
		}
		g, ok := live[id]
		if !ok {
			return nil, errors.New("состав зависимой группы Mihomo не подтверждён")
		}
		if strings.EqualFold(g.Type, "Selector") && removed[g.Now] {
			return nil, errors.New("в группе Mihomo закреплён удаляемый узел. Сначала выберите автовыбор или сервер другого источника")
		}
		if !strings.EqualFold(g.Type, "Selector") && unsafeFallback(id, live, map[string]bool{}) {
			return nil, errors.New("автоматическая группа провайдера допускает прямой выход. Измените её состав перед удалением подписки")
		}
		// A configured country filter restores the saved owner fallback when
		// restrictions are lifted. Removal must remain closed in both states.
		if state := object(group[countryFilterKey]); state != nil {
			state["empty-fallback"] = "REJECT"
		}
		group["empty-fallback"] = "REJECT"
		if len(keep) > 0 {
			group["use"] = keep
		} else {
			delete(group, "use")
		}
		if len(keep) == 0 && !all && group["include-all-proxies"] != true && len(list(group["proxies"])) == 0 {
			group["proxies"] = []string{"REJECT"}
		}
		affected[id] = true
	}
	for _, name := range names {
		delete(object(p.doc["proxy-providers"]), name)
	}
	return affected, nil
}

// DetachSource changes the native provider only after confirming ownership by
// URL. The private undo restores the original profile if the surrounding
// catalogue transaction subsequently fails.
func (c *Controller) DetachSource(ctx context.Context, source string) (func(context.Context) error, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	p, err := c.read()
	if err != nil {
		return nil, err
	}
	names := matchingProviders(p, []string{source})
	if len(names) == 0 {
		return nil, nil
	}
	providers, err := p.api.providers(ctx)
	if err != nil {
		return nil, err
	}
	removed := map[string]bool{}
	for _, name := range names {
		info, ok := providers[name]
		if !ok {
			return nil, errors.New("связанный провайдер отсутствует в работающем Mihomo")
		}
		for _, node := range info.Proxies {
			removed[node.Name] = true
		}
	}
	for name, info := range providers {
		if slices.Contains(names, name) {
			continue
		}
		for _, node := range info.Proxies {
			if removed[node.Name] {
				return nil, errors.New("имена узлов разных провайдеров совпадают. Невозможно безопасно отключить только один из них")
			}
		}
	}
	for _, value := range list(p.doc["proxies"]) {
		if removed[str(object(value)["name"])] {
			return nil, errors.New("имя узла провайдера совпадает с отдельным выходом Mihomo. Невозможно однозначно отключить его соединения")
		}
	}
	live, err := p.api.selectors(ctx)
	if err != nil {
		return nil, err
	}
	affected, err := detachProviderGroups(p, names, removed, live)
	if err != nil {
		return nil, err
	}
	body, err := yaml.Marshal(p.doc)
	if err != nil {
		return nil, errors.New("не удалось подготовить профиль без удаляемого источника")
	}
	if err = c.install(ctx, p, body, p.doc, live, nil, autoCountryGroups{}); err != nil {
		return nil, err
	}
	undo := func(ctx context.Context) error {
		file, err := stage(filepath.Dir(c.path), p.raw)
		if err != nil {
			return err
		}
		defer os.Remove(file)
		disk, err := os.ReadFile(c.path)
		if err != nil || !bytes.Equal(disk, body) {
			return errors.New("профиль Mihomo изменился во время отката")
		}
		if err := os.Rename(file, c.path); err != nil {
			return err
		}
		if err := p.api.reload(ctx, c.path); err != nil {
			return err
		}
		after, err := p.api.selectors(ctx)
		if err != nil {
			return err
		}
		return restoreSelectors(ctx, p.api, live, after)
	}
	if err := confirmProviderRemoval(ctx, p.api, names, removed, affected); err != nil {
		recovery, cancel := context.WithTimeout(context.Background(), 45*time.Second)
		defer cancel()
		if undo(recovery) != nil {
			return nil, errors.New("отключение провайдера не подтверждено, проверьте восстановление профиля Mihomo")
		}
		return nil, err
	}
	return func(ctx context.Context) error {
		c.mu.Lock()
		defer c.mu.Unlock()
		return undo(ctx)
	}, nil
}

func confirmProviderRemoval(ctx context.Context, api coreAPI, names []string, removed, affected map[string]bool) error {
	providers, err := api.providers(ctx)
	if err != nil {
		return err
	}
	for _, name := range names {
		if _, exists := providers[name]; exists {
			return errors.New("удалённый провайдер всё ещё доступен")
		}
	}
	live, err := api.selectors(ctx)
	if err != nil {
		return err
	}
	for id := range affected {
		group := live[id]
		if len(group.All) == 0 || removed[group.Now] {
			return errors.New("Mihomo не подтвердил отключение узлов в зависимой группе")
		}
		for _, member := range group.All {
			if removed[member] || member == "COMPATIBLE" {
				return errors.New("Mihomo не подтвердил закрытый резерв группы")
			}
		}
	}
	for attempt := 0; attempt < 2; attempt++ {
		var snapshot struct {
			Connections []struct {
				ID     string
				Chains []string
			}
		}
		if err := api.request(ctx, "GET", "/connections", nil, &snapshot); err != nil {
			return err
		}
		found := false
		for _, flow := range snapshot.Connections {
			if len(flow.Chains) == 0 || !slices.ContainsFunc(flow.Chains, func(tag string) bool { return removed[tag] }) {
				continue
			}
			found = true
			if attempt != 0 || flow.ID == "" {
				return errors.New("Mihomo не подтвердил закрытие соединений удалённого провайдера")
			}
			if err := api.request(ctx, "DELETE", "/connections/"+url.PathEscape(flow.ID), nil, nil); err != nil {
				return err
			}
		}
		if !found {
			return nil
		}
	}
	return errors.New("не удалось отключить соединения провайдера")
}
