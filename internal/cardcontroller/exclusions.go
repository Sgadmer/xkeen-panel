package cardcontroller

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strings"

	"github.com/go-chi/chi/v5"
	"xkeen-panel/internal/xkeen"
)

const exclusionKey = "x-xkeen-panel-exclusions"

// Convert only direct rules the legacy UI can represent without changing their
// meaning. Complex conditional rules, categories and MATCH are not editable here.
func directEntry(rule string) (xkeen.Exclusion, bool) {
	fields := strings.Split(rule, ",")
	if len(fields) < 3 || fields[2] != "DIRECT" {
		return xkeen.Exclusion{}, false
	}
	value := fields[1]
	switch fields[0] {
	case "DOMAIN", "DOMAIN-SUFFIX":
		if len(fields) != 3 {
			return xkeen.Exclusion{}, false
		}
		if fields[0] == "DOMAIN" {
			value = "full:" + value
		} else {
			value = "domain:" + value
		}
	case "IP-CIDR", "IP-CIDR6":
		if len(fields) != 4 || fields[3] != "no-resolve" {
			return xkeen.Exclusion{}, false
		}
		prefix, err := netip.ParsePrefix(value)
		if err != nil {
			return xkeen.Exclusion{}, false
		}
		if prefix.Bits() == prefix.Addr().BitLen() {
			value = prefix.Addr().String()
		}
	default:
		return xkeen.Exclusion{}, false
	}
	entry, err := xkeen.NormalizeExclusion(value, "")
	return entry, err == nil
}

func exclusionRule(e xkeen.Exclusion) string {
	if e.Type == "domain" {
		return "DOMAIN-SUFFIX," + strings.TrimPrefix(e.Value, "domain:") + ",DIRECT"
	}
	if e.Type == "full" {
		return "DOMAIN," + strings.TrimPrefix(e.Value, "full:") + ",DIRECT"
	}
	cidr := e.Value
	if a, err := netip.ParseAddr(cidr); err == nil {
		cidr = netip.PrefixFrom(a, a.BitLen()).String()
	}
	kind := "IP-CIDR"
	if strings.Contains(cidr, ":") {
		kind = "IP-CIDR6"
	}
	return kind + "," + cidr + ",DIRECT,no-resolve"
}

func managedExclusions(doc map[string]interface{}) (xkeen.Exclusions, bool, error) {
	raw, found := doc[exclusionKey]
	if !found {
		return xkeen.Exclusions{}, false, nil
	}
	bytes, err := json.Marshal(raw)
	var entries xkeen.Exclusions
	if err != nil || json.Unmarshal(bytes, &entries) != nil || entries.Entries == nil || len(entries.Entries) > xkeen.MaxExclusions {
		return entries, true, errors.New("повреждены исключения в профиле Mihomo")
	}
	seen := map[string]bool{}
	for _, e := range entries.Entries {
		normalized, err := xkeen.NormalizeExclusion(e.Value, e.Comment)
		if err != nil || normalized != e || seen[exclusionRule(e)] {
			return entries, true, errors.New("повреждены данные исключения Mihomo")
		}
		seen[exclusionRule(e)] = true
	}
	return entries, true, nil
}

func currentExclusions(p profile, dataDir string) (xkeen.Exclusions, error) {
	managed, found, err := managedExclusions(p.doc)
	if err != nil || found {
		return managed, err
	}
	old, err := xkeen.LoadExclusions(dataDir)
	if err != nil {
		return old, err
	}
	known := map[string]xkeen.Exclusion{}
	for _, e := range old.Entries {
		known[exclusionRule(e)] = e
	}
	entries := xkeen.Exclusions{Entries: []xkeen.Exclusion{}}
	seen := map[string]bool{}
	for _, item := range list(p.doc["rules"]) {
		rule := str(item)
		fields, target := targetPart(rule)
		if target < 1 {
			break
		}
		if strings.HasPrefix(fields[target], cardPrefix) {
			continue
		}
		if fields[target] != "DIRECT" || fields[0] == "MATCH" {
			break
		}
		e, ok := directEntry(rule)
		if !ok {
			continue
		}
		key := exclusionRule(e)
		if legacy, ok := known[key]; ok {
			e = legacy
		}
		if !seen[key] {
			entries.Entries = append(entries.Entries, e)
			seen[key] = true
		}
	}
	if len(entries.Entries) == 0 {
		return old, nil
	}
	return entries, nil
}

func replaceExclusionRules(p *profile, old, next xkeen.Exclusions) {
	previous := map[string]bool{}
	for _, e := range old.Entries {
		previous[exclusionRule(e)] = true
	}
	rules := []interface{}{}
	for _, e := range next.Entries {
		rules = append(rules, exclusionRule(e))
	}
	leading := true
	for _, raw := range list(p.doc["rules"]) {
		r := str(raw)
		f, t := targetPart(r)
		if t >= 1 && !strings.HasPrefix(f[t], cardPrefix) {
			if f[t] != "DIRECT" || f[0] == "MATCH" {
				leading = false
			}
			if entry, ok := directEntry(r); leading && ok && previous[exclusionRule(entry)] {
				continue
			}
		}
		rules = append(rules, raw)
	}
	p.doc["rules"], p.doc[exclusionKey] = rules, next
}

func (c *Controller) updateExclusions(ctx context.Context, dir string, change func(*xkeen.Exclusions) error) (xkeen.Exclusions, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	p, err := c.read()
	if err != nil {
		return xkeen.Exclusions{}, err
	}
	old, err := currentExclusions(p, dir)
	if err != nil {
		return old, err
	}
	if change == nil {
		return old, nil
	}
	next := xkeen.Exclusions{Entries: append([]xkeen.Exclusion{}, old.Entries...)}
	if err = change(&next); err != nil {
		return old, err
	}
	// Prepare the compatibility copy before the core is touched. The embedded
	// YAML state is authoritative, including after an interrupted final rename.
	raw, err := json.MarshalIndent(next, "", "  ")
	if err != nil {
		return old, err
	}
	mirror := xkeen.ExclusionsPath(dir)
	if info, err := os.Lstat(mirror); err == nil && !info.Mode().IsRegular() {
		return old, errors.New("файл сохранённых исключений занят")
	} else if err != nil && !os.IsNotExist(err) {
		return old, err
	}
	tmp, err := stage(filepath.Dir(mirror), append(raw, '\n'))
	if err != nil {
		return old, err
	}
	defer os.Remove(tmp)
	_, err = c.apply(ctx, "", "", func(candidate *profile) error {
		if !bytes.Equal(candidate.raw, p.raw) {
			return errors.New("профиль изменён параллельно")
		}
		replaceExclusionRules(candidate, old, next)
		return nil
	})
	if err != nil {
		return old, err
	}
	if err = os.Rename(tmp, mirror); err != nil {
		return next, errors.New("исключения применены в Mihomo, копию для старой панели сохранить не удалось")
	}
	return next, nil
}

// MountExclusions belongs inside the companion's authenticated API router.
func (c *Controller) MountExclusions(r chi.Router, dir string) {
	send := func(w http.ResponseWriter, entries xkeen.Exclusions, err error) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
			return
		}
		_ = json.NewEncoder(w).Encode(entries)
	}
	r.Get("/exclusions", func(w http.ResponseWriter, r *http.Request) {
		v, e := c.updateExclusions(r.Context(), dir, nil)
		send(w, v, e)
	})
	r.Post("/exclusions", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Value   string `json:"value"`
			Comment string `json:"comment"`
		}
		dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8192))
		dec.DisallowUnknownFields()
		if dec.Decode(&req) != nil || dec.Decode(new(interface{})) != io.EOF {
			send(w, xkeen.Exclusions{}, errors.New("неверный формат запроса"))
			return
		}
		entry, err := xkeen.NormalizeExclusion(req.Value, req.Comment)
		if err != nil {
			send(w, xkeen.Exclusions{}, err)
			return
		}
		v, e := c.updateExclusions(r.Context(), dir, func(s *xkeen.Exclusions) error {
			if len(s.Entries) >= xkeen.MaxExclusions {
				return errors.New("достигнут предел в 500 исключений")
			}
			for _, old := range s.Entries {
				if exclusionRule(old) == exclusionRule(entry) {
					return errors.New("такое исключение уже добавлено")
				}
			}
			s.Entries = append(s.Entries, entry)
			return nil
		})
		send(w, v, e)
	})
	r.Delete("/exclusions/{id}", func(w http.ResponseWriter, r *http.Request) {
		id := chi.URLParam(r, "id")
		v, e := c.updateExclusions(r.Context(), dir, func(s *xkeen.Exclusions) error {
			for i, entry := range s.Entries {
				if entry.ID == id {
					s.Entries = append(s.Entries[:i], s.Entries[i+1:]...)
					return nil
				}
			}
			return errors.New("исключение не найдено")
		})
		send(w, v, e)
	})
}
