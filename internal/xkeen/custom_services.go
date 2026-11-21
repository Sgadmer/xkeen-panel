package xkeen

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync/atomic"
	"unicode/utf8"
)

// A custom service is a card the owner describes: a name and the addresses
// that belong to it. It gets a route and a kill switch like a built-in card.
//
// Its rules stand after the rules of every built-in card, and its addresses
// may not overlap another card (the card controller checks that against the
// live lists), so a custom card can never take an address away from Claude or
// from any other card.

const (
	CustomServicePrefix = "custom-"
	MaxCustomServices   = 30
	maxCustomAddresses  = 200
	maxCustomNameRunes  = 40
)

type CustomService struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	// "domain:example.com" covers the domain and everything below it,
	// "full:host.example.com" one exact name.
	Domains  []string `json:"domains"`
	Networks []string `json:"networks,omitempty"`
}

var (
	customServices  atomic.Pointer[[]CustomService]
	customIDPattern = regexp.MustCompile(`^custom-[0-9a-f]{8}$`)
)

// CustomServices returns the owner's cards in the order they were created.
func CustomServices() []CustomService {
	current := customServices.Load()
	if current == nil {
		return nil
	}
	result := make([]CustomService, len(*current))
	for i, service := range *current {
		result[i] = CustomService{service.ID, service.Name, slices.Clone(service.Domains), slices.Clone(service.Networks)}
	}
	return result
}

// SetCustomServices replaces the registry. The entries must be normalised.
func SetCustomServices(list []CustomService) {
	copied := make([]CustomService, len(list))
	for i, service := range list {
		copied[i] = CustomService{service.ID, service.Name, slices.Clone(service.Domains), slices.Clone(service.Networks)}
	}
	customServices.Store(&copied)
}

func customService(id string) (CustomService, bool) {
	if current := customServices.Load(); current != nil {
		for _, service := range *current {
			if service.ID == id {
				return service, true
			}
		}
	}
	return CustomService{}, false
}

// IsCustomService reports whether the identifier names an existing custom card.
func IsCustomService(id string) bool {
	_, found := customService(id)
	return found
}

// CustomServiceID reports whether the identifier has the form of a custom card,
// existing or not. Saved settings of a card that was removed are recognised by it.
func CustomServiceID(id string) bool { return customIDPattern.MatchString(id) }

func NewCustomServiceID() (string, error) {
	var raw [4]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	return CustomServicePrefix + hex.EncodeToString(raw[:]), nil
}

// NormalizeCustomService checks the name and turns the address lines into the
// stored form: a domain, a full: host, a link (its host is taken), an IP
// address or a network.
func NormalizeCustomService(id, name string, addresses []string) (CustomService, error) {
	name = strings.Join(strings.Fields(name), " ")
	if !customIDPattern.MatchString(id) {
		return CustomService{}, errors.New("недопустимый идентификатор сервиса")
	}
	if name == "" || utf8.RuneCountInString(name) > maxCustomNameRunes {
		return CustomService{}, fmt.Errorf("дайте сервису название до %d символов", maxCustomNameRunes)
	}
	for _, r := range name {
		if r < 32 || r == 127 {
			return CustomService{}, errors.New("в названии сервиса есть недопустимый символ")
		}
	}
	service := CustomService{ID: id, Name: name, Domains: []string{}}
	seen := map[string]bool{}
	for _, line := range addresses {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		entry, err := NormalizeExclusion(line, "")
		if err != nil {
			return CustomService{}, fmt.Errorf("«%s»: %w", shorten(line), err)
		}
		value := entry.Value
		switch entry.Type {
		case "domain", "full":
		case "ip":
			prefix, err := netip.ParsePrefix(value)
			if err != nil {
				addr, _ := netip.ParseAddr(value)
				prefix = netip.PrefixFrom(addr, addr.BitLen())
			}
			// A whole-internet network would swallow every address without a name.
			if prefix.Bits() < 8 {
				return CustomService{}, fmt.Errorf("«%s»: сеть слишком широкая", shorten(line))
			}
			value = prefix.Masked().String()
		default:
			return CustomService{}, fmt.Errorf("«%s»: шаблоны со звёздочкой в своих сервисах не поддерживаются — укажите домен", shorten(line))
		}
		if seen[value] {
			continue
		}
		seen[value] = true
		if entry.Type == "ip" {
			service.Networks = append(service.Networks, value)
		} else {
			service.Domains = append(service.Domains, value)
		}
	}
	if count := len(service.Domains) + len(service.Networks); count == 0 {
		return CustomService{}, errors.New("укажите хотя бы один адрес сервиса")
	} else if count > maxCustomAddresses {
		return CustomService{}, fmt.Errorf("у сервиса может быть не больше %d адресов", maxCustomAddresses)
	}
	return service, nil
}

func shorten(text string) string {
	if utf8.RuneCountInString(text) <= 60 {
		return text
	}
	return string([]rune(text)[:60]) + "…"
}

// Addresses gives the lines a card was made of, in the form the owner edits.
func (s CustomService) Addresses() []string {
	result := make([]string, 0, len(s.Domains)+len(s.Networks))
	for _, domain := range s.Domains {
		result = append(result, strings.TrimPrefix(domain, "domain:"))
	}
	return append(result, s.Networks...)
}

func CustomServicesPath(dataDir string) string {
	return filepath.Join(dataDir, "custom-services.json")
}

// LoadCustomServices reads the saved cards. A damaged file is an error: the
// caller keeps the panel running without custom cards rather than guess.
func LoadCustomServices(dataDir string) ([]CustomService, error) {
	raw, err := os.ReadFile(CustomServicesPath(dataDir))
	if os.IsNotExist(err) {
		return nil, nil
	}
	damaged := errors.New("сохранённые свои сервисы повреждены")
	var stored struct {
		Services []CustomService `json:"services"`
	}
	if err != nil || json.Unmarshal(raw, &stored) != nil || len(stored.Services) > MaxCustomServices {
		return nil, damaged
	}
	seen := map[string]bool{}
	for _, service := range stored.Services {
		normal, err := NormalizeCustomService(service.ID, service.Name, service.Addresses())
		if err != nil || seen[service.ID] || !slices.Equal(normal.Domains, service.Domains) || !slices.Equal(normal.Networks, service.Networks) || normal.Name != service.Name {
			return nil, damaged
		}
		seen[service.ID] = true
	}
	return stored.Services, nil
}

func SaveCustomServices(dataDir string, list []CustomService) error {
	if list == nil {
		list = []CustomService{}
	}
	raw, err := json.MarshalIndent(map[string]interface{}{"services": list}, "", "  ")
	if err != nil {
		return err
	}
	if err = os.MkdirAll(dataDir, 0700); err != nil {
		return err
	}
	path := CustomServicesPath(dataDir)
	tmp := path + ".tmp"
	if err = os.WriteFile(tmp, append(raw, '\n'), 0600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// customForHost finds the custom card a host name belongs to.
func customForHost(host string) string {
	current := customServices.Load()
	if current == nil || len(*current) == 0 {
		return ""
	}
	for _, service := range *current {
		if slices.Contains(service.Domains, "full:"+host) {
			return service.ID
		}
	}
	for name := host; name != ""; {
		for _, service := range *current {
			if slices.Contains(service.Domains, "domain:"+name) {
				return service.ID
			}
		}
		_, rest, _ := strings.Cut(name, ".")
		name = rest
	}
	return ""
}
