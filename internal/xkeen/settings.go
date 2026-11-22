package xkeen

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// ListKind picks the validation applied to an XKeen list file.
type ListKind string

const (
	ListPorts ListKind = "ports"
	ListIPs   ListKind = "ips"
)

// listFiles maps the API name of a list to its file and validation.
var listFiles = map[string]struct {
	file string
	kind ListKind
}{
	"port_proxying": {"port_proxying.lst", ListPorts},
	"port_exclude":  {"port_exclude.lst", ListPorts},
	"ip_exclude":    {"ip_exclude.lst", ListIPs},
}

// ListNames returns the editable list names.
func ListNames() []string {
	names := make([]string, 0, len(listFiles))
	for name := range listFiles {
		names = append(names, name)
	}
	return names
}

// ListPath resolves an XKeen list file next to xkeen.json.
func ListPath(rt Runtime, name string) (string, ListKind, error) {
	entry, ok := listFiles[name]
	if !ok {
		return "", "", fmt.Errorf("неизвестный список %q", name)
	}
	return filepath.Join(filepath.Dir(rt.XkeenJSON), entry.file), entry.kind, nil
}

// ReadSettings loads xkeen.json. A missing file is an empty config — XKeen
// treats it the same way.
func ReadSettings(path string) (map[string]interface{}, error) {
	var cfg map[string]interface{}
	if err := ReadJSONC(path, &cfg); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return map[string]interface{}{}, nil
		}
		return nil, err
	}
	if cfg == nil {
		cfg = map[string]interface{}{}
	}

	return cfg, nil
}

// WriteSettings validates and stores xkeen.json.
//
// Comments in the original are lost — the panel serialises the parsed tree — so
// the previous content is kept as .bak.
func WriteSettings(path string, cfg map[string]interface{}) error {
	if err := ValidateSettings(cfg); err != nil {
		return err
	}

	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return fmt.Errorf("ошибка сериализации xkeen.json: %w", err)
	}

	if err := backupFile(path); err != nil {
		return err
	}

	return writeFileAtomic(path, data, 0644)
}

// WriteList stores a list file, keeping the previous content as .bak.
func WriteList(path, content string) error {
	if !strings.HasSuffix(content, "\n") {
		content += "\n"
	}

	if err := backupFile(path); err != nil {
		return err
	}

	return writeFileAtomic(path, []byte(content), 0644)
}

// ValidateSettings mirrors the checks XKeen runs on startup: an `xkeen` section
// whose `policy` entries lack a name makes the proxy refuse to start, and the
// panel must not be able to produce that file.
func ValidateSettings(cfg map[string]interface{}) error {
	section, ok := cfg["xkeen"]
	if !ok {
		return nil
	}

	xkeenSection, ok := section.(map[string]interface{})
	if !ok {
		return fmt.Errorf("секция xkeen должна быть объектом")
	}

	policies, exists := xkeenSection["policy"]
	if !exists {
		return nil
	}

	list, ok := policies.([]interface{})
	if !ok {
		return fmt.Errorf("xkeen.policy должен быть массивом")
	}

	for i, raw := range list {
		policy, ok := raw.(map[string]interface{})
		if !ok {
			return fmt.Errorf("xkeen.policy[%d] должен быть объектом", i)
		}
		if name, _ := policy["name"].(string); strings.TrimSpace(name) == "" {
			return fmt.Errorf("xkeen.policy[%d] без имени — XKeen не запустит прокси с таким файлом", i)
		}
	}

	return nil
}

// ValidateList checks the entries of a list file. Comments and blank lines are
// left alone: the shipped files are full of commented examples that the owner
// uncomments, and rewriting them would destroy that.
func ValidateList(content string, kind ListKind) error {
	for i, line := range strings.Split(content, "\n") {
		entry := strings.TrimSpace(line)
		if entry == "" || strings.HasPrefix(entry, "#") {
			continue
		}

		var err error
		switch kind {
		case ListPorts:
			err = validatePortEntry(entry)
		case ListIPs:
			err = validateIPEntry(entry)
		}
		if err != nil {
			return fmt.Errorf("строка %d: %w", i+1, err)
		}
	}

	return nil
}

// ListEntries returns the working lines of a list file: no comments, no blanks.
func ListEntries(content string) []string {
	var entries []string
	for _, line := range strings.Split(content, "\n") {
		entry, _, _ := strings.Cut(line, "#")
		if entry = strings.TrimSpace(entry); entry != "" {
			entries = append(entries, entry)
		}
	}
	return entries
}

// PortListCovers reports whether a port list names the port, alone or inside
// a range.
func PortListCovers(content string, port int) bool {
	for _, entry := range ListEntries(content) {
		low, high, isRange := strings.Cut(entry, ":")
		from, err := parsePort(low)
		if err != nil {
			continue
		}
		to := from
		if isRange {
			if to, err = parsePort(high); err != nil {
				continue
			}
		}
		if from <= port && port <= to {
			return true
		}
	}
	return false
}

// CheckListPolicy refuses a list the panel must not write. A filled
// port_proxying list sends every port it does not name past the core. That is
// a usual way to spare the router, as long as ordinary sites and applications
// (443 and 80) still reach the core.
func CheckListPolicy(name, content string) error {
	if name != "port_proxying" || len(ListEntries(content)) == 0 {
		return nil
	}
	for _, port := range []int{443, 80} {
		if !PortListCovers(content, port) {
			return fmt.Errorf("в списке нет порта %d. Без портов 80 и 443 обычные сайты и приложения пойдут мимо VPN. Добавьте их или очистите список", port)
		}
	}
	return nil
}

// DefaultProxyPorts is what the first-run wizard writes to port_proxying:
// ordinary sites and applications (80, 443), the relays of Telegram calls
// (596:599, the range of XKeen's own sample file) and the range usually added
// next to them when XKeen is set up. Everything else goes to the provider
// before the core and loads the router less.
var DefaultProxyPorts = []string{"80", "443", "596:599", "50000:50030"}

// ProxyPortsUnset reports whether the owner has chosen no ports yet: neither
// "only these ports" nor "these ports past the VPN" has a working line.
func ProxyPortsUnset(rt Runtime) bool {
	for _, name := range []string{"port_proxying", "port_exclude"} {
		path, _, err := ListPath(rt, name)
		if err != nil {
			return false
		}
		content, err := os.ReadFile(path)
		if err != nil && !os.IsNotExist(err) || len(ListEntries(string(content))) > 0 {
			return false
		}
	}
	return true
}

// ApplyDefaultProxyPorts fills port_proxying while no ports are chosen. The
// commented examples of the shipped file stay. It reports whether the file
// was written; XKeen reads it when it starts.
func ApplyDefaultProxyPorts(rt Runtime) (bool, error) {
	if !ProxyPortsUnset(rt) {
		return false, nil
	}
	path, _, err := ListPath(rt, "port_proxying")
	if err != nil {
		return false, err
	}
	content, err := os.ReadFile(path)
	if err != nil && !os.IsNotExist(err) {
		return false, err
	}
	text := string(content)
	if text != "" && !strings.HasSuffix(text, "\n") {
		text += "\n"
	}
	text += strings.Join(DefaultProxyPorts, "\n") + "\n"
	if err := CheckListPolicy("port_proxying", text); err != nil {
		return false, err
	}
	return true, WriteList(path, text)
}

// validatePortEntry accepts a single port or an XKeen range like 596:599.
func validatePortEntry(entry string) error {
	low, high, isRange := strings.Cut(entry, ":")

	from, err := parsePort(low)
	if err != nil {
		return err
	}
	if !isRange {
		return nil
	}

	to, err := parsePort(high)
	if err != nil {
		return err
	}
	if to <= from {
		return fmt.Errorf("диапазон %q: конец должен быть больше начала", entry)
	}

	return nil
}

func parsePort(text string) (int, error) {
	port, err := strconv.Atoi(strings.TrimSpace(text))
	if err != nil {
		return 0, fmt.Errorf("%q — не порт", text)
	}
	if port < 1 || port > 65535 {
		return 0, fmt.Errorf("порт %d вне диапазона 1–65535", port)
	}
	return port, nil
}

// validateIPEntry requires a prefix length. XKeen feeds these lines to ipset,
// which rejects a bare address, so /32 (or /128) has to be spelled out.
func validateIPEntry(entry string) error {
	address, prefix, ok := strings.Cut(entry, "/")
	if !ok {
		return fmt.Errorf("%q без маски — укажите /32 для одиночного адреса", entry)
	}

	bits, err := strconv.Atoi(prefix)
	if err != nil {
		return fmt.Errorf("%q: маска должна быть числом", entry)
	}

	maxBits := 32
	if strings.Contains(address, ":") {
		maxBits = 128
	}
	if bits < 0 || bits > maxBits {
		return fmt.Errorf("%q: маска вне диапазона 0–%d", entry, maxBits)
	}
	if strings.TrimSpace(address) == "" {
		return fmt.Errorf("%q: пустой адрес", entry)
	}

	return nil
}
