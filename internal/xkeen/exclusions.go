package xkeen

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/netip"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"
	"unicode/utf8"
)

// Exclusions are uniquely tagged rules in the effective routing document.
// Xray replaces (rather than appends) routing when merging config fragments.
const exclusionRulePrefix = "panel-exclusion-"
const MaxExclusions = 500

type Exclusion struct {
	ID      string `json:"id"`
	Type    string `json:"type"`
	Value   string `json:"value"`
	Comment string `json:"comment"`
}

type Exclusions struct {
	Entries []Exclusion `json:"entries"`
}

func ExclusionsPath(dataDir string) string { return filepath.Join(dataDir, "exclusions.json") }
func ExclusionsConfigPath(rt Runtime) string {
	path := rt.RoutingFile
	for _, candidate := range ConfigFiles(rt) {
		var cfg map[string]interface{}
		if ReadJSONC(candidate, &cfg) == nil {
			if _, ok := cfg["routing"].(map[string]interface{}); ok {
				path = candidate
			}
		}
	}
	return path
}

func NormalizeExclusion(value, comment string) (Exclusion, error) {
	bad := func() (Exclusion, error) {
		return Exclusion{}, fmt.Errorf("укажите домен, HTTP(S) URL, IP или подсеть CIDR")
	}
	value, comment = strings.TrimSpace(value), strings.TrimSpace(comment)
	if len(value) == 0 || len(value) > 2048 || utf8.RuneCountInString(comment) > 200 || !utf8.ValidString(comment) {
		return bad()
	}
	for _, r := range comment {
		if r < 32 || r == 127 {
			return bad()
		}
	}
	kind := "domain"
	if strings.Contains(value, "://") {
		u, err := url.Parse(value)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.User != nil || u.Hostname() == "" {
			return bad()
		}
		value = u.Hostname()
	} else if strings.HasPrefix(value, "domain:") {
		value = strings.TrimPrefix(value, "domain:")
	} else if strings.HasPrefix(value, "full:") {
		kind, value = "full", strings.TrimPrefix(value, "full:")
	}
	value = strings.ToLower(strings.TrimSuffix(value, "."))
	if ip, err := netip.ParseAddr(value); err == nil && ip.Zone() == "" {
		kind, value = "ip", ip.Unmap().String()
	} else if prefix, err := netip.ParsePrefix(value); err == nil {
		kind, value = "ip", prefix.Masked().String()
	} else {
		if len(value) > 253 || !strings.Contains(value, ".") {
			return bad()
		}
		numeric := true
		for _, c := range value {
			if c != '.' && (c < '0' || c > '9') {
				numeric = false
			}
		}
		if numeric {
			return bad()
		}
		for _, label := range strings.Split(value, ".") {
			if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
				return bad()
			}
			for _, c := range label {
				if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
					return bad()
				}
			}
		}
		value = kind + ":" + value
	}
	hash := sha256.Sum256([]byte(kind + "\n" + value))
	return Exclusion{ID: hex.EncodeToString(hash[:16]), Type: kind, Value: value, Comment: comment}, nil
}

func LoadExclusions(dataDir string) (Exclusions, error) {
	result := Exclusions{Entries: []Exclusion{}}
	raw, err := os.ReadFile(ExclusionsPath(dataDir))
	if os.IsNotExist(err) {
		return result, nil
	}
	if err != nil || json.Unmarshal(raw, &result) != nil || len(result.Entries) > MaxExclusions {
		return Exclusions{}, fmt.Errorf("не удалось прочитать сохранённые исключения")
	}
	if result.Entries == nil {
		result.Entries = []Exclusion{}
	}
	seen := map[string]bool{}
	for _, entry := range result.Entries {
		normalized, err := NormalizeExclusion(entry.Value, entry.Comment)
		if err != nil || entry != normalized || seen[entry.ID] {
			return Exclusions{}, fmt.Errorf("сохранённые исключения повреждены")
		}
		seen[entry.ID] = true
	}
	return result, nil
}

func SaveExclusions(dataDir string, entries Exclusions) error {
	raw, err := json.MarshalIndent(entries, "", "  ")
	if err != nil {
		return err
	}
	return writeFileAtomic(ExclusionsPath(dataDir), append(raw, '\n'), 0600)
}

// BuildExclusionsConfig limits exceptions to actual client entrances. API,
// synthetic provider loopbacks, DNS and the forced VPN probe keep their routes.
func BuildExclusionsConfig(rt Runtime, entries Exclusions) (map[string]interface{}, error) {
	if rt.Core != CoreXray {
		return nil, fmt.Errorf("исключения поддерживаются при использовании Xray")
	}
	var clients []string
	direct := ""
	var document map[string]interface{}
	for _, path := range ConfigFiles(rt) {
		var cfg map[string]interface{}
		if err := ReadJSONC(path, &cfg); err != nil {
			return nil, fmt.Errorf("не удалось прочитать конфигурацию Xray")
		}
		if _, ok := cfg["routing"].(map[string]interface{}); ok {
			document = cfg
		}
		for _, raw := range asSlice(cfg["inbounds"]) {
			ib := mapOf(raw)
			tag, _ := ib["tag"].(string)
			proto, _ := ib["protocol"].(string)
			if tag != ProbeInboundTag && !IsProfileInternalTag(tag) && !strings.HasPrefix(tag, profileInboundPrefix) && profilePhysicalInput(tag, proto) {
				clients = append(clients, tag)
			}
		}
		for _, raw := range asSlice(cfg["outbounds"]) {
			ob := mapOf(raw)
			tag, _ := ob["tag"].(string)
			if ob["protocol"] == "freedom" && tag != "" && !IsProfileInternalTag(tag) && (direct == "" || tag == "direct") {
				direct = tag
			}
		}
	}
	sort.Strings(clients)
	if document == nil {
		return nil, fmt.Errorf("не найдена действующая маршрутизация Xray")
	}
	if len(entries.Entries) > 0 && (direct == "" || len(clients) == 0) {
		return nil, fmt.Errorf("не найдены клиентские входы или прямой выход Xray")
	}
	rules := []interface{}{}
	for _, entry := range entries.Entries {
		normalized, err := NormalizeExclusion(entry.Value, entry.Comment)
		if err != nil || entry != normalized {
			return nil, fmt.Errorf("некорректное исключение")
		}
		field := "domain"
		if entry.Type == "ip" {
			field = "ip"
		}
		rules = append(rules, map[string]interface{}{"type": "field", "ruleTag": exclusionRulePrefix + entry.ID, "inboundTag": clients, field: []string{entry.Value}, "outboundTag": direct})
	}
	routing := mapOf(document["routing"])
	for _, raw := range asSlice(routing["rules"]) {
		tag, _ := mapOf(raw)["ruleTag"].(string)
		if !strings.HasPrefix(tag, exclusionRulePrefix) {
			rules = append(rules, raw)
		}
	}
	routing["rules"] = rules
	return document, nil
}

// WriteExclusionsConfig validates a complete copy before touching the live
// routing file. The caller owns the surrounding file/runtime rollback transaction.
func WriteExclusionsConfig(rt Runtime, entries Exclusions) error {
	doc, err := BuildExclusionsConfig(rt, entries)
	if err != nil {
		return err
	}
	path := ExclusionsConfigPath(rt)
	if info, err := os.Lstat(path); err == nil && !info.Mode().IsRegular() {
		return fmt.Errorf("файл исключений не является обычным файлом")
	} else if err != nil && !os.IsNotExist(err) {
		return err
	}
	raw, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return err
	}
	if rt.Installed {
		if err := validateExclusionCandidate(rt, raw); err != nil {
			return err
		}
	}
	return writeFileAtomic(path, append(raw, '\n'), 0600)
}

func validateExclusionCandidate(rt Runtime, raw []byte) error {
	if rt.CoreBin == "" {
		return fmt.Errorf("проверка Xray недоступна")
	}
	dir, err := os.MkdirTemp(filepath.Dir(rt.XrayConfDir), ".panel-exclusions-test-*")
	if err != nil {
		return fmt.Errorf("не удалось подготовить проверку исключений")
	}
	defer os.RemoveAll(dir)
	for _, path := range ConfigFiles(rt) {
		if path == ExclusionsConfigPath(rt) {
			continue
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("не удалось подготовить проверку исключений")
		}
		if err := os.WriteFile(filepath.Join(dir, filepath.Base(path)), data, 0600); err != nil {
			return err
		}
	}
	if err := os.WriteFile(filepath.Join(dir, filepath.Base(ExclusionsConfigPath(rt))), raw, 0600); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, rt.CoreBin, "run", "-test", "-confdir", dir)
	for _, env := range os.Environ() {
		if !strings.HasPrefix(env, "XRAY_LOCATION_CONFDIR=") && !strings.HasPrefix(env, "XRAY_LOCATION_CONFIG=") && !strings.HasPrefix(env, "XRAY_LOCATION_ASSET=") {
			cmd.Env = append(cmd.Env, env)
		}
	}
	cmd.Env = append(cmd.Env, "XRAY_LOCATION_ASSET="+filepath.Join(filepath.Dir(rt.XrayConfDir), "dat"))
	// Core diagnostics can quote the active provider configuration. Keep the
	// API error generic instead of returning any subprocess output to clients.
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("Xray отклонил исключения; прежние настройки сохранены")
	}
	return nil
}
