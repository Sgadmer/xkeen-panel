package xkeen

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
)

const routingPolicyRulePrefix = "panel-policy-"

// RoutingPolicy is kept outside *.json: it is control state, not an Xray
// fragment (Xray replaces routing wholesale when merging fragments).
type RoutingPolicy struct {
	Mode      string   `json:"mode"`
	Services  []string `json:"services"`
	Addresses []string `json:"addresses"`
}
type routingPolicyStored struct {
	RoutingPolicy
	Sniffing []profileSniffBaseline `json:"sniffing_baseline,omitempty"`
}
type RoutingService struct {
	ID      string   `json:"id"`
	Name    string   `json:"name"`
	Domains []string `json:"domains"`
}

var routingServices = []RoutingService{
	{"youtube", "YouTube", []string{"domain:youtube.com", "domain:youtu.be", "domain:googlevideo.com", "domain:ytimg.com", "domain:youtubei.googleapis.com"}},
	{"telegram", "Telegram", []string{"domain:telegram.org", "domain:t.me", "domain:telegram.me", "domain:tdesktop.com"}},
	{"instagram", "Instagram", []string{"domain:instagram.com", "domain:cdninstagram.com"}},
	{"facebook", "Facebook", []string{"domain:facebook.com", "domain:fbcdn.net", "domain:facebook.net"}},
	{"discord", "Discord", []string{"domain:discord.com", "domain:discord.gg", "domain:discordapp.com", "domain:discordapp.net", "domain:discord.media"}},
	{"openai", "ChatGPT / OpenAI", []string{"domain:chatgpt.com", "domain:openai.com", "domain:oaistatic.com", "domain:oaiusercontent.com"}},
	{"netflix", "Netflix", []string{"domain:netflix.com", "domain:nflxvideo.net", "domain:nflximg.net", "domain:nflxso.net", "domain:nflxext.com"}},
}

func RoutingServices() []RoutingService {
	result := make([]RoutingService, len(routingServices))
	for i, s := range routingServices {
		result[i] = s
		result[i].Domains = append([]string(nil), s.Domains...)
	}
	return result
}
func RoutingPolicyPath(rt Runtime) string {
	return filepath.Join(rt.XrayConfDir, ".panel-routing-policy")
}

func NormalizeRoutingPolicy(p RoutingPolicy) (RoutingPolicy, error) {
	if p.Mode != "preserve" && p.Mode != "selected" && p.Mode != "all" {
		return p, fmt.Errorf("выберите текущую политику, выбранные сервисы или весь трафик")
	}
	if len(p.Services) > len(routingServices) || len(p.Addresses) > 500 {
		return p, fmt.Errorf("слишком много правил маршрутизации")
	}
	known := map[string]bool{}
	for _, s := range routingServices {
		known[s.ID] = true
	}
	services := []string{}
	seen := map[string]bool{}
	for _, id := range p.Services {
		if !known[id] {
			return p, fmt.Errorf("неизвестный сервис")
		}
		if !seen[id] {
			services = append(services, id)
			seen[id] = true
		}
	}
	addresses := []string{}
	seen = map[string]bool{}
	for _, value := range p.Addresses {
		entry, err := NormalizeExclusion(value, "")
		if err != nil {
			return p, err
		}
		if !seen[entry.Value] {
			addresses = append(addresses, entry.Value)
			seen[entry.Value] = true
		}
	}
	sort.Strings(services)
	sort.Strings(addresses)
	return RoutingPolicy{Mode: p.Mode, Services: services, Addresses: addresses}, nil
}

func LoadRoutingPolicy(rt Runtime) (RoutingPolicy, error) {
	stored, err := loadRoutingPolicyStored(rt)
	return stored.RoutingPolicy, err
}

func loadRoutingPolicyStored(rt Runtime) (routingPolicyStored, error) {
	p := RoutingPolicy{Mode: "preserve", Services: []string{}, Addresses: []string{}}
	stored := routingPolicyStored{RoutingPolicy: p}
	raw, err := os.ReadFile(RoutingPolicyPath(rt))
	if os.IsNotExist(err) {
		return stored, nil
	}
	if err != nil {
		return stored, fmt.Errorf("не удалось прочитать режим маршрутизации")
	}
	if json.Unmarshal(raw, &stored) != nil {
		return stored, fmt.Errorf("сохранённый режим маршрутизации повреждён")
	}
	stored.RoutingPolicy, err = NormalizeRoutingPolicy(stored.RoutingPolicy)
	for _, baseline := range stored.Sniffing {
		if !withinConfigDir(rt, baseline.File) || baseline.Tag == "" {
			return stored, fmt.Errorf("состояние распознавания доменов повреждено")
		}
	}
	return stored, err
}

// SetRoutingPolicy is called inside the API file/runtime transaction. No
// provider profile is silently flattened into the outer balancer.
func SetRoutingPolicy(rt Runtime, outboundsPath string, p RoutingPolicy) error {
	p, err := NormalizeRoutingPolicy(p)
	if err != nil {
		return err
	}
	if rt.Core != CoreXray {
		return fmt.Errorf("режимы маршрутизации поддерживаются с ядром Xray")
	}
	if p.Mode != "preserve" && HasActiveProfile(outboundsPath) {
		return fmt.Errorf("этот профиль содержит свои правила; для ручного режима выберите обычный сервер")
	}
	stored, err := loadRoutingPolicyStored(rt)
	if err != nil {
		return err
	}
	if p.Mode != "preserve" && stored.Mode == "preserve" {
		stored.Sniffing = nil
		for _, path := range ConfigFiles(rt) {
			var doc map[string]interface{}
			if ReadJSONC(path, &doc) != nil {
				return fmt.Errorf("не удалось сохранить распознавание доменов")
			}
			for _, raw := range asSlice(doc["inbounds"]) {
				ib := mapOf(raw)
				tag, _ := ib["tag"].(string)
				proto, _ := ib["protocol"].(string)
				if policyClientInput(tag, proto) {
					value, exists := ib["sniffing"]
					stored.Sniffing = append(stored.Sniffing, profileSniffBaseline{File: path, Tag: tag, Value: value, Exists: exists})
				}
			}
		}
	}
	stored.RoutingPolicy = p
	raw, err := json.Marshal(stored)
	if err != nil {
		return err
	}
	if err := writeFileAtomic(RoutingPolicyPath(rt), raw, 0600); err != nil {
		return fmt.Errorf("не удалось сохранить режим маршрутизации")
	}
	if err := applyConfigs(rt, map[string]map[string]interface{}{}); err != nil {
		return err
	}
	if p.Mode == "preserve" {
		stored.Sniffing = nil
		raw, _ := json.Marshal(stored)
		return writeFileAtomic(RoutingPolicyPath(rt), raw, 0600)
	}
	return nil
}

// applyRoutingPolicy runs before every managed config write (pool, profile,
// refresh, selection). It rewrites only owned rules and never drops foreign
// rules: Preserve removes the override and restores their original order.
func applyRoutingPolicy(rt Runtime, writes map[string]map[string]interface{}) error {
	if _, err := os.Stat(RoutingPolicyPath(rt)); os.IsNotExist(err) {
		return nil
	} else if err != nil {
		return err
	}
	stored, err := loadRoutingPolicyStored(rt)
	if err != nil {
		return err
	}
	p := stored.RoutingPolicy
	paths := ConfigFiles(rt)
	for path := range writes {
		found := false
		for _, v := range paths {
			if path == v {
				found = true
			}
		}
		if !found {
			paths = append(paths, path)
		}
	}
	sort.Strings(paths)
	docs := map[string]map[string]interface{}{}
	routePath := ""
	direct := ""
	proxyTags := map[string]bool{}
	var clients []string
	for _, path := range paths {
		doc := writes[path]
		if doc == nil {
			if ReadJSONC(path, &doc) != nil {
				return fmt.Errorf("не удалось прочитать конфигурацию маршрутизации")
			}
		}
		docs[path] = doc
		if _, ok := doc["routing"].(map[string]interface{}); ok {
			routePath = path
		}
		for _, raw := range asSlice(doc["inbounds"]) {
			ib := mapOf(raw)
			tag, _ := ib["tag"].(string)
			proto, _ := ib["protocol"].(string)
			if policyClientInput(tag, proto) {
				clients = profileAppendUnique(clients, tag)
				if p.Mode != "preserve" {
					sniff := mapOf(ib["sniffing"])
					if sniff == nil {
						sniff = map[string]interface{}{}
					}
					overrides := stringList(sniff["destOverride"])
					for _, kind := range []string{"http", "tls", "quic"} {
						if !containsPolicyString(overrides, kind) {
							overrides = append(overrides, kind)
						}
					}
					if sniff["enabled"] != true || !reflect.DeepEqual(stringList(sniff["destOverride"]), overrides) {
						sniff["enabled"] = true
						sniff["destOverride"] = overrides
						ib["sniffing"] = sniff
						writes[path] = doc
					}
				} else {
					for _, baseline := range stored.Sniffing {
						if baseline.File == path && baseline.Tag == tag {
							if baseline.Exists {
								ib["sniffing"] = baseline.Value
							} else {
								delete(ib, "sniffing")
							}
							writes[path] = doc
						}
					}
				}
			}
		}
		for _, raw := range asSlice(doc["outbounds"]) {
			ob := mapOf(raw)
			tag := outboundTag(ob)
			if ob["protocol"] == "freedom" && !IsProfileInternalTag(tag) && (direct == "" || tag == "direct") {
				direct = tag
			}
			if !isServiceOutbound(ob) && !IsProfileInternalTag(tag) && tag != "" {
				proxyTags[tag] = true
			}
		}
	}
	if routePath == "" {
		return fmt.Errorf("не найдена действующая маршрутизация")
	}
	doc := docs[routePath]
	routing := mapOf(doc["routing"])
	var original []interface{}
	var exclusions []interface{}
	var dnsRules []interface{}
	for _, raw := range asSlice(routing["rules"]) {
		rule := mapOf(raw)
		tag, _ := rule["ruleTag"].(string)
		if strings.HasPrefix(tag, routingPolicyRulePrefix) {
			continue
		}
		original = append(original, raw)
		if strings.HasPrefix(tag, exclusionRulePrefix) {
			exclusions = append(exclusions, raw)
		}
		// Client DNS must reach its existing resolver, not the mode catchall. Any
		// foreign rule remains below the policy again when Preserve is selected.
		if rule["port"] == "53" {
			copy, err := cloneProfileRule(rule)
			if err != nil {
				return err
			}
			copy["ruleTag"] = fmt.Sprintf("%sdns-%d", routingPolicyRulePrefix, len(dnsRules))
			dnsRules = append(dnsRules, copy)
		}
	}
	if p.Mode == "preserve" {
		if !reflect.DeepEqual(original, asSlice(routing["rules"])) {
			routing["rules"] = original
			writes[routePath] = doc
		}
		return nil
	}
	if direct == "" || len(clients) == 0 {
		return fmt.Errorf("не найдены клиентские входы или прямой выход")
	}
	sort.Strings(clients)
	targetKey, target := "", ""
	for _, raw := range original {
		r := mapOf(raw)
		in := stringList(r["inboundTag"])
		client := len(in) == 0
		for _, s := range clients {
			if containsPolicyString(in, s) {
				client = true
			}
		}
		if !client {
			continue
		}
		b, _ := r["balancerTag"].(string)
		o, _ := r["outboundTag"].(string)
		if IsProfileInternalTag(b) || IsProfileInternalTag(o) {
			return fmt.Errorf("этот профиль содержит свои правила; для ручного режима выберите обычный сервер")
		}
		if b != "" {
			targetKey, target = "balancerTag", b
		}
		if proxyTags[o] && target == "" {
			targetKey, target = "outboundTag", o
		}
	}
	if target == "" {
		return fmt.Errorf("не найден действующий выход VPN; сначала настройте сервер")
	}
	rule := func(tag string, fields map[string]interface{}) map[string]interface{} {
		r := map[string]interface{}{"type": "field", "ruleTag": routingPolicyRulePrefix + tag, "inboundTag": clients}
		for k, v := range fields {
			r[k] = v
		}
		return r
	}
	owned := []interface{}{rule("local", map[string]interface{}{"ip": []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "169.254.0.0/16", "224.0.0.0/4", "255.255.255.255/32", "::1/128", "fc00::/7", "fe80::/10", "ff00::/8"}, "outboundTag": direct})}
	if p.Mode == "all" {
		owned = append(owned, rule("all", map[string]interface{}{"network": "tcp,udp", targetKey: target}))
	} else {
		var domains, ips []string
		for _, id := range p.Services {
			for _, service := range routingServices {
				if service.ID == id {
					domains = append(domains, service.Domains...)
					if id == "telegram" {
						ips = append(ips, "149.154.160.0/20", "91.108.4.0/22", "91.108.8.0/22", "91.108.12.0/22", "91.108.16.0/22", "91.108.20.0/22", "91.108.56.0/22")
					}
				}
			}
		}
		for _, address := range p.Addresses {
			entry, _ := NormalizeExclusion(address, "")
			if entry.Type == "ip" {
				ips = append(ips, entry.Value)
			} else {
				domains = append(domains, entry.Value)
			}
		}
		if len(domains) > 0 {
			owned = append(owned, rule("domains", map[string]interface{}{"domain": domains, targetKey: target}))
		}
		if len(ips) > 0 {
			owned = append(owned, rule("ips", map[string]interface{}{"ip": ips, targetKey: target}))
		}
		owned = append(owned, rule("direct-default", map[string]interface{}{"network": "tcp,udp", "outboundTag": direct}))
	}
	var remaining []interface{}
	for _, raw := range original {
		r := mapOf(raw)
		tag, _ := r["ruleTag"].(string)
		if strings.HasPrefix(tag, exclusionRulePrefix) {
			continue
		}
		remaining = append(remaining, raw)
	}
	combined := append(append(append(append([]interface{}{}, exclusions...), dnsRules...), owned...), remaining...)
	if !reflect.DeepEqual(combined, asSlice(routing["rules"])) {
		routing["rules"] = combined
		writes[routePath] = doc
	}
	return nil
}
func containsPolicyString(v []string, w string) bool {
	for _, s := range v {
		if s == w {
			return true
		}
	}
	return false
}

func policyClientInput(tag, proto string) bool {
	return tag != ProbeInboundTag && !IsProfileInternalTag(tag) && !strings.HasPrefix(tag, profileInboundPrefix) && profilePhysicalInput(tag, proto)
}
