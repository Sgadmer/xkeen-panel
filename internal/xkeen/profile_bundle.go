package xkeen

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"xkeen-panel/internal/models"
)

// ProfileBundle is a single provider profile rendered into the existing core.
// No listener, external process or production file is created by this renderer.
// Rules use owned virtual inputs as a reusable intermediate representation.
// BindProfileRules maps client traffic directly onto the router's real inputs;
// the virtual entry is a guarded control identity, not the data path.
// Globals always includes dns/policy/observatory/burstObservatory; a nil value
// means remove that baseline key while this profile is active. RoutingGlobals
// has the same convention for routing.domainStrategy and legacy domainMatcher.
// Xray v26.3.27 ignores domainMatcher and always uses its native MPH matcher;
// recognized legacy values are retained without claiming to restore old modes.
// Sniffing is an explicit
// requirement for the router's actual entry inbounds; Xray v26.3.27 loopback
// accepts only inboundTag, so putting sniffing on loopback would silently lose it.
type ProfileBundle struct {
	Entry             map[string]interface{}
	InternalOutbounds []interface{}
	Rules             []interface{}
	Balancers         []interface{}
	Globals           map[string]interface{}
	RoutingGlobals    map[string]interface{}
	Sniffing          map[string]interface{}
	InboundTag        string
	Namespace         string
	Adaptations       []string
}

type profileRenderer struct {
	bundle       ProfileBundle
	document     map[string]interface{}
	outbounds    []map[string]interface{}
	outboundTags map[string]string
	balancerTags map[string]string
	inboundTags  map[string]string
	loopbackTags map[string]string
	syntheticDNS map[string]bool
	ownedTags    []string
	graph        map[string][]string
}

func profileError() error {
	return fmt.Errorf("профиль содержит неподдерживаемую или неоднозначную конфигурацию Xray")
}

type profileRenderError struct {
	phase string
	cause error
}

func (e *profileRenderError) Error() string {
	return "profile-render/" + e.phase + ": " + e.cause.Error()
}
func (e *profileRenderError) Unwrap() error { return e.cause }

// ProfileRenderPhase returns a fixed ASCII diagnostic code, never source keys,
// tags, values or credentials. An empty result means the error came from another
// component. It remains safe when the original error is wrapped by its caller.
func ProfileRenderPhase(err error) string {
	var renderError *profileRenderError
	if errors.As(err, &renderError) {
		return renderError.phase
	}
	return ""
}

func profilePhaseError(phase string, err error) error {
	return &profileRenderError{phase: phase, cause: err}
}

// BuildProfileBundle preserves provider routing/leastLoad settings and gives
// every internal tag a profile-specific namespace. It validates dependencies
// before returning anything the caller could apply. The caller is responsible
// for the transactional restart and for restoring baseline global components.
func BuildProfileBundle(server models.Server, tag string, template map[string]interface{}) (ProfileBundle, error) {
	var empty ProfileBundle
	if len(server.RawProfile) == 0 || len(server.RawProfile) > maxSubscriptionBody || tag == "" {
		return empty, profilePhaseError("input", profileError())
	}
	document, err := decodeServerOutbound(server.RawProfile)
	if err != nil {
		return empty, profilePhaseError("decode", profileError())
	}
	identity := ProfileIdentity(server)
	hash := strings.TrimPrefix(identity, profileIdentityPrefix)
	if !profileHashPattern.MatchString(hash) {
		return empty, profilePhaseError("identity", profileError())
	}
	entry, err := BuildProfileEntry(server, tag, template)
	if err != nil {
		return empty, profilePhaseError("entry", profileError())
	}
	r := profileRenderer{
		document: document,
		bundle: ProfileBundle{Entry: entry, Namespace: "xkp-" + hash + "-", InboundTag: profileInboundPrefix + hash,
			Globals:        map[string]interface{}{"dns": nil, "policy": nil, "observatory": nil, "burstObservatory": nil},
			RoutingGlobals: map[string]interface{}{"domainStrategy": nil, "domainMatcher": nil}},
		outboundTags: map[string]string{}, balancerTags: map[string]string{}, inboundTags: map[string]string{}, loopbackTags: map[string]string{}, syntheticDNS: map[string]bool{}, graph: map[string][]string{},
	}
	if err := r.build(template); err != nil {
		return empty, err
	}
	return r.bundle, nil
}

func (r *profileRenderer) build(template map[string]interface{}) (err error) {
	phase := "schema"
	defer func() {
		if err != nil {
			err = profilePhaseError(phase, err)
		}
	}()
	if !profileKeys(r.document, "remarks", "name", "ps", "remark", "tag", "log", "inbounds", "outbounds", "routing", "dns", "policy", "observatory", "burstObservatory") {
		return profileError()
	}
	r.ownedTags = []string{r.bundle.InboundTag}
	phase = "clients"
	if err := r.clientInbounds(); err != nil {
		return err
	}
	phase = "dns"
	if err := r.dns(); err != nil {
		return err
	}
	phase = "outbound-index"
	items, ok := r.document["outbounds"].([]interface{})
	if !ok || len(items) == 0 || len(items) > 256 {
		return profileError()
	}
	for _, item := range items {
		outbound := mapOf(item)
		name, _ := outbound["tag"].(string)
		protocol, _ := outbound["protocol"].(string)
		if outbound == nil || name == "" || r.outboundTags[name] != "" || !profileProtocol(protocol) {
			return profileError()
		}
		r.outboundTags[name] = r.bundle.Namespace + "ob-" + name
		r.outbounds = append(r.outbounds, outbound)
		if protocol == "loopback" {
			settings := mapOf(outbound["settings"])
			inbound, _ := settings["inboundTag"].(string)
			if inbound == "" || !profileKeys(settings, "inboundTag") {
				return profileError()
			}
			alias := r.bundle.Namespace + "loop-" + inbound
			r.loopbackTags[inbound] = alias
			if r.inboundTags[inbound] == "" {
				r.inboundTags[inbound] = alias
			}
			r.ownedTags = profileAppendUnique(r.ownedTags, alias)
		}
	}
	phase = "routing"
	routing := mapOf(r.document["routing"])
	if _, exists := r.document["routing"]; exists && routing == nil {
		return profileError()
	}
	if !profileKeys(routing, "rules", "balancers", "domainStrategy", "domainMatcher") {
		return profileError()
	}
	if strategy, present := routing["domainStrategy"]; present {
		value, ok := strategy.(string)
		if !ok || !profileOneOf(strings.ToLower(value), "asis", "ipifnonmatch", "ipondemand") {
			return profileError()
		}
		r.bundle.RoutingGlobals["domainStrategy"] = value
	}
	if matcher, present := routing["domainMatcher"]; present {
		value, ok := matcher.(string)
		if !ok || !profileOneOf(value, "", "linear", "hybrid", "mph") {
			return profileError()
		}
		r.bundle.RoutingGlobals["domainMatcher"] = value
	}
	phase = "balancer-index"
	balancers, err := profileArray(routing, "balancers", 64)
	if err != nil {
		return profileError()
	}
	for _, item := range balancers {
		balancer := mapOf(item)
		name, _ := balancer["tag"].(string)
		if name == "" || r.balancerTags[name] != "" {
			return profileError()
		}
		r.balancerTags[name] = r.bundle.Namespace + "bal-" + name
	}
	phase = "rules"
	rules, err := profileArray(routing, "rules", 2048)
	if err != nil {
		return err
	}
	phase = "dns-adapter"
	if err := r.adaptClientDNSOutbounds(rules, balancers); err != nil {
		return err
	}
	phase = "outbounds"
	for _, outbound := range r.outbounds {
		if err := r.outbound(outbound, template); err != nil {
			return err
		}
	}
	phase = "balancers"
	for _, item := range balancers {
		if err := r.balancer(mapOf(item)); err != nil {
			return err
		}
	}
	phase = "rules"
	if err := r.rules(rules); err != nil {
		return err
	}
	phase = "observer"
	if err := r.observer(); err != nil {
		return err
	}
	phase = "policy"
	if policy, exists := r.document["policy"]; exists && policy != nil {
		value := mapOf(policy)
		if value == nil || !profileKeys(value, "levels", "system") {
			return profileError()
		}
		r.bundle.Globals["policy"] = value
	}
	phase = "cycles"
	if profileGraphCycle(r.graph) {
		return fmt.Errorf("составной профиль содержит цикл маршрутизации")
	}
	return nil
}

func (r *profileRenderer) clientInbounds() error {
	items, err := profileArray(r.document, "inbounds", 16)
	if err != nil {
		return err
	}
	var sniffingJSON string
	for _, item := range items {
		inbound := mapOf(item)
		protocol, _ := inbound["protocol"].(string)
		if inbound == nil || !profileOneOf(protocol, "socks", "http", "mixed") || !profileKeys(inbound, "protocol", "tag", "listen", "port", "settings", "sniffing", "streamSettings") {
			return profileError()
		}
		name, _ := inbound["tag"].(string)
		if name != "" {
			if r.inboundTags[name] != "" {
				return profileError()
			}
			r.inboundTags[name] = r.bundle.InboundTag
		}
		if value, present := inbound["streamSettings"]; present && value != nil && mapOf(value) == nil {
			return profileError()
		}
		if stream := mapOf(inbound["streamSettings"]); len(stream) > 0 {
			return profileError()
		}
		if value, present := inbound["sniffing"]; present && value != nil && mapOf(value) == nil {
			return profileError()
		}
		sniffing := mapOf(inbound["sniffing"])
		if sniffing != nil {
			if !profileKeys(sniffing, "enabled", "destOverride", "domainsExcluded", "metadataOnly", "routeOnly") {
				return profileError()
			}
			for _, key := range []string{"enabled", "metadataOnly", "routeOnly"} {
				if value, exists := sniffing[key]; exists {
					if _, ok := value.(bool); !ok {
						return profileError()
					}
				}
			}
			for _, key := range []string{"destOverride", "domainsExcluded"} {
				if value, exists := sniffing[key]; exists {
					values, err := profileStrings(value)
					if err != nil {
						return err
					}
					if key == "destOverride" {
						for _, value := range values {
							if !profileOneOf(value, "http", "tls", "quic") {
								return profileError()
							}
						}
					}
				}
			}
		}
		encoded, _ := json.Marshal(sniffing)
		if sniffingJSON != "" && sniffingJSON != string(encoded) {
			return fmt.Errorf("разные настройки sniffing входов профиля не поддерживаются")
		}
		sniffingJSON = string(encoded)
		r.bundle.Sniffing = sniffing
	}
	return nil
}

func (r *profileRenderer) dns() error {
	value, exists := r.document["dns"]
	if !exists || value == nil {
		return nil
	}
	dns := mapOf(value)
	if dns == nil || !profileKeys(dns, "servers", "hosts", "clientIp", "tag", "queryStrategy", "disableCache", "serveStale", "serveExpiredTTL", "disableFallback", "disableFallbackIfMatch", "enableParallelQuery", "useSystemHosts") {
		return profileError()
	}
	if err := r.dnsTag(dns); err != nil {
		return err
	}
	servers, err := profileArray(dns, "servers", 64)
	if err != nil {
		return err
	}
	for _, server := range servers {
		if address, ok := server.(string); ok {
			if strings.HasPrefix(strings.ToLower(address), "fakedns") {
				return profileError()
			}
			continue
		}
		object := mapOf(server)
		if object == nil || !profileKeys(object, "address", "clientIp", "port", "skipFallback", "domains", "expectedIPs", "expectIPs", "queryStrategy", "tag", "timeoutMs", "disableCache", "serveStale", "serveExpiredTTL", "finalQuery", "unexpectedIPs") {
			return profileError()
		}
		if err := r.dnsTag(object); err != nil {
			return err
		}
	}
	if tag, _ := dns["tag"].(string); tag == "" {
		// Native Xray otherwise generates a random tag for these queries. A
		// stable owned tag lets the same unscoped provider rules match them
		// after embedding, without falling through to the router's outer pool.
		// Do not register a source-tag mapping: an explicit but nonexistent
		// source input must remain dormant, even if named "dns-default".
		base := r.bundle.Namespace + "dns-default"
		generated := base
		for suffix := 1; ; suffix++ {
			occupied := false
			for _, owned := range r.ownedTags {
				if owned == generated {
					occupied = true
					break
				}
			}
			if !occupied {
				break
			}
			generated = base + "-" + strconv.Itoa(suffix)
		}
		dns["tag"] = generated
		r.ownedTags = append(r.ownedTags, generated)
	}
	r.bundle.Globals["dns"] = dns
	return nil
}

func (r *profileRenderer) dnsTag(object map[string]interface{}) error {
	value, present := object["tag"]
	if !present {
		return nil
	}
	tag, ok := value.(string)
	if !ok {
		return profileError()
	}
	if tag == "" {
		return nil
	}
	newTag := r.bundle.Namespace + "dns-" + tag
	if existing := r.inboundTags[tag]; existing != "" && existing != newTag {
		return profileError()
	}
	r.inboundTags[tag] = newTag
	object["tag"] = newTag
	r.ownedTags = profileAppendUnique(r.ownedTags, newTag)
	return nil
}

func (r *profileRenderer) outbound(outbound, template map[string]interface{}) error {
	oldTag := outbound["tag"].(string)
	newTag := r.outboundTags[oldTag]
	protocol := outbound["protocol"].(string)
	if !profileKeys(outbound, "tag", "protocol", "settings", "streamSettings", "proxySettings", "mux", "sendThrough", "targetStrategy") {
		return profileError()
	}
	outbound["tag"] = newTag
	proxy := mapOf(outbound["proxySettings"])
	if target, ok := proxy["tag"].(string); ok && target != "" {
		mapped := r.outboundTags[target]
		if mapped == "" {
			return profileError()
		}
		proxy["tag"] = mapped
		r.edge("o:"+newTag, "o:"+mapped)
	}
	stream := mapOf(outbound["streamSettings"])
	options := mapOf(stream["sockopt"])
	if target, ok := options["dialerProxy"].(string); ok && target != "" {
		mapped := r.outboundTags[target]
		if mapped == "" {
			return profileError()
		}
		options["dialerProxy"] = mapped
		r.edge("o:"+newTag, "o:"+mapped)
	}
	if protocol == "loopback" {
		settings := mapOf(outbound["settings"])
		oldInbound := settings["inboundTag"].(string)
		settings["inboundTag"] = r.loopbackTags[oldInbound]
		r.edge("o:"+newTag, "i:"+r.loopbackTags[oldInbound])
	}
	if source := mapOf(mapOf(template["streamSettings"])["sockopt"]); source != nil && protocol != "blackhole" && protocol != "block" {
		if mark, ok := source["mark"]; ok {
			if stream == nil {
				stream = map[string]interface{}{}
				outbound["streamSettings"] = stream
			}
			if options == nil {
				options = map[string]interface{}{}
				stream["sockopt"] = options
			}
			options["mark"] = mark
		}
	}
	r.bundle.InternalOutbounds = append(r.bundle.InternalOutbounds, outbound)
	return nil
}

func (r *profileRenderer) balancer(balancer map[string]interface{}) error {
	if !profileKeys(balancer, "tag", "selector", "strategy", "fallbackTag") {
		return profileError()
	}
	oldTag := balancer["tag"].(string)
	newTag := r.balancerTags[oldTag]
	balancer["tag"] = newTag
	selectors, err := profileStrings(balancer["selector"])
	if err != nil || len(selectors) == 0 {
		return profileError()
	}
	mapped := make([]interface{}, 0, len(selectors))
	matched := false
	for _, selector := range selectors {
		mapped = append(mapped, r.bundle.Namespace+"ob-"+selector)
		for old, out := range r.outboundTags {
			if strings.HasPrefix(old, selector) {
				r.edge("b:"+newTag, "o:"+out)
				matched = true
			}
		}
	}
	if !matched {
		return profileError()
	}
	balancer["selector"] = mapped
	if fallback, ok := balancer["fallbackTag"].(string); ok && fallback != "" {
		target := r.outboundTags[fallback]
		if target == "" {
			return profileError()
		}
		balancer["fallbackTag"] = target
		r.edge("b:"+newTag, "o:"+target)
	}
	strategy := mapOf(balancer["strategy"])
	if strategy != nil {
		if !profileKeys(strategy, "type", "settings") {
			return profileError()
		}
		kind, _ := strategy["type"].(string)
		if !profileOneOf(strings.ToLower(kind), "", "random", "roundrobin", "leastping", "leastload") {
			return profileError()
		}
		if settings := mapOf(strategy["settings"]); settings != nil {
			if strings.EqualFold(kind, "leastLoad") {
				if !profileKeys(settings, "costs", "baselines", "expected", "maxRTT", "tolerance") {
					return profileError()
				}
				if costs, ok := settings["costs"]; ok {
					rewritten, err := r.costs(costs)
					if err != nil {
						return err
					}
					settings["costs"] = rewritten
				}
			} else if len(settings) != 0 {
				return profileError()
			}
		}
	}
	r.bundle.Balancers = append(r.bundle.Balancers, balancer)
	return nil
}

func (r *profileRenderer) rules(rules []interface{}) error {
	if len(rules) > 2048 {
		return profileError()
	}
	terminal := map[string]bool{}
	for i, item := range rules {
		rule := mapOf(item)
		if rule == nil || !profileKeys(rule, "type", "ruleTag", "outboundTag", "balancerTag", "domain", "domains", "ip", "port", "network", "sourceIP", "source", "sourcePort", "user", "vlessRoute", "inboundTag", "protocol", "attrs", "localIP", "localPort", "process", "webhook") {
			return profileError()
		}
		if _, has := rule["webhook"]; has {
			return profileError()
		}
		out, hasOut := rule["outboundTag"].(string)
		bal, hasBal := rule["balancerTag"].(string)
		if hasOut == hasBal || hasOut && out == "" || hasBal && bal == "" {
			return profileError()
		}
		target := ""
		if hasOut {
			mapped := r.outboundTags[out]
			if mapped == "" {
				return profileError()
			}
			rule["outboundTag"] = mapped
			target = "o:" + mapped
		} else {
			mapped := r.balancerTags[bal]
			if mapped == "" {
				return profileError()
			}
			rule["balancerTag"] = mapped
			target = "b:" + mapped
		}
		tags := append([]string(nil), r.ownedTags...)
		if original, exists := rule["inboundTag"]; exists {
			values, err := profileStrings(original)
			if err != nil {
				return err
			}
			if len(values) > 0 {
				tags = nil
				for _, value := range values {
					mapped := r.inboundTags[value]
					if mapped == "" {
						if value == "" {
							return profileError()
						}
						// Native Xray permits a rule referring to an input that the
						// profile never creates. Keep that predicate dormant rather
						// than expanding it onto the router's real client inputs.
						mapped = r.bundle.Namespace + "dormant-" + value
						r.inboundTags[value] = mapped
					}
					tags = profileAppendUnique(tags, mapped)
					if alias := r.loopbackTags[value]; alias != "" {
						tags = profileAppendUnique(tags, alias)
					}
				}
			}
		}
		if r.syntheticDNS[out] {
			// This DNS service was implicit in a client-specific template.
			// It may intercept original client DNS requests, but the DNS
			// engine's own queries must follow the remaining provider policy.
			var clients []string
			for _, input := range tags {
				if r.isSourceClientInput(input) {
					clients = profileAppendUnique(clients, input)
				}
			}
			tags = clients
			if len(tags) == 0 {
				continue
			}
		}
		rule["inboundTag"] = profileInterfaces(tags)
		rule["ruleTag"] = r.bundle.Namespace + "rule-" + strconv.Itoa(i+1)
		for _, inbound := range tags {
			if !terminal[inbound] {
				r.edge("i:"+inbound, target)
				if profileCatchAll(rule) {
					terminal[inbound] = true
				}
			}
		}
		r.bundle.Rules = append(r.bundle.Rules, rule)
	}
	first := r.outbounds[0]["tag"].(string)
	for _, inbound := range r.ownedTags {
		if !terminal[inbound] {
			r.edge("i:"+inbound, "o:"+first)
		}
	}
	r.bundle.Rules = append(r.bundle.Rules, map[string]interface{}{"type": "field", "ruleTag": r.bundle.Namespace + "default", "inboundTag": profileInterfaces(r.ownedTags), "outboundTag": first})
	return nil
}

func (r *profileRenderer) observer() error {
	regular, normal := r.document["observatory"]
	burst, bursty := r.document["burstObservatory"]
	if normal && regular != nil && bursty && burst != nil {
		return fmt.Errorf("одновременные observatory и burstObservatory в профиле не поддерживаются")
	}
	if regular == nil && burst == nil {
		for _, item := range r.bundle.Balancers {
			kind, _ := mapOf(mapOf(item)["strategy"])["type"].(string)
			if strings.EqualFold(kind, "leastPing") || strings.EqualFold(kind, "leastLoad") {
				return fmt.Errorf("балансировщику профиля требуется observatory")
			}
		}
	}
	for _, key := range []string{"observatory", "burstObservatory"} {
		value, present := r.document[key]
		if !present || value == nil {
			continue
		}
		observer := mapOf(value)
		if observer == nil {
			return profileError()
		}
		if key == "observatory" && !profileKeys(observer, "subjectSelector", "probeURL", "probeInterval", "enableConcurrency") {
			return profileError()
		}
		if key == "burstObservatory" && !profileKeys(observer, "subjectSelector", "pingConfig") {
			return profileError()
		}
		selectors, err := profileStrings(observer["subjectSelector"])
		if err != nil || len(selectors) == 0 {
			return profileError()
		}
		mapped := make([]interface{}, 0, len(selectors))
		matched := false
		for _, selector := range selectors {
			mapped = append(mapped, r.bundle.Namespace+"ob-"+selector)
			for original := range r.outboundTags {
				if strings.HasPrefix(original, selector) {
					matched = true
				}
			}
		}
		if !matched {
			return profileError()
		}
		observer["subjectSelector"] = mapped
		if key == "burstObservatory" {
			ping := mapOf(observer["pingConfig"])
			if ping == nil || !profileKeys(ping, "destination", "connectivity", "interval", "sampling", "timeout", "httpMethod") {
				return profileError()
			}
		}
		r.bundle.Globals[key] = observer
	}
	return nil
}

var profileWeightNumber = regexp.MustCompile(`\d+(\.\d+)?`)

// Expand cost expressions against the original tags. Applying an unmodified
// substring/regexp to namespaced tags could accidentally match hash digits and
// change automatic weights; exact rewritten expressions preserve the result.
func (r *profileRenderer) costs(value interface{}) ([]interface{}, error) {
	items, ok := value.([]interface{})
	if !ok {
		return nil, profileError()
	}
	var result []interface{}
	tags := make([]string, 0, len(r.outboundTags))
	for tag := range r.outboundTags {
		tags = append(tags, tag)
	}
	sort.Strings(tags)
	for _, tag := range tags {
		for _, item := range items {
			cost := mapOf(item)
			if cost == nil || !profileKeys(cost, "match", "regexp", "value") {
				return nil, profileError()
			}
			match, ok := cost["match"].(string)
			if !ok {
				return nil, profileError()
			}
			expression, isRegex := cost["regexp"].(bool)
			if _, exists := cost["regexp"]; exists && !isRegex {
				return nil, profileError()
			}
			matched := ""
			if expression {
				compiled, err := regexp.Compile(match)
				if err != nil {
					return nil, profileError()
				}
				matched = compiled.FindString(tag)
			} else if strings.Contains(tag, match) {
				matched = match
			}
			if matched == "" {
				continue
			}
			weight := float64(0)
			if raw, exists := cost["value"]; exists {
				number, err := strconv.ParseFloat(fmt.Sprint(raw), 64)
				if err != nil || math.IsNaN(number) || math.IsInf(number, 0) {
					return nil, profileError()
				}
				weight = number
			}
			if weight <= 0 {
				weight = 1
				if number := profileWeightNumber.FindString(matched); number != "" {
					if parsed, err := strconv.ParseFloat(number, 64); err == nil && !math.IsNaN(parsed) && !math.IsInf(parsed, 0) {
						weight = parsed
					}
				}
			}
			result = append(result, map[string]interface{}{"regexp": true, "match": "^" + regexp.QuoteMeta(r.outboundTags[tag]) + "$", "value": weight})
			break
		}
	}
	return result, nil
}

func (r *profileRenderer) edge(from, to string) { r.graph[from] = append(r.graph[from], to) }
func profileKeys(value map[string]interface{}, keys ...string) bool {
	allowed := map[string]bool{}
	for _, key := range keys {
		allowed[key] = true
	}
	for key := range value {
		if !allowed[key] {
			return false
		}
	}
	return true
}
func profileOneOf(value string, values ...string) bool {
	for _, candidate := range values {
		if value == candidate {
			return true
		}
	}
	return false
}
func profileProtocol(value string) bool {
	return profileOneOf(value, "vless", "vmess", "trojan", "shadowsocks", "socks", "http", "hysteria", "wireguard", "freedom", "direct", "blackhole", "block", "dns", "loopback")
}
func profileStrings(value interface{}) ([]string, error) {
	switch v := value.(type) {
	case string:
		return []string{v}, nil
	case []interface{}:
		result := make([]string, 0, len(v))
		for _, item := range v {
			s, ok := item.(string)
			if !ok {
				return nil, profileError()
			}
			result = append(result, s)
		}
		return result, nil
	default:
		return nil, profileError()
	}
}

func profileArray(object map[string]interface{}, key string, max int) ([]interface{}, error) {
	value, present := object[key]
	if !present || value == nil {
		return nil, nil
	}
	items, ok := value.([]interface{})
	if !ok || len(items) > max {
		return nil, profileError()
	}
	return items, nil
}
func profileAppendUnique(values []string, value string) []string {
	for _, current := range values {
		if current == value {
			return values
		}
	}
	return append(values, value)
}
func profileInterfaces(values []string) []interface{} {
	result := make([]interface{}, len(values))
	for i, value := range values {
		result[i] = value
	}
	return result
}
func profileCatchAll(rule map[string]interface{}) bool {
	for key := range rule {
		if !profileOneOf(key, "type", "ruleTag", "inboundTag", "outboundTag", "balancerTag", "network") {
			return false
		}
	}
	if value, ok := rule["network"]; ok {
		networks, err := profileStrings(value)
		if err != nil {
			return false
		}
		joined := strings.Join(networks, ",")
		return joined == "tcp,udp" || joined == "udp,tcp"
	}
	return true
}
func profileGraphCycle(graph map[string][]string) bool {
	state := map[string]int{}
	var visit func(string) bool
	visit = func(node string) bool {
		if state[node] == 1 {
			return true
		}
		if state[node] == 2 {
			return false
		}
		state[node] = 1
		for _, target := range graph[node] {
			if visit(target) {
				return true
			}
		}
		state[node] = 2
		return false
	}
	for node := range graph {
		if visit(node) {
			return true
		}
	}
	return false
}
