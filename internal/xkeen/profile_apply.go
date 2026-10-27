package xkeen

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"xkeen-panel/internal/models"
)

type selectionFile struct {
	Data   []byte
	Mode   os.FileMode
	Exists bool
}
type SelectionSnapshot struct{ files map[string]selectionFile }

func ProfileStatePath(outboundsPath string) string { return outboundsPath + ".profile-state" }

// CaptureSelectionFiles names every possible mutation before selecting a
// profile. Restore never discovers or removes files created by somebody else.
func CaptureSelectionFiles(rt Runtime, outboundsPath string) (*SelectionSnapshot, error) {
	paths, err := filepath.Glob(filepath.Join(rt.XrayConfDir, "*.json"))
	if err != nil {
		return nil, err
	}
	paths = append(paths, outboundsPath, ProfileStatePath(outboundsPath))
	copyPaths := append([]string(nil), paths...)
	for _, path := range copyPaths {
		paths = append(paths, path+".bak")
	}
	snapshot := &SelectionSnapshot{files: map[string]selectionFile{}}
	for _, path := range paths {
		if path == "" {
			continue
		}
		if _, ok := snapshot.files[path]; ok {
			continue
		}
		file := selectionFile{}
		info, err := os.Lstat(path)
		if os.IsNotExist(err) {
			snapshot.files[path] = file
			continue
		}
		if err != nil || !info.Mode().IsRegular() {
			return nil, fmt.Errorf("не удалось сохранить настройки для отката")
		}
		file.Data, err = os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		file.Mode = info.Mode().Perm()
		file.Exists = true
		snapshot.files[path] = file
	}
	return snapshot, nil
}

func (snapshot *SelectionSnapshot) Restore() error {
	for path, file := range snapshot.files {
		if !file.Exists {
			if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
				return err
			}
			continue
		}
		if err := writeFileAtomic(path, file.Data, file.Mode); err != nil {
			return err
		}
	}
	return nil
}

type profileSniffBaseline struct {
	File   string      `json:"file"`
	Tag    string      `json:"tag"`
	Value  interface{} `json:"value"`
	Exists bool        `json:"exists,omitempty"`
}
type profileFieldBaseline struct {
	Exists bool        `json:"exists"`
	Value  interface{} `json:"value"`
}
type profileGlobalBaseline struct {
	File   string                          `json:"file"`
	Fields map[string]profileFieldBaseline `json:"fields"`
}
type activeProfileState struct {
	Version      int                     `json:"version"`
	Identity     string                  `json:"identity"`
	DefaultTag   string                  `json:"default_tag,omitempty"`
	RoutingFile  string                  `json:"routing_file"`
	InboundTags  []string                `json:"inbound_tags"`
	RuleTags     []string                `json:"rule_tags,omitempty"`
	BalancerTags []string                `json:"balancer_tags"`
	BaseGlobals  map[string]interface{}  `json:"base_globals"`
	GlobalFiles  []profileGlobalBaseline `json:"global_files,omitempty"`
	BaseRouting  map[string]interface{}  `json:"base_routing"`
	Sniffing     []profileSniffBaseline  `json:"sniffing"`
}

func HasActiveProfile(outboundsPath string) bool {
	_, err := os.Stat(ProfileStatePath(outboundsPath))
	return err == nil
}

func withinConfigDir(rt Runtime, path string) bool {
	return filepath.Dir(filepath.Clean(path)) == filepath.Clean(rt.XrayConfDir)
}

func restoreMapFields(target map[string]interface{}, baseline map[string]interface{}) {
	for key, value := range baseline {
		if value == nil {
			delete(target, key)
		} else {
			target[key] = value
		}
	}
}

// prepareProfilePolicy edits copies of existing documents. Global resolver and
// observer options belong to one active profile and return to the exact saved
// values when its owner selects an ordinary node.
func prepareProfilePolicy(rt Runtime, outboundsPath string, server models.Server, template map[string]interface{}) (map[string]map[string]interface{}, *activeProfileState, *ProfileBundle, error) {
	writes := map[string]map[string]interface{}{}
	doc, err := findRoutingDoc(rt, func(map[string]interface{}) bool { return false })
	if err != nil {
		return nil, nil, nil, err
	}
	writes[doc.path] = doc.config
	documents := map[string]map[string]interface{}{doc.path: doc.config}
	loadDocument := func(path string) (map[string]interface{}, error) {
		if !withinConfigDir(rt, path) {
			return nil, fmt.Errorf("некорректное состояние профиля")
		}
		if config := documents[path]; config != nil {
			return config, nil
		}
		var config map[string]interface{}
		if err := ReadJSONC(path, &config); err != nil {
			return nil, err
		}
		if config == nil {
			return nil, fmt.Errorf("некорректный документ Xray")
		}
		documents[path] = config
		return config, nil
	}
	if oldRaw, readErr := os.ReadFile(ProfileStatePath(outboundsPath)); readErr == nil {
		var old activeProfileState
		decoder := json.NewDecoder(bytes.NewReader(oldRaw))
		decoder.UseNumber()
		if decoder.Decode(&old) != nil || old.Version != 1 || old.RoutingFile != doc.path {
			return nil, nil, nil, fmt.Errorf("состояние профиля повреждено; настройки сохранены")
		}
		if len(old.GlobalFiles) > 0 {
			for _, baseline := range old.GlobalFiles {
				config, err := loadDocument(baseline.File)
				if err != nil {
					return nil, nil, nil, err
				}
				for key, field := range baseline.Fields {
					if field.Exists {
						config[key] = field.Value
					} else {
						delete(config, key)
					}
				}
				writes[baseline.File] = config
			}
		} else {
			// Compatible with state saved before per-document baselines existed.
			restoreMapFields(doc.config, old.BaseGlobals)
		}
		restoreMapFields(doc.routing, old.BaseRouting)
		owned := map[string]bool{}
		for _, tag := range old.InboundTags {
			owned[tag] = true
		}
		var rules []interface{}
		ownedRuleTags := map[string]bool{}
		for _, tag := range old.RuleTags {
			ownedRuleTags[tag] = true
		}
		for _, raw := range asSlice(doc.routing["rules"]) {
			rule := mapOf(raw)
			matched := false
			if len(ownedRuleTags) > 0 {
				tag, _ := rule["ruleTag"].(string)
				matched = ownedRuleTags[tag]
			} else {
				for _, tag := range stringList(rule["inboundTag"]) {
					matched = matched || owned[tag]
				}
			}
			if !matched {
				rules = append(rules, raw)
			}
		}
		doc.routing["rules"] = rules
		balancerTags := map[string]bool{}
		for _, tag := range old.BalancerTags {
			balancerTags[tag] = true
		}
		var balancers []interface{}
		for _, raw := range asSlice(doc.routing["balancers"]) {
			tag, _ := mapOf(raw)["tag"].(string)
			if !balancerTags[tag] {
				balancers = append(balancers, raw)
			}
		}
		doc.routing["balancers"] = balancers
		for _, baseline := range old.Sniffing {
			if !withinConfigDir(rt, baseline.File) {
				return nil, nil, nil, fmt.Errorf("некорректное состояние профиля")
			}
			config, err := loadDocument(baseline.File)
			if err != nil {
				return nil, nil, nil, err
			}
			writes[baseline.File] = config
			for _, raw := range asSlice(config["inbounds"]) {
				inbound := mapOf(raw)
				if inbound["tag"] == baseline.Tag {
					if baseline.Exists || baseline.Value != nil {
						inbound["sniffing"] = baseline.Value
					} else {
						delete(inbound, "sniffing")
					}
				}
			}
		}
	} else if !os.IsNotExist(readErr) {
		return nil, nil, nil, readErr
	}
	if len(server.RawProfile) == 0 {
		return writes, nil, nil, nil
	}
	bundle, err := BuildProfileBundle(server, ManualTag, template)
	if err != nil {
		return nil, nil, nil, err
	}
	state := &activeProfileState{Version: 1, Identity: ProfileIdentity(server), RoutingFile: doc.path, BaseGlobals: map[string]interface{}{}, BaseRouting: map[string]interface{}{}}
	if len(bundle.InternalOutbounds)>0 { state.DefaultTag=outboundTag(mapOf(bundle.InternalOutbounds[0])) }
	// Every JSON fragment is merged by Xray. Later globals would shadow the
	// provider's policy, and globals it omits would otherwise remain active.
	// Save each document's exact fields, then give the active profile one owner.
	paths, err := filepath.Glob(filepath.Join(rt.XrayConfDir, "*.json"))
	if err != nil {
		return nil, nil, nil, err
	}
	for _, path := range paths {
		config, err := loadDocument(path)
		if err != nil {
			return nil, nil, nil, err
		}
		baseline := profileGlobalBaseline{File: path, Fields: map[string]profileFieldBaseline{}}
		for key := range bundle.Globals {
			value, exists := config[key]
			if exists || path == doc.path {
				baseline.Fields[key] = profileFieldBaseline{Exists: exists, Value: value}
			}
			if exists {
				delete(config, key)
				writes[path] = config
			}
		}
		if len(baseline.Fields) > 0 {
			state.GlobalFiles = append(state.GlobalFiles, baseline)
		}
	}
	for key, value := range bundle.Globals {
		if value != nil {
			doc.config[key] = value
		}
	}
	for key, value := range bundle.RoutingGlobals {
		state.BaseRouting[key] = doc.routing[key]
		if value == nil {
			delete(doc.routing, key)
		} else {
			doc.routing[key] = value
		}
	}
	for _, raw := range bundle.Balancers {
		tag, _ := mapOf(raw)["tag"].(string)
		state.BalancerTags = append(state.BalancerTags, tag)
	}
	clients := profilePhysicalInputs(documents)
	if len(clients) == 0 {
		return nil, nil, nil, fmt.Errorf("не найдены входы роутера для профиля")
	}
	bound, err := BindProfileRules(bundle, clients)
	if err != nil {
		return nil, nil, nil, err
	}
	probe, err := BindProfileRules(bundle, []string{ProbeInboundTag})
	if err != nil {
		return nil, nil, nil, err
	}
	bundle.InternalOutbounds = append(bundle.InternalOutbounds, bound.GuardOutbounds...)
	baseRules := asSlice(doc.routing["rules"])
	boundary := len(baseRules)
	for i, raw := range baseRules {
		rule := mapOf(raw)
		target, _ := rule["balancerTag"].(string)
		if target == "" || IsProfileInternalTag(target) {
			continue
		}
		tags := stringList(rule["inboundTag"])
		if len(tags) == 1 && tags[0] == ProbeInboundTag {
			continue
		}
		boundary = i
		break
	}
	ownedRules := append(append([]interface{}{}, bound.OwnedRules...), probe.ClientRules...)
	combined := append(append([]interface{}{}, baseRules[:boundary]...), bound.ClientRules...)
	combined = append(combined, baseRules[boundary:]...)
	doc.routing["rules"] = append(ownedRules, combined...)
	for _, raw := range append(append([]interface{}{}, ownedRules...), bound.ClientRules...) {
		tag, _ := mapOf(raw)["ruleTag"].(string)
		state.RuleTags = append(state.RuleTags, tag)
	}
	doc.routing["balancers"] = append(asSlice(doc.routing["balancers"]), bundle.Balancers...)
	if len(bundle.Sniffing) > 0 {
		for _, path := range paths {
			config, err := loadDocument(path)
			if err != nil {
				return nil, nil, nil, err
			}
			changed := false
			for _, raw := range asSlice(config["inbounds"]) {
				inbound := mapOf(raw)
				tag, _ := inbound["tag"].(string)
				proto, _ := inbound["protocol"].(string)
				if !profilePhysicalInput(tag, proto) {
					continue
				}
				value, exists := inbound["sniffing"]
				state.Sniffing = append(state.Sniffing, profileSniffBaseline{File: path, Tag: tag, Value: value, Exists: exists})
				inbound["sniffing"] = bundle.Sniffing
				changed = true
			}
			if changed {
				writes[path] = config
			}
		}
	}
	return writes, state, &bundle, nil
}

func profilePhysicalInput(tag, protocol string) bool {
	if tag == "" || tag == "api" {
		return false
	}
	return protocol == "dokodemo-door" || protocol == "tunnel" || protocol == "http" || protocol == "socks" || tag == ProbeInboundTag
}

func profilePhysicalInputs(documents map[string]map[string]interface{}) []string {
	var tags []string
	for _, config := range documents {
		for _, raw := range asSlice(config["inbounds"]) {
			inbound := mapOf(raw)
			tag, _ := inbound["tag"].(string)
			protocol, _ := inbound["protocol"].(string)
			if tag != ProbeInboundTag && profilePhysicalInput(tag, protocol) {
				tags = append(tags, tag)
			}
		}
	}
	return tags
}

func stringList(value interface{}) []string {
	var result []string
	switch v := value.(type) {
	case []string:
		return v
	case []interface{}:
		for _, x := range v {
			if s, ok := x.(string); ok {
				result = append(result, s)
			}
		}
	case string:
		result = append(result, v)
	}
	return result
}

func setManualWithProfile(rt Runtime, path string, server models.Server) (err error) {
	snapshot, err := CaptureSelectionFiles(rt, path)
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			if restoreErr := snapshot.Restore(); restoreErr != nil {
				err = fmt.Errorf("ошибка профиля; откат файлов не подтверждён")
			}
		}
	}()
	config, err := ReadOutboundsConfig(path)
	if err != nil {
		return err
	}
	outbounds := asSlice(config["outbounds"])
	_, template := findProxyOutbound(outbounds)
	writes, state, bundle, err := prepareProfilePolicy(rt, path, server, template)
	if err != nil {
		return err
	}
	// A combined document can contain outbounds, routing, globals and sniffing.
	// Continue editing its staged copy rather than overwriting policy changes.
	if staged := writes[path]; staged != nil {
		config = staged
		outbounds = asSlice(config["outbounds"])
	}
	slot, err := BuildServerOutbound(server, ManualTag, template)
	if err != nil {
		return err
	}
	var remaining []interface{}
	for _, raw := range outbounds {
		outbound := mapOf(raw)
		tag, _ := outbound["tag"].(string)
		if tag != ManualTag && !IsProfileInternalTag(tag) {
			remaining = append(remaining, raw)
		}
	}
	var proxies []interface{}
	for _, raw := range remaining {
		if !isServiceOutbound(mapOf(raw)) {
			proxies = append(proxies, raw)
		}
	}
	proxies = append(proxies, slot)
	if bundle != nil {
		proxies = append(append([]interface{}{},bundle.InternalOutbounds...),proxies...)
	}
	config["outbounds"] = append(proxies, serviceOutbounds(remaining)...)
	writes[path] = config
	if err = applyConfigs(rt, writes); err != nil {
		return err
	}
	if state == nil {
		err = os.Remove(ProfileStatePath(path))
		if os.IsNotExist(err) {
			err = nil
		}
		return err
	}
	raw, err := json.Marshal(state)
	if err != nil {
		return err
	}
	return writeFileAtomic(ProfileStatePath(path), raw, 0600)
}

func preserveProfileDefault(outboundsPath string,config map[string]interface{}) {
	data,err:=os.ReadFile(ProfileStatePath(outboundsPath));if err!=nil{return}
	var state activeProfileState
	if json.Unmarshal(data,&state)!=nil||state.DefaultTag=="" {return}
	outbounds:=asSlice(config["outbounds"])
	for i,raw:=range outbounds { if outboundTag(mapOf(raw))==state.DefaultTag {
		ordered:=[]interface{}{raw};ordered=append(ordered,outbounds[:i]...);ordered=append(ordered,outbounds[i+1:]...);config["outbounds"]=ordered;return
	} }
}
