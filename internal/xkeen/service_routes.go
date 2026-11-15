package xkeen

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"time"
	"xkeen-panel/internal/models"
)

const servicePrefix = "xkp-service-"
const serviceBlock = servicePrefix + "block"

// An optional, separately provisioned client proxy can tag all traffic here,
// including third-party hosts used by Claude or its local tools.
const ClaudeClientInbound = "xkp-claude-client"

func ServiceRoutesPath(rt Runtime) string {
	return filepath.Join(rt.XrayConfDir, ".panel-service-routes")
}
func ServiceFragmentPath(rt Runtime) string {
	// Xray appends the outbounds of fragments with "tail" in their name.
	return filepath.Join(rt.XrayConfDir, "99_tail_panel_services.json")
}

func ServiceRoutesArmed(rt Runtime) bool {
	_, err := os.Stat(ServiceRoutesPath(rt))
	return !os.IsNotExist(err)
}

func serviceGuardCommand(rt Runtime, command string, input []byte) bool {
	if rt.Core != CoreXray || !rt.Installed {
		return false
	}
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "/opt/sbin/xkeen-panel-guard", command)
	cmd.Stdin = bytes.NewReader(input)
	return cmd.Run() == nil
}

var serviceNetworks = map[string][]string{
	// Anthropic publishes inbound API/Console prefixes separately from its
	// outbound MCP addresses: https://platform.claude.com/docs/en/api/ip-addresses
	"claude":   {"160.79.104.0/23", "153.61.224.0/22", "2607:6bc0::/48"},
	"telegram": {"149.154.160.0/20", "91.108.4.0/22", "91.108.8.0/22", "91.108.12.0/22", "91.108.16.0/22", "91.108.20.0/22", "91.108.56.0/22"},
}

// ServiceNetworks returns the address ranges managed by the service card.
func ServiceNetworks(id string) []string { return slices.Clone(serviceNetworks[id]) }

func servicePolicyReady(rt Runtime, state serviceRoutesState) bool {
	// A verified native exclusive route need not use synthetic prefixes.
	// A verifier using FakeDNS must itself verify the prefix packet filter.
	if rt.Core != CoreXray || !rt.Installed {
		return false
	}
	selectors := []map[string]interface{}{}
	geo := serviceGeosites(rt)
	for i, service := range serviceCatalog {
		if service.id != "claude" && state.Assignments[service.id] == "" {
			continue
		}
		item := map[string]interface{}{"id": service.id, "domains": serviceDomains(i, geo)}
		if ips := serviceNetworks[service.id]; len(ips) != 0 {
			item["ips"] = ips
		}
		selectors = append(selectors, item)
	}
	policy, err := json.Marshal(map[string]interface{}{"services": selectors})
	return err == nil && serviceGuardCommand(rt, "check-policy", policy)
}

func ServiceGuardReady(rt Runtime) bool {
	state, err := loadServiceRoutes(rt)
	return err == nil && servicePolicyReady(rt, state)
}

type serviceRoutesState struct {
	Version     int                               `json:"version"`
	Assignments map[string]string                 `json:"assignments"`
	Outbounds   map[string]map[string]interface{} `json:"outbounds"`
}

func loadServiceRoutes(rt Runtime) (serviceRoutesState, error) {
	state := serviceRoutesState{1, map[string]string{}, map[string]map[string]interface{}{}}
	raw, err := os.ReadFile(ServiceRoutesPath(rt))
	if os.IsNotExist(err) {
		return state, nil
	}
	if err != nil {
		return state, err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	invalid := errors.New("повреждены сохранённые маршруты сервисов")
	if decoder.Decode(&state) != nil || decoder.Decode(new(interface{})) != io.EOF || state.Version != 1 || state.Assignments == nil || state.Outbounds == nil {
		return state, invalid
	}
	for key, id := range state.Assignments {
		if !knownService(key) || !profileHashPattern.MatchString(id) {
			return state, invalid
		}
	}
	for id, ob := range state.Outbounds {
		if !profileHashPattern.MatchString(id) || ob["tag"] != servicePrefix+id || !permittedServiceOutbound(ob) {
			return state, invalid
		}
	}
	return state, nil
}

func permittedServiceOutbound(ob map[string]interface{}) bool {
	if hasOutboundDependency(ob) {
		return false
	}
	_, _, _, err := outboundMetadata(ob)
	return err == nil
}

// ServiceTargetID identifies the complete native outbound semantics and omits
// subscription sequence numbers, display names, latency and plaintext secrets.
func ServiceTargetID(server models.Server) string {
	if len(server.RawProfile) > 0 {
		identity := ProfileIdentity(server)
		if identity == "" {
			return ""
		}
		hash := sha256.Sum256([]byte(identity))
		return hex.EncodeToString(hash[:])
	}
	outbound, err := BuildServerOutbound(server, "endpoint", nil)
	if err != nil || !permittedServiceOutbound(outbound) {
		return ""
	}
	raw, err := json.Marshal(outbound)
	if err != nil {
		return ""
	}
	hash := sha256.Sum256(raw)
	return hex.EncodeToString(hash[:])
}

type ServiceTarget struct {
	ID      string   `json:"id"`
	Name    string   `json:"name"`
	Kind    string   `json:"kind"`
	Country string   `json:"country,omitempty"`
	Sources []string `json:"sources,omitempty"`
}
type ServiceRouteView struct {
	RoutingService
	Target         string               `json:"target"`
	Blocked        bool                 `json:"blocked"`
	RouteName      string               `json:"route_name,omitempty"`
	InheritedRoute *InheritedRoute      `json:"inherited_route,omitempty"`
	CurrentRoute   *CurrentServiceRoute `json:"current_route,omitempty"`
}

// CurrentServiceRoute describes the next selection reported by the live core.
// For a conditional rule this is the VPN branch only.
type CurrentServiceRoute struct {
	Pool        string `json:"pool,omitempty"`
	PoolCountry string `json:"pool_country,omitempty"`
	Kind        string `json:"kind"`
	Name        string `json:"name,omitempty"`
	Country     string `json:"country,omitempty"`
	Source      string `json:"source,omitempty"`
}

// InheritedRoute describes the service's own active Mihomo group in rule mode.
type InheritedRoute struct {
	Group    string   `json:"group"`
	Via      []string `json:"via"`
	Kind     string   `json:"kind"`
	Endpoint string   `json:"endpoint,omitempty"`
	Strategy string   `json:"strategy,omitempty"`
	Members  []string `json:"members,omitempty"`
}
type ServiceRoutesView struct {
	Services   []ServiceRouteView `json:"services"`
	Targets    []ServiceTarget    `json:"targets"`
	GuardReady bool               `json:"guard_ready"`
	Active     bool               `json:"active"`
}

func ReadServiceRoutes(rt Runtime, servers []models.Server) (ServiceRoutesView, error) {
	state, err := loadServiceRoutes(rt)
	view := ServiceRoutesView{Active: ServiceRoutesArmed(rt), GuardReady: ServiceGuardReady(rt), Targets: []ServiceTarget{}}
	if err != nil {
		return view, err
	}
	positions := map[string]int{}
	for _, s := range servers {
		id := ServiceTargetID(s)
		if id == "" {
			continue
		}
		i, exists := positions[id]
		if !exists {
			kind := "server"
			if len(s.RawProfile) > 0 {
				kind = "profile"
			}
			i = len(view.Targets)
			positions[id] = i
			view.Targets = append(view.Targets, ServiceTarget{ID: id, Name: s.Name, Kind: kind, Country: ServerCountry(s)})
		}
		if s.SourceName != "" && !slices.Contains(view.Targets[i].Sources, s.SourceName) {
			view.Targets[i].Sources = append(view.Targets[i].Sources, s.SourceName)
		}
	}
	geo := serviceGeosites(rt)
	for i, s := range serviceCatalog {
		id := state.Assignments[s.id]
		_, present := positions[id]
		blocked := view.Active && (s.id == "claude" || id != "") && (!present || state.Outbounds[id] == nil)
		view.Services = append(view.Services, ServiceRouteView{RoutingService: RoutingService{s.id, s.name, serviceDomains(i, geo)}, Target: id, Blocked: blocked})
	}
	return view, nil
}

// ReconcileServiceRoutes re-resolves saved identities against a fresh snapshot.
// Absence or an unusable existing worker materializes a block immediately.
// key is nonempty only for an explicit assignment, whose preparation errors
// are returned to the caller before any file is committed.
func ReconcileServiceRoutes(rt Runtime, outboundsPath string, servers []models.Server, key, requested string) (bool, error) {
	if rt.Core != CoreXray {
		return false, errors.New("маршруты сервисов требуют Xray")
	}
	if key != "" && (!knownService(key) || key == "claude" && requested == "" || requested != "" && !profileHashPattern.MatchString(requested)) {
		return false, errors.New("укажите допустимый сервис и защищённую цель")
	}
	candidate, err := loadServiceRoutes(rt)
	if err != nil {
		return false, err
	}
	if key != "" {
		if requested == "" {
			delete(candidate.Assignments, key)
		} else {
			candidate.Assignments[key] = requested
		}
	}
	if !servicePolicyReady(rt, candidate) {
		return false, errors.New("сетевой запрет прямого выхода не подтверждён")
	}
	return reconcileServiceRoutes(rt, outboundsPath, servers, key, requested)
}

func reconcileServiceRoutes(rt Runtime, outboundsPath string, servers []models.Server, key, requested string) (bool, error) {
	state, err := loadServiceRoutes(rt)
	if err != nil {
		return false, err
	}
	if key != "" {
		if !knownService(key) || (requested != "" && !profileHashPattern.MatchString(requested)) {
			return false, errors.New("неизвестный сервис или сервер")
		}
		if requested == "" {
			if key == "claude" {
				return false, errors.New("для Claude требуется защищённый сервер")
			}
			delete(state.Assignments, key)
		} else {
			state.Assignments[key] = requested
		}
	}
	available := map[string]models.Server{}
	for _, server := range servers {
		if id := ServiceTargetID(server); id != "" {
			available[id] = server
		}
	}
	if requested != "" {
		if _, ok := available[requested]; !ok {
			return false, errors.New("выбранный сервер отсутствует в подписке")
		}
	}
	primary, err := ReadOutboundsConfig(outboundsPath)
	if err != nil {
		return false, err
	}
	_, template := findProxyOutbound(asSlice(primary["outbounds"]))
	state.Outbounds = map[string]map[string]interface{}{}
	attempted := map[string]bool{}
	for _, id := range state.Assignments {
		server, ok := available[id]
		if !ok || attempted[id] {
			continue
		}
		attempted[id] = true
		var ob map[string]interface{}
		if len(server.RawProfile) > 0 {
			ob, err = PrepareServiceProfile(rt, id, server, servicePrefix+id, template)
		} else {
			ob, err = BuildServerOutbound(server, servicePrefix+id, template)
		}
		if err != nil || !permittedServiceOutbound(ob) {
			if requested == id {
				return false, errors.New("защищённый выход для выбранной цели недоступен")
			}
			continue
		}
		state.Outbounds[id] = ob
	}
	raw, err := json.Marshal(state)
	if err != nil {
		return false, err
	}
	before, err := os.ReadFile(ServiceRoutesPath(rt))
	if err != nil && !os.IsNotExist(err) {
		return false, err
	}
	changed := !bytes.Equal(before, raw)
	writes := map[string]map[string]interface{}{}
	if err := compileServiceRoutes(rt, writes, state); err != nil {
		return false, err
	}
	if changed {
		if err := writeFileAtomic(ServiceRoutesPath(rt), raw, 0600); err != nil {
			return false, err
		}
	}
	if len(writes) == 0 {
		return changed, nil
	}
	if err := applyConfigs(rt, writes); err != nil {
		return false, fmt.Errorf("не удалось проверить маршруты сервисов: %w", err)
	}
	return true, nil
}

func PruneInactiveServiceProfiles(rt Runtime, servers []models.Server) error {
	state, err := loadServiceRoutes(rt)
	if err != nil {
		return err
	}
	keep := map[string]bool{}
	for _, server := range servers {
		if len(server.RawProfile) > 0 {
			id := ServiceTargetID(server)
			if state.Outbounds[id] != nil {
				keep[id] = true
			}
		}
	}
	return PruneServiceProfiles(rt, keep)
}
