// panel-prepare creates a staged pool and saved manual selection. It never
// starts the HTTP server, invokes a dispatcher/core, or writes a live directory.
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"xkeen-panel/internal/models"
	"xkeen-panel/internal/xkeen"
)

type prepareInput struct {
	DataDir            string `json:"data_dir"`
	CandidateConfigDir string `json:"candidate_config_dir"`
	OutboundsFile      string `json:"outbounds_file"`
	RoutingFile        string `json:"routing_file"`
	LiveConfigDir      string `json:"live_config_dir"`
	APIAddr            string `json:"api_addr"`
	ProbeAddr          string `json:"probe_addr"`
	PreferredTag       string `json:"preferred_tag"`
}

func fail(code string) {
	log.Print("prepare failed: " + code)
	fmt.Fprintln(os.Stderr, "PREPARE_ERROR="+code)
	os.Exit(1)
}

func inside(parent, path string) bool {
	rel, err := filepath.Rel(parent, path)
	return err == nil && !filepath.IsAbs(rel) && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

func disjoint(a, b string) bool { return !inside(a, b) && !inside(b, a) }

func regular(path string) bool {
	info, err := os.Lstat(path)
	return err == nil && info.Mode().IsRegular()
}

func privateRegular(path string) bool {
	info, err := os.Lstat(path)
	return err == nil && info.Mode().IsRegular() && (os.PathSeparator == '\\' || info.Mode().Perm()&0077 == 0)
}

func noSymlinksInTree(path string) bool {
	return filepath.WalkDir(path, func(_ string, entry os.DirEntry, err error) error {
		if err != nil || entry.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("unsafe_tree")
		}
		return nil
	}) == nil
}

// System anchors such as /opt may legitimately be Entware mount symlinks. Only
// the explicitly approved anchor is resolved; stage components below it must
// all be ordinary directories rather than symlink aliases.
func safeDescendant(anchor, path string) bool {
	if !inside(anchor, path) {
		return false
	}
	rel, err := filepath.Rel(anchor, path)
	if err != nil {
		return false
	}
	current := anchor
	for _, part := range strings.Split(rel, string(filepath.Separator)) {
		if part == "." || part == "" {
			continue
		}
		current = filepath.Join(current, part)
		info, err := os.Lstat(current)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return false
		}
	}
	return true
}

func normalizePaths(input *prepareInput) bool {
	paths := []*string{&input.DataDir, &input.CandidateConfigDir, &input.OutboundsFile, &input.RoutingFile, &input.LiveConfigDir}
	for _, path := range paths {
		if !filepath.IsAbs(*path) {
			return false
		}
		*path = filepath.Clean(*path)
	}
	candidate, live := input.CandidateConfigDir, input.LiveConfigDir
	if !disjoint(candidate, live) || !disjoint(input.DataDir, candidate) || !disjoint(input.DataDir, live) {
		return false
	}
	stage := filepath.Dir(candidate)
	var anchor string
	if os.PathSeparator == '/' && inside("/opt/etc", candidate) {
		if filepath.Base(candidate) != "candidate" || filepath.Dir(stage) != "/opt/etc" || !regexp.MustCompile(`^xkeen-custom-stage\.[A-Za-z0-9_-]{4,}$`).MatchString(filepath.Base(stage)) {
			return false
		}
		anchor = "/opt/etc"
	} else {
		// Allows t.TempDir fixtures, but never accepts a production /opt path
		// just because /opt eventually resolves into a /tmp/mnt mount.
		anchor = filepath.Clean(os.TempDir())
		if !inside(anchor, candidate) {
			return false
		}
	}
	if !inside(stage, input.DataDir) || input.DataDir == stage || !safeDescendant(anchor, candidate) || !safeDescendant(anchor, input.DataDir) {
		return false
	}
	if filepath.Dir(input.OutboundsFile) != candidate || filepath.Dir(input.RoutingFile) != candidate || input.OutboundsFile == input.RoutingFile || filepath.Ext(input.OutboundsFile) != ".json" || filepath.Ext(input.RoutingFile) != ".json" {
		return false
	}
	if !regular(input.OutboundsFile) || !regular(input.RoutingFile) || !noSymlinksInTree(candidate) || !noSymlinksInTree(input.DataDir) {
		return false
	}
	if !privateRegular(filepath.Join(input.DataDir, "subscription.json")) {
		return false
	}
	liveInfo, err := os.Lstat(live)
	if err != nil || !liveInfo.IsDir() || liveInfo.Mode()&os.ModeSymlink != 0 {
		return false
	}
	resolvedCandidate, err := filepath.EvalSymlinks(candidate)
	if err != nil {
		return false
	}
	resolvedData, err := filepath.EvalSymlinks(input.DataDir)
	if err != nil {
		return false
	}
	resolvedLive, err := filepath.EvalSymlinks(live)
	return err == nil && disjoint(resolvedCandidate, resolvedLive) && disjoint(resolvedData, resolvedLive) && disjoint(resolvedData, resolvedCandidate)
}

func loopbackAddr(address string) bool {
	host, portText, err := net.SplitHostPort(address)
	port, portErr := strconv.Atoi(portText)
	ip := net.ParseIP(host)
	// Current pool/probe helpers use the IPv4 host:port form internally.
	return err == nil && portErr == nil && port >= 1024 && port <= 65535 && ip != nil && ip.To4() != nil && ip.IsLoopback()
}

func readJSON(path string, target interface{}, private bool) bool {
	if !regular(path) || private && !privateRegular(path) {
		return false
	}
	file, err := os.Open(path)
	if err != nil {
		return false
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, (16<<20)+1))
	if err != nil || len(data) > 16<<20 {
		return false
	}
	decoder := json.NewDecoder(bytes.NewReader(xkeen.StripJSONComments(data)))
	decoder.UseNumber()
	if decoder.Decode(target) != nil {
		return false
	}
	var extra interface{}
	return decoder.Decode(&extra) == io.EOF
}

func serviceOutbound(outbound map[string]interface{}) bool {
	protocol, _ := outbound["protocol"].(string)
	switch protocol {
	case "freedom", "blackhole", "dns", "loopback":
		return true
	}
	return false
}

func preferredTemplate(input prepareInput) (map[string]interface{}, string, bool) {
	var doc map[string]interface{}
	if !readJSON(input.OutboundsFile, &doc, false) {
		return nil, "", false
	}
	outbounds, ok := doc["outbounds"].([]interface{})
	if !ok {
		return nil, "", false
	}
	var template map[string]interface{}
	for _, raw := range outbounds {
		outbound, ok := raw.(map[string]interface{})
		if !ok {
			return nil, "", false
		}
		if serviceOutbound(outbound) {
			continue
		}
		if template != nil {
			return nil, "", false
		}
		template = outbound
	}
	if template == nil {
		return nil, "", false
	}
	tag, _ := template["tag"].(string)
	if tag == "" || input.PreferredTag != "" && input.PreferredTag != tag {
		return nil, "", false
	}
	encoded, err := json.Marshal(template)
	if err != nil {
		return nil, "", false
	}
	identity := xkeen.ServerIdentity(models.Server{RawOutbound: encoded})
	return template, identity, identity != ""
}

func canonicalIdentity(server models.Server, template map[string]interface{}) string {
	if len(server.RawOutbound) > 0 {
		return xkeen.ServerIdentity(server)
	}
	outbound, err := xkeen.BuildServerOutbound(server, "", template)
	if err != nil {
		return ""
	}
	raw, err := json.Marshal(outbound)
	if err != nil {
		return ""
	}
	return xkeen.ServerIdentity(models.Server{RawOutbound: raw})
}

func liveMetadataPath(candidate, live, path string) (string, bool) {
	if path == "" {
		return "", true
	}
	if !inside(candidate, path) || path == candidate {
		return "", false
	}
	rel, err := filepath.Rel(candidate, path)
	if err != nil {
		return "", false
	}
	return filepath.Join(live, rel), true
}

func main() {
	log.SetOutput(io.Discard)
	xkeen.Log = log.Printf
	defer func() {
		if recover() != nil {
			fail("internal")
		}
	}()
	flags := flag.NewFlagSet("panel-prepare", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	inputFile := flags.String("input", "", "protected staged preparation JSON")
	if flags.Parse(os.Args[1:]) != nil || *inputFile == "" || flags.NArg() != 0 {
		fail("arguments")
	}
	var input prepareInput
	if !readJSON(*inputFile, &input, true) || !normalizePaths(&input) {
		fail("input_or_stage_paths")
	}
	if !loopbackAddr(input.APIAddr) || !loopbackAddr(input.ProbeAddr) || input.APIAddr == input.ProbeAddr {
		fail("loopback_addresses")
	}
	logFile, err := os.OpenFile(filepath.Join(input.DataDir, "prepare.log"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil || logFile.Chmod(0600) != nil {
		fail("private_log")
	}
	defer logFile.Close()
	log.SetOutput(logFile)
	template, wantedIdentity, ok := preferredTemplate(input)
	if !ok {
		fail("preferred_template_not_single")
	}
	sm := xkeen.NewSubscriptionManager(input.DataDir)
	if sm.Load() != nil {
		fail("subscription_load")
	}
	servers := sm.GetServers()
	preferredIndex := -1
	for i, server := range servers {
		if canonicalIdentity(server, template) == wantedIdentity {
			preferredIndex = i
			break
		}
	}
	if preferredIndex < 0 {
		fail("preferred_missing_from_subscription")
	}
	preferred := servers[preferredIndex]
	if preferred.ProbeKind != "https" || preferred.Latency < 0 || preferred.LastChecked.IsZero() {
		fail("preferred_needs_successful_https_probe")
	}
	selection := xkeen.PoolSelection{MaxNodes: 32, AvoidCountries: []string{"RU", "BY"}}
	selected := xkeen.SelectPoolServers(servers, selection)
	preferredAllowed := false
	for _, server := range selected {
		if server.ProbeKind != "https" || server.Latency < 0 {
			fail("pool_contains_unverified_server")
		}
		if canonicalIdentity(server, template) == wantedIdentity {
			preferredAllowed = true
		}
	}
	if len(selected) == 0 || !preferredAllowed {
		fail("preferred_not_allowed_in_pool")
	}
	// These deliberately empty/false fields guarantee applyConfigs cannot run
	// TestConfig, xkeen, system init scripts, or a production Xray process.
	runtime := xkeen.Runtime{Core: xkeen.CoreXray, XrayConfDir: input.CandidateConfigDir, RoutingFile: input.RoutingFile, Installed: false, Dispatcher: "", CoreBin: ""}
	initialTopology := xkeen.ReadTopology(runtime)
	templateTag, _ := template["tag"].(string)
	if initialTopology.Mode != xkeen.TopologySingle || len(initialTopology.ProxyTags) != 1 || initialTopology.ProxyTags[0] != templateTag {
		fail("candidate_has_other_proxy_fragments")
	}
	state, err := xkeen.EnablePool(runtime, input.OutboundsFile, servers, xkeen.PoolOptions{APIAddr: input.APIAddr, Selection: selection})
	if err != nil {
		log.Printf("staged pool rejected: %v", err)
		fail("enable_staged_pool")
	}
	topology := xkeen.ReadTopology(runtime)
	if topology.Mode != xkeen.TopologyPool || topology.BalancerTag != state.BalancerTag {
		fail("candidate_pool_topology")
	}
	ready, changed, err := xkeen.EnsureProbeRoute(runtime, input.ProbeAddr, topology)
	if err != nil || !ready {
		fail("candidate_probe_route")
	}
	nodes, err := xkeen.PoolNodes(input.OutboundsFile, state.Selector, servers)
	if err != nil || len(nodes) != len(selected) {
		fail("candidate_pool_nodes")
	}
	var pinned *xkeen.PoolNode
	for i := range nodes {
		if nodes[i].Server != nil && canonicalIdentity(*nodes[i].Server, template) == wantedIdentity {
			pinned = &nodes[i]
			break
		}
	}
	if pinned == nil || pinned.Tag == "" || pinned.NodeKey == "" {
		fail("preferred_pool_identity")
	}
	state.PinnedTag, state.PinnedNode = pinned.Tag, pinned.NodeKey
	state.PinManual = true
	state.PinCountry = xkeen.ServerCountry(preferred)
	state.PinNote = "Сохранён текущий сервер после настройки панели."
	if state.RoutingFile, ok = liveMetadataPath(input.CandidateConfigDir, input.LiveConfigDir, state.RoutingFile); !ok {
		fail("routing_metadata_path")
	}
	if state.APIFile, ok = liveMetadataPath(input.CandidateConfigDir, input.LiveConfigDir, state.APIFile); !ok {
		fail("api_metadata_path")
	}
	if _, err := sm.SetActive(preferredIndex); err != nil {
		fail("staged_active_server_save")
	}
	if xkeen.NewPoolStore(input.DataDir).Set(state) != nil {
		fail("staged_pool_save")
	}
	fmt.Printf("PREPARE_CATALOG=%d\nPREPARE_POOL_NODES=%d\nPREPARE_POOL_SKIPPED=%d\n", len(servers), len(nodes), len(servers)-len(nodes))
	fmt.Printf("PREPARE_PROBE_READY=%t\nPREPARE_PROBE_CHANGED=%t\n", ready, changed)
	fmt.Print("PREPARE_PIN_MANUAL=true\nPREPARE_PREFERRED_PRESERVED=true\nPREPARE_LIVE_WRITES=0\nPREPARE_DISPATCHER_CALLS=0\n")
}
