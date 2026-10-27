// profile-candidate exercises the production manual-profile write path against
// two private stage copies, then runs Xray -test. It never starts a core or an
// HTTP server, changes interception, invokes XKeen, or writes a live directory.
package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"time"

	"xkeen-panel/internal/models"
	"xkeen-panel/internal/xkeen"
)

const responseLimit = 16 << 20
const coreBinary = "/opt/sbin/xray"

var stagePattern = regexp.MustCompile(`^xkeen-universal-stage\.[A-Za-z0-9]{6}$`)

type candidateInfo struct {
	Index            int    `json:"index"`
	Kind             string `json:"kind"`
	ConfigDir        string `json:"config_dir"`
	APIAddr          string `json:"api_addr"`
	ProbeAddr        string `json:"probe_addr"`
	MainBalancer     string `json:"main_balancer"`
	PinnedTag        string `json:"pinned_tag"`
	PinManual        bool   `json:"pin_manual"`
	ProfileNodes     int    `json:"profile_nodes"`
	NativeTestPassed bool   `json:"native_test_passed"`
}

type candidateEnvelope struct {
	Candidates []candidateInfo `json:"candidates"`
}

func within(parent, path string) bool {
	rel, err := filepath.Rel(parent, path)
	return err == nil && !filepath.IsAbs(rel) && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

// /opt may itself be an Entware mount symlink. Resolve only that system
// anchor; all components below /opt/etc must be ordinary directories.
func ordinaryDescendant(anchor, path string) bool {
	if !within(anchor, path) {
		return false
	}
	rel, err := filepath.Rel(anchor, path)
	if err != nil {
		return false
	}
	current := anchor
	for _, component := range strings.Split(rel, string(filepath.Separator)) {
		if component == "." || component == "" {
			continue
		}
		current = filepath.Join(current, component)
		info, err := os.Lstat(current)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return false
		}
	}
	return true
}

func safeStage(raw string) (string, bool) {
	if !filepath.IsAbs(raw) {
		return "", false
	}
	stage := filepath.Clean(raw)
	anchor := "/opt/etc"
	if runtime.GOOS == "windows" {
		anchor = filepath.Clean(os.TempDir())
		if !within(anchor, stage) {
			return "", false
		}
	} else if filepath.Dir(stage) != anchor || !stagePattern.MatchString(filepath.Base(stage)) {
		return "", false
	}
	if !ordinaryDescendant(anchor, stage) {
		return "", false
	}
	info, err := os.Lstat(stage)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || runtime.GOOS != "windows" && info.Mode().Perm()&0077 != 0 {
		return "", false
	}
	for _, name := range []string{"profile-config-0", "profile-config-1", "candidate-info.json", "profile-candidate.log", "profile-config-0-test.log", "profile-config-1-test.log"} {
		if _, err := os.Lstat(filepath.Join(stage, name)); !os.IsNotExist(err) {
			return "", false
		}
	}
	return stage, true
}

func readRegular(path string, private bool) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() > responseLimit || private && runtime.GOOS != "windows" && info.Mode().Perm()&0077 != 0 {
		return nil, fmt.Errorf("protected_file")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("protected_file")
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, responseLimit+1))
	if err != nil || len(data) > responseLimit {
		return nil, fmt.Errorf("protected_file")
	}
	return data, nil
}

func decodeDocument(data []byte) (map[string]interface{}, error) {
	decoder := json.NewDecoder(bytes.NewReader(xkeen.StripJSONComments(data)))
	decoder.UseNumber()
	var document map[string]interface{}
	if decoder.Decode(&document) != nil || document == nil {
		return nil, fmt.Errorf("config_json")
	}
	var extra interface{}
	if decoder.Decode(&extra) != io.EOF {
		return nil, fmt.Errorf("config_json")
	}
	return document, nil
}

func writeDocument(path string, value interface{}) error {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return fmt.Errorf("config_encode")
	}
	data = append(data, '\n')
	if info, err := os.Lstat(path); err == nil && (!info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0) {
		return fmt.Errorf("config_file")
	}
	if os.WriteFile(path, data, 0600) != nil || os.Chmod(path, 0600) != nil {
		return fmt.Errorf("config_write")
	}
	return nil
}

func hash(data []byte) string { digest := sha256.Sum256(data); return hex.EncodeToString(digest[:]) }

func loadSourceConfigs(stage string) (map[string][]byte, error) {
	source := filepath.Join(stage, "live-configs")
	if !ordinaryDescendant(stage, source) {
		return nil, fmt.Errorf("source_directory")
	}
	paths, err := filepath.Glob(filepath.Join(source, "*.json"))
	if err != nil || len(paths) == 0 || len(paths) > 256 {
		return nil, fmt.Errorf("source_configs")
	}
	files := map[string][]byte{}
	size := 0
	for _, path := range paths {
		data, err := readRegular(path, false)
		if err != nil {
			return nil, err
		}
		if _, err := decodeDocument(data); err != nil {
			return nil, err
		}
		size += len(data)
		if size > 64<<20 {
			return nil, fmt.Errorf("source_size")
		}
		files[filepath.Base(path)] = data
	}
	if files["04_outbounds.json"] == nil || files["05_routing.json"] == nil {
		return nil, fmt.Errorf("source_main_files")
	}
	return files, nil
}

func profileKind(name string) string {
	name = strings.ToLower(name)
	auto := strings.Contains(name, "авто") || strings.Contains(name, "обход") || strings.Contains(name, "auto")
	fast := strings.Contains(name, "быстр") || strings.Contains(name, "fast")
	if auto == fast {
		return ""
	}
	if auto {
		return "AUTO"
	}
	return "FAST"
}

func selectProfiles(data []byte) ([]models.Server, error) {
	servers, _, err := xkeen.ParseSubscriptionDetailed(string(data))
	if err != nil {
		return nil, fmt.Errorf("subscription_parse")
	}
	selected := map[string]models.Server{}
	count := 0
	for _, server := range servers {
		if len(server.RawProfile) == 0 {
			continue
		}
		count++
		kind := profileKind(server.Name)
		if kind == "" {
			return nil, fmt.Errorf("profile_kind")
		}
		if _, exists := selected[kind]; exists {
			return nil, fmt.Errorf("duplicate_profile_kind")
		}
		selected[kind] = server
	}
	if count != 2 || len(selected) != 2 {
		return nil, fmt.Errorf("profile_count")
	}
	return []models.Server{selected["AUTO"], selected["FAST"]}, nil
}

func isolateCandidate(directory string) error {
	paths, err := filepath.Glob(filepath.Join(directory, "*.json"))
	if err != nil {
		return fmt.Errorf("isolation_configs")
	}
	probeCount, apiCount := 0, 0
	for _, path := range paths {
		data, err := readRegular(path, true)
		if err != nil {
			return err
		}
		document, err := decodeDocument(data)
		if err != nil {
			return err
		}
		if raw, exists := document["inbounds"]; exists {
			inbounds, ok := raw.([]interface{})
			if !ok {
				return fmt.Errorf("inbounds_array")
			}
			kept := []interface{}{}
			for _, item := range inbounds {
				inbound, ok := item.(map[string]interface{})
				if !ok {
					return fmt.Errorf("inbound_object")
				}
				if inbound["tag"] != xkeen.ProbeInboundTag {
					continue
				}
				if inbound["protocol"] != "socks" {
					return fmt.Errorf("probe_protocol")
				}
				inbound["listen"] = "127.0.0.1"
				inbound["port"] = 18086
				kept = append(kept, inbound)
				probeCount++
			}
			document["inbounds"] = kept
		}
		if raw, exists := document["api"]; exists {
			api, ok := raw.(map[string]interface{})
			if !ok {
				return fmt.Errorf("api_object")
			}
			api["listen"] = "127.0.0.1:18085"
			apiCount++
		}
		if raw, exists := document["log"]; exists {
			logging, ok := raw.(map[string]interface{})
			if !ok {
				return fmt.Errorf("log_object")
			}
			logging["access"] = "none"
			logging["error"] = filepath.Join(directory, "core-runtime.log")
		}
		if err := writeDocument(path, document); err != nil {
			return err
		}
	}
	if probeCount != 1 || apiCount != 1 {
		return fmt.Errorf("isolated_listener_count")
	}
	return nil
}

func prepareCandidate(stage string, index int, profile models.Server, source map[string][]byte) (candidateInfo, error) {
	info := candidateInfo{Index: index, Kind: profileKind(profile.Name), ConfigDir: filepath.Join(stage, fmt.Sprintf("profile-config-%d", index)), APIAddr: "127.0.0.1:18085", ProbeAddr: "127.0.0.1:18086", PinnedTag: xkeen.ManualTag, PinManual: true, ProfileNodes: profile.ProfileNodes}
	if os.Mkdir(info.ConfigDir, 0700) != nil {
		return info, fmt.Errorf("candidate_directory")
	}
	for name, data := range source {
		document, err := decodeDocument(data)
		if err != nil {
			return info, err
		}
		if err := writeDocument(filepath.Join(info.ConfigDir, name), document); err != nil {
			return info, err
		}
	}
	rt := xkeen.Runtime{Core: xkeen.CoreXray, XrayConfDir: info.ConfigDir, RoutingFile: filepath.Join(info.ConfigDir, "05_routing.json"), Installed: false, Dispatcher: "", CoreBin: "", InitScript: ""}
	top := xkeen.ReadTopology(rt)
	if top.Mode != xkeen.TopologyPool || top.BalancerTag == "" {
		return info, fmt.Errorf("baseline_pool")
	}
	info.MainBalancer = top.BalancerTag
	if err := xkeen.SetManualOutbound(rt, filepath.Join(info.ConfigDir, "04_outbounds.json"), profile); err != nil {
		phase := xkeen.ProfileRenderPhase(err)
		if phase != "" {
			log.Print("profile renderer phase: " + phase)
		}
		return info, fmt.Errorf("manual_profile_write")
	}
	if !xkeen.HasActiveProfile(filepath.Join(info.ConfigDir, "04_outbounds.json")) || !xkeen.HasManualOutbound(filepath.Join(info.ConfigDir, "04_outbounds.json")) {
		return info, fmt.Errorf("manual_profile_state")
	}
	if err := isolateCandidate(info.ConfigDir); err != nil {
		return info, err
	}
	return info, nil
}

func coreEnvironment(assets string) []string {
	var result []string
	for _, entry := range os.Environ() {
		key := strings.SplitN(entry, "=", 2)[0]
		switch key {
		case "XRAY_LOCATION_CONFIG", "XRAY_LOCATION_CONFDIR", "XRAY_LOCATION_ASSET":
			continue
		}
		result = append(result, entry)
	}
	return append(result, "XRAY_LOCATION_ASSET="+assets)
}

func testCandidate(stage string, info candidateInfo) bool {
	output, err := os.OpenFile(filepath.Join(stage, fmt.Sprintf("profile-config-%d-test.log", info.Index)), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return false
	}
	defer output.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, coreBinary, "run", "-test", "-confdir", info.ConfigDir)
	command.Env = coreEnvironment(filepath.Join(stage, "probe-assets"))
	command.Stdout = output
	command.Stderr = output
	return command.Run() == nil
}

func sourceUnchanged(stage string, responseHash string, source map[string][]byte) bool {
	response, err := readRegular(filepath.Join(stage, "source-response.json"), true)
	if err != nil || hash(response) != responseHash {
		return false
	}
	current, err := loadSourceConfigs(stage)
	if err != nil || len(current) != len(source) {
		return false
	}
	for name, data := range source {
		if hash(data) != hash(current[name]) {
			return false
		}
	}
	return true
}

func summary(candidates, passed int) {
	fmt.Printf("AUDIT_PROFILE_CANDIDATES=%d\nAUDIT_PROFILE_PASSED=%d\nAUDIT_PROFILE_FAILED=%d\n", candidates, passed, 2-passed)
}

func run() int {
	log.SetOutput(io.Discard)
	xkeen.Log = log.Printf
	flags := flag.NewFlagSet("profile-candidate", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	stageArg := flags.String("stage", "", "private universal stage")
	if flags.Parse(os.Args[1:]) != nil || flags.NArg() != 0 {
		summary(0, 0)
		return 1
	}
	stage, ok := safeStage(*stageArg)
	if !ok {
		summary(0, 0)
		return 1
	}
	output, err := os.OpenFile(filepath.Join(stage, "profile-candidate.log"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		summary(0, 0)
		return 1
	}
	defer output.Close()
	log.SetOutput(output)
	fail := func(code string, created int) int { log.Print(code); summary(created, 0); return 1 }
	response, err := readRegular(filepath.Join(stage, "source-response.json"), true)
	if err != nil {
		return fail("source_response", 0)
	}
	source, err := loadSourceConfigs(stage)
	if err != nil {
		return fail("source_configs", 0)
	}
	profiles, err := selectProfiles(response)
	if err != nil {
		return fail("profile_selection", 0)
	}
	if !ordinaryDescendant(stage, filepath.Join(stage, "probe-assets")) {
		return fail("probe_assets", 0)
	}
	envelope := candidateEnvelope{Candidates: []candidateInfo{}}
	for index, profile := range profiles {
		info, err := prepareCandidate(stage, index, profile, source)
		if err != nil {
			return fail("candidate_prepare", len(envelope.Candidates))
		}
		envelope.Candidates = append(envelope.Candidates, info)
	}
	passed := 0
	for index := range envelope.Candidates {
		info := &envelope.Candidates[index]
		info.NativeTestPassed = testCandidate(stage, *info)
		if info.NativeTestPassed {
			passed++
		}
		log.Printf("candidate %d native_test=%t", index, info.NativeTestPassed)
	}
	if err := writeDocument(filepath.Join(stage, "candidate-info.json"), envelope); err != nil {
		return fail("candidate_info", 2)
	}
	if !sourceUnchanged(stage, hash(response), source) {
		return fail("source_changed", 2)
	}
	summary(2, passed)
	if passed != 2 {
		return 1
	}
	return 0
}

func main() { os.Exit(run()) }
