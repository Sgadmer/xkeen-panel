// subscription-audit imports and checks a subscription in its own private data
// directory. It does not start the panel HTTP server, discover the production
// runtime, restart a service, or write any production configuration file.
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"xkeen-panel/internal/models"
	"xkeen-panel/internal/xkeen"
)

const auditOwnerFile = ".subscription-audit-owner"
const auditOwnerValue = "panel-custom-subscription-audit-v1\n"
const maxAuditInputBytes = 64 << 10
const maxBaselineBytes = 16 << 20

type auditInput struct {
	URL                   string   `json:"url"`
	HWID                  string   `json:"hwid"`
	DataDir               string   `json:"data_dir"`
	CoreBin               string   `json:"core_bin"`
	BaselineOutboundsFile string   `json:"baseline_outbounds_file"`
	Probe                 bool     `json:"probe"`
	ExcludeCountries      []string `json:"exclude_countries"`
}

type auditCounts struct {
	Imported           int `json:"imported"`
	RawOutbounds       int `json:"raw_outbounds"`
	VLESS              int `json:"vless"`
	HY2                int `json:"hy2"`
	Other              int `json:"other"`
	SkippedComposite   int `json:"skipped_composite"`
	SkippedUnsupported int `json:"skipped_unsupported"`
	BuildFailures      int `json:"build_failures"`
	Baseline           int `json:"baseline"`
	BaselineUnique     int `json:"baseline_unique"`
	BaselinePreserved  int `json:"baseline_preserved"`
	BaselineMissing    int `json:"baseline_missing"`
	Excluded           int `json:"excluded"`
	ProbeTotal         int `json:"probe_total"`
	VLESSSuccess       int `json:"vless_success"`
	VLESSFailed        int `json:"vless_failed"`
	HY2Success         int `json:"hy2_success"`
	HY2Failed          int `json:"hy2_failed"`
	OtherSuccess       int `json:"other_success"`
	OtherFailed        int `json:"other_failed"`
}

type auditNodeCheck struct {
	ID        int    `json:"id"`
	Protocol  string `json:"protocol"`
	Latency   int    `json:"latency_ms"`
	ProbeKind string `json:"probe_kind"`
}

type auditState struct {
	CreatedAt    time.Time          `json:"created_at"`
	Counts       auditCounts        `json:"counts"`
	ImportReport xkeen.ImportReport `json:"import_report"`
	Checks       []auditNodeCheck   `json:"checks,omitempty"`
	HWIDReused   bool               `json:"hwid_reused"`
}

func auditFail(code string) {
	// No native errors, URLs, paths, names, response bodies, or credentials are
	// ever formatted into stdout/stderr, including flag and panic failures.
	log.Print("audit failed: " + code)
	fmt.Fprintln(os.Stderr, "AUDIT_ERROR="+code)
	os.Exit(1)
}

func readLimitedFile(path string, limit int64, private bool) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() > limit {
		return nil, fmt.Errorf("file_invalid")
	}
	if private && os.PathSeparator != '\\' && info.Mode().Perm()&0077 != 0 {
		return nil, fmt.Errorf("file_permissions")
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("file_read")
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil || int64(len(data)) > limit {
		return nil, fmt.Errorf("file_read")
	}
	return data, nil
}

func decodeExactJSON(data []byte, target interface{}) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if decoder.Decode(target) != nil {
		return fmt.Errorf("json_invalid")
	}
	var extra interface{}
	if decoder.Decode(&extra) != io.EOF {
		return fmt.Errorf("json_trailing")
	}
	return nil
}

func writePrivateNew(path string, data []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return fmt.Errorf("file_create")
	}
	defer f.Close()
	if _, err := f.Write(data); err != nil {
		return fmt.Errorf("file_write")
	}
	if err := f.Sync(); err != nil {
		return fmt.Errorf("file_sync")
	}
	return nil
}

func prepareAuditDir(dir string) error {
	if !filepath.IsAbs(dir) || filepath.Clean(dir) == string(filepath.Separator) {
		return fmt.Errorf("data_dir_invalid")
	}
	info, err := os.Lstat(dir)
	if os.IsNotExist(err) {
		// Mkdir rather than MkdirAll: only this explicitly named test directory
		// is created. Its parent must already exist.
		if os.Mkdir(dir, 0700) != nil {
			return fmt.Errorf("data_dir_create")
		}
		return writePrivateNew(filepath.Join(dir, auditOwnerFile), []byte(auditOwnerValue))
	}
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("data_dir_invalid")
	}
	if os.PathSeparator != '\\' && info.Mode().Perm()&0077 != 0 {
		return fmt.Errorf("data_dir_permissions")
	}
	marker, err := readLimitedFile(filepath.Join(dir, auditOwnerFile), 128, true)
	if err != nil || string(marker) != auditOwnerValue {
		return fmt.Errorf("data_dir_unrelated")
	}
	return nil
}

func seedAuditIdentity(dir, hwid string) error {
	path := filepath.Join(dir, "subscription-client.json")
	if _, err := os.Lstat(path); os.IsNotExist(err) {
		data, err := json.Marshal(struct {
			Version int    `json:"version"`
			HWID    string `json:"hwid"`
		}{Version: 1, HWID: hwid})
		if err != nil || writePrivateNew(path, append(data, '\n')) != nil {
			return fmt.Errorf("identity_seed")
		}
		return nil
	}
	return verifyAuditIdentity(dir, hwid)
}

func verifyAuditIdentity(dir, expected string) error {
	data, err := readLimitedFile(filepath.Join(dir, "subscription-client.json"), 8192, true)
	if err != nil {
		return fmt.Errorf("identity_read")
	}
	var stored struct {
		Version int    `json:"version"`
		HWID    string `json:"hwid"`
	}
	if decodeExactJSON(data, &stored) != nil || stored.Version != 1 || stored.HWID != expected {
		return fmt.Errorf("identity_mismatch")
	}
	return nil
}

func rawMap(value interface{}) map[string]interface{} {
	object, _ := value.(map[string]interface{})
	return object
}

// Comparison intentionally performs no transport/credential normalization. It
// ignores only the runtime tag and local mark. Other socket options, secrets,
// REALITY/TLS, xhttp extras, and number precision must remain byte-semantically
// equivalent after canonical JSON key ordering.
func connectionHash(outbound map[string]interface{}) (string, error) {
	encoded, err := json.Marshal(outbound)
	if err != nil {
		return "", fmt.Errorf("canonical_json")
	}
	var canonical map[string]interface{}
	if decodeExactJSON(encoded, &canonical) != nil {
		return "", fmt.Errorf("canonical_json")
	}
	delete(canonical, "tag")
	if stream := rawMap(canonical["streamSettings"]); stream != nil {
		if options := rawMap(stream["sockopt"]); options != nil {
			delete(options, "mark")
			if len(options) == 0 {
				delete(stream, "sockopt")
			}
		}
		if len(stream) == 0 {
			delete(canonical, "streamSettings")
		}
	}
	encoded, err = json.Marshal(canonical)
	if err != nil {
		return "", fmt.Errorf("canonical_json")
	}
	hash := sha256.Sum256(encoded)
	return hex.EncodeToString(hash[:]), nil
}

func baselineHashes(path string) ([]string, error) {
	data, err := readLimitedFile(path, maxBaselineBytes, false)
	if err != nil {
		return nil, fmt.Errorf("baseline_read")
	}
	var object map[string]interface{}
	if decodeExactJSON(xkeen.StripJSONComments(data), &object) != nil {
		return nil, fmt.Errorf("baseline_json")
	}
	outbounds, ok := object["outbounds"].([]interface{})
	if !ok {
		return nil, fmt.Errorf("baseline_outbounds")
	}
	var hashes []string
	for _, raw := range outbounds {
		outbound := rawMap(raw)
		if outbound == nil {
			return nil, fmt.Errorf("baseline_outbound")
		}
		protocol, _ := outbound["protocol"].(string)
		switch strings.ToLower(protocol) {
		case "freedom", "blackhole", "dns", "loopback":
			continue
		}
		if protocol == "" {
			return nil, fmt.Errorf("baseline_protocol")
		}
		hash, err := connectionHash(outbound)
		if err != nil {
			return nil, err
		}
		hashes = append(hashes, hash)
	}
	if len(hashes) == 0 {
		return nil, fmt.Errorf("baseline_empty")
	}
	return hashes, nil
}

func protocolClass(server models.Server) string {
	switch strings.ToLower(server.Protocol) {
	case "vless":
		return "vless"
	case "hysteria", "hysteria2", "hy2":
		return "hy2"
	default:
		return "other"
	}
}

func compareBaseline(servers []models.Server, baseline []string, counts *auditCounts) {
	built := make(map[string]bool, len(servers))
	template := map[string]interface{}{"streamSettings": map[string]interface{}{"sockopt": map[string]interface{}{"mark": 255}}}
	for _, server := range servers {
		if len(server.RawOutbound) > 0 {
			counts.RawOutbounds++
		}
		switch protocolClass(server) {
		case "vless":
			counts.VLESS++
		case "hy2":
			counts.HY2++
		default:
			counts.Other++
		}
		outbound, err := xkeen.BuildServerOutbound(server, "audit-node", template)
		if err != nil {
			counts.BuildFailures++
			continue
		}
		hash, err := connectionHash(outbound)
		if err != nil {
			counts.BuildFailures++
			continue
		}
		built[hash] = true
	}
	uniqueBaseline := make(map[string]bool)
	for _, hash := range baseline {
		uniqueBaseline[hash] = true
		if built[hash] {
			counts.BaselinePreserved++
		} else {
			counts.BaselineMissing++
		}
	}
	counts.Baseline = len(baseline)
	counts.BaselineUnique = len(uniqueBaseline)
}

func writeAuditState(path string, state auditState) error {
	if info, err := os.Lstat(path); err == nil && !info.Mode().IsRegular() {
		return fmt.Errorf("state_not_regular")
	} else if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("state_unavailable")
	}
	encoded, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return fmt.Errorf("state_json")
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
	if err != nil {
		return fmt.Errorf("state_write")
	}
	defer f.Close()
	if f.Chmod(0600) != nil {
		return fmt.Errorf("state_permissions")
	}
	if _, err := f.Write(append(encoded, '\n')); err != nil {
		return fmt.Errorf("state_write")
	}
	return f.Sync()
}

func emitAuditCounts(counts auditCounts, reused bool) {
	values := []struct {
		name string
		n    int
	}{
		{"IMPORTED", counts.Imported}, {"RAW_OUTBOUNDS", counts.RawOutbounds},
		{"VLESS", counts.VLESS}, {"HY2", counts.HY2}, {"OTHER", counts.Other},
		{"SKIPPED_COMPOSITE", counts.SkippedComposite}, {"SKIPPED_UNSUPPORTED", counts.SkippedUnsupported},
		{"BUILD_FAILURES", counts.BuildFailures}, {"BASELINE_TOTAL", counts.Baseline},
		{"BASELINE_UNIQUE", counts.BaselineUnique}, {"BASELINE_PRESERVED", counts.BaselinePreserved},
		{"BASELINE_MISSING", counts.BaselineMissing}, {"COUNTRIES_EXCLUDED", counts.Excluded},
		{"PROBE_TOTAL", counts.ProbeTotal}, {"VLESS_HTTPS_SUCCESS", counts.VLESSSuccess},
		{"VLESS_HTTPS_FAILED", counts.VLESSFailed}, {"HY2_HTTPS_SUCCESS", counts.HY2Success},
		{"HY2_HTTPS_FAILED", counts.HY2Failed}, {"OTHER_HTTPS_SUCCESS", counts.OtherSuccess},
		{"OTHER_HTTPS_FAILED", counts.OtherFailed},
	}
	for _, value := range values {
		fmt.Printf("AUDIT_%s=%d\n", value.name, value.n)
	}
	fmt.Printf("AUDIT_HWID_REUSED=%t\n", reused)
}

func main() {
	log.SetOutput(io.Discard)
	xkeen.Log = log.Printf
	defer func() {
		if recover() != nil {
			auditFail("internal")
		}
	}()
	flags := flag.NewFlagSet("subscription-audit", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	inputPath := flags.String("input", "", "protected audit input JSON")
	if flags.Parse(os.Args[1:]) != nil || *inputPath == "" || flags.NArg() != 0 {
		auditFail("arguments")
	}
	data, err := readLimitedFile(*inputPath, maxAuditInputBytes, true)
	var input auditInput
	if err != nil || decodeExactJSON(data, &input) != nil {
		auditFail("input")
	}
	parsedURL, err := url.Parse(input.URL)
	if err != nil || parsedURL.Hostname() == "" || (parsedURL.Scheme != "http" && parsedURL.Scheme != "https") || !regexp.MustCompile(`^[a-zA-Z0-9=-]{10,64}$`).MatchString(input.HWID) || input.BaselineOutboundsFile == "" {
		auditFail("input_fields")
	}
	if input.Probe && (!filepath.IsAbs(input.CoreBin) || input.CoreBin == "") {
		auditFail("core_binary")
	}
	if prepareAuditDir(input.DataDir) != nil {
		auditFail("data_dir_unrelated_or_unavailable")
	}
	logPath := filepath.Join(input.DataDir, "audit.log")
	if info, err := os.Lstat(logPath); err == nil && !info.Mode().IsRegular() || err != nil && !os.IsNotExist(err) {
		auditFail("log_file")
	}
	privateLog, err := os.OpenFile(logPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil || privateLog.Chmod(0600) != nil {
		auditFail("log_file")
	}
	defer privateLog.Close()
	log.SetOutput(privateLog)
	if seedAuditIdentity(input.DataDir, input.HWID) != nil {
		auditFail("hwid_seed_or_mismatch")
	}
	baseline, err := baselineHashes(input.BaselineOutboundsFile)
	if err != nil {
		auditFail("baseline")
	}
	sm := xkeen.NewSubscriptionManager(input.DataDir)
	if sm.Load() != nil {
		auditFail("subscription_load")
	}
	servers, err := sm.UpdateURL(input.URL)
	if err != nil {
		log.Printf("subscription import rejected: %v", err)
		auditFail("subscription_import")
	}
	if verifyAuditIdentity(input.DataDir, input.HWID) != nil {
		auditFail("hwid_changed")
	}
	report := sm.GetImportReport()
	counts := auditCounts{Imported: len(servers), SkippedComposite: report.SkippedComposite, SkippedUnsupported: report.SkippedUnsupported}
	compareBaseline(servers, baseline, &counts)
	excluded := make(map[string]bool)
	if len(input.ExcludeCountries) == 0 {
		input.ExcludeCountries = []string{"RU", "BY"}
	}
	for _, country := range input.ExcludeCountries {
		country = strings.ToUpper(strings.TrimSpace(country))
		if !regexp.MustCompile(`^[A-Z]{2}$`).MatchString(country) {
			auditFail("exclude_countries")
		}
		excluded[country] = true
	}
	var candidates []models.Server
	for _, server := range servers {
		country := strings.ToUpper(strings.TrimSpace(server.CountryOverride))
		if country == "" {
			country = strings.ToUpper(strings.TrimSpace(server.Country))
		}
		if excluded[country] {
			counts.Excluded++
			continue
		}
		candidates = append(candidates, server)
	}
	state := auditState{CreatedAt: time.Now().UTC(), ImportReport: report, HWIDReused: true}
	if input.Probe {
		checked, err := xkeen.CheckServersHTTPS(xkeen.Runtime{Core: xkeen.CoreXray, CoreBin: input.CoreBin}, candidates, xkeen.ProbeOptions{StateDir: input.DataDir, Timeout: 8 * time.Second, Concurrency: 3})
		if err != nil {
			log.Printf("isolated HTTPS probe rejected: %v", err)
			auditFail("https_probe")
		}
		counts.ProbeTotal = len(checked)
		for _, server := range checked {
			pass := server.ProbeKind == "https" && server.Latency >= 0
			switch protocolClass(server) {
			case "vless":
				if pass {
					counts.VLESSSuccess++
				} else {
					counts.VLESSFailed++
				}
			case "hy2":
				if pass {
					counts.HY2Success++
				} else {
					counts.HY2Failed++
				}
			default:
				if pass {
					counts.OtherSuccess++
				} else {
					counts.OtherFailed++
				}
			}
			state.Checks = append(state.Checks, auditNodeCheck{ID: server.ID, Protocol: protocolClass(server), Latency: server.Latency, ProbeKind: server.ProbeKind})
		}
		sm.UpdateLatencies(checked)
		if sm.Save() != nil {
			auditFail("probe_save")
		}
	}
	state.Counts = counts
	if writeAuditState(filepath.Join(input.DataDir, "audit-state.json"), state) != nil {
		auditFail("audit_state_write")
	}
	emitAuditCounts(counts, true)
	if counts.BaselineMissing > 0 || counts.BuildFailures > 0 {
		os.Exit(2)
	}
}
