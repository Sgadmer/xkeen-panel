// format-audit validates public synthetic subscriptions with the installed
// Xray v26.3.27. It only invokes `run -test`: no HTTP app, listeners, tunnel
// probes, production configuration writes, or dispatcher commands are used.
package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"time"

	"xkeen-panel/internal/xkeen"
)

const syntheticUUID = "00000000-0000-4000-8000-000000000001"
const syntheticPublicKey = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8"
const syntheticSS2022Key = "MDEyMzQ1Njc4OWFiY2RlZg=="
const expectedCoreVersion = "26.3.27"

var safeCaseID = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)
var stageName = regexp.MustCompile(`^xkeen-(custom|universal)-stage\.[A-Za-z0-9]{6}$`)
var outputName = regexp.MustCompile(`^format-audit(?:\.[A-Za-z0-9_-]{1,32})?$`)

type auditCase struct {
	ID       string
	Body     string
	Protocol string
	Reject   bool
}

// All credentials/hosts below are deliberately synthetic. Keeping the data in
// this binary makes the native audit independent of subscription/secret files.
func auditCases() []auditCase {
	clash := []struct{ id, protocol, node string }{
		{"vless_reality", "vless", `name: Synthetic VLESS
    type: vless
    server: vless.example.invalid
    port: 443
    uuid: ` + syntheticUUID + `
    flow: xtls-rprx-vision
    tls: true
    servername: tls.example.invalid
    client-fingerprint: chrome
    reality-opts: {public-key: ` + syntheticPublicKey + `, short-id: "0102"}`},
		{"vmess_ws", "vmess", `name: Synthetic VMess
    type: vmess
    server: vmess.example.invalid
    port: 443
    uuid: ` + syntheticUUID + `
    alterId: 0
    cipher: aes-128-gcm
    tls: true
    servername: tls.example.invalid
    network: ws
    ws-opts: {path: /synthetic, headers: {Host: cdn.example.invalid}, max-early-data: 1024, early-data-header-name: Sec-WebSocket-Protocol}`},
		{"trojan_grpc", "trojan", `name: Synthetic Trojan
    type: trojan
    server: trojan.example.invalid
    port: 443
    password: synthetic-password
    sni: tls.example.invalid
    network: grpc
    grpc-opts: {grpc-service-name: synthetic-service, grpc-user-agent: synthetic-client}`},
		{"ss2022", "shadowsocks", `name: Synthetic Shadowsocks
    type: ss
    server: ss.example.invalid
    port: 8443
    cipher: 2022-blake3-aes-128-gcm
    password: ` + syntheticSS2022Key},
		{"socks5", "socks", `name: Synthetic SOCKS
    type: socks5
    server: socks.example.invalid
    port: 1080
    username: synthetic-user
    password: synthetic-password`},
		{"http", "http", `name: Synthetic HTTP
    type: http
    server: http.example.invalid
    port: 8080
    username: synthetic-user
    password: synthetic-password
    headers: {X-Synthetic: audit}`},
		{"hy2_hops", "hysteria2", `name: Synthetic Hysteria2
    type: hysteria2
    server: hy2.example.invalid
    port: 443
    ports: 5000-5002,8443
    hop-interval: 20
    password: synthetic-password
    up: 30
    down: 100 Mbps
    obfs: salamander
    obfs-password: synthetic-obfs
    sni: tls.example.invalid
    alpn: [h3]`},
	}
	singbox := []struct{ id, protocol, node string }{
		{"vless_reality", "vless", `{"type":"vless","tag":"Synthetic","server":"vless.example.invalid","server_port":443,"uuid":"` + syntheticUUID + `","flow":"xtls-rprx-vision","tls":{"enabled":true,"server_name":"tls.example.invalid","utls":{"enabled":true,"fingerprint":"chrome"},"reality":{"enabled":true,"public_key":"` + syntheticPublicKey + `","short_id":"0102"}}}`},
		{"vmess_grpc", "vmess", `{"type":"vmess","tag":"Synthetic","server":"vmess.example.invalid","server_port":443,"uuid":"` + syntheticUUID + `","security":"aes-128-gcm","alter_id":0,"authenticated_length":true,"tls":{"enabled":true,"server_name":"tls.example.invalid","alpn":["h2"]},"transport":{"type":"grpc","service_name":"synthetic-service","idle_timeout":"30s","ping_timeout":"15s","permit_without_stream":true}}`},
		{"trojan_upgrade", "trojan", `{"type":"trojan","tag":"Synthetic","server":"trojan.example.invalid","server_port":443,"password":"synthetic-password","tls":{"enabled":true,"server_name":"tls.example.invalid"},"transport":{"type":"httpupgrade","path":"/synthetic","host":"cdn.example.invalid","headers":{"X-Synthetic":"audit"}}}`},
		{"ss2022", "shadowsocks", `{"type":"shadowsocks","tag":"Synthetic","server":"ss.example.invalid","server_port":8443,"method":"2022-blake3-aes-128-gcm","password":"` + syntheticSS2022Key + `"}`},
		{"socks5_noauth", "socks", `{"type":"socks","tag":"Synthetic","server":"socks.example.invalid","server_port":1080,"version":"5"}`},
		{"http_tls", "http", `{"type":"http","tag":"Synthetic","server":"http.example.invalid","server_port":443,"username":"synthetic-user","password":"synthetic-password","headers":{"X-Synthetic":"audit"},"tls":{"enabled":true,"server_name":"tls.example.invalid"}}`},
		{"hy2_hops", "hysteria2", `{"type":"hysteria2","tag":"Synthetic","server":"hy2.example.invalid","server_port":443,"server_ports":["5000:5002","8443"],"hop_interval":"20s","password":"synthetic-password","up_mbps":30,"down_mbps":100,"obfs":{"type":"salamander","password":"synthetic-obfs"},"tls":{"enabled":true,"server_name":"tls.example.invalid","alpn":["h3"]}}`},
	}
	var result []auditCase
	for _, node := range clash {
		result = append(result, auditCase{ID: "clash_" + node.id, Body: "proxies:\n  - " + node.node + "\n", Protocol: node.protocol})
	}
	for _, node := range singbox {
		result = append(result, auditCase{ID: "singbox_" + node.id, Body: "// Synthetic sing-box JSONC\n{\"outbounds\":[" + node.node + "]}", Protocol: node.protocol})
	}
	vmessJSON := `{"v":"2","ps":"Synthetic","add":"vmess.example.invalid","port":"443","id":"` + syntheticUUID + `","aid":"0","scy":"aes-128-gcm","net":"ws","type":"none","host":"cdn.example.invalid","path":"/synthetic?ed=1024","tls":"tls","sni":"tls.example.invalid","fp":"chrome"}`
	uri := []struct{ id, protocol, body string }{
		{"vless_reality", "vless", "vless://" + syntheticUUID + "@vless.example.invalid:443?type=tcp&security=reality&sni=tls.example.invalid&fp=chrome&pbk=" + syntheticPublicKey + "&sid=0102&flow=xtls-rprx-vision#Synthetic"},
		{"vmess_ws", "vmess", "vmess://" + base64.RawURLEncoding.EncodeToString([]byte(vmessJSON))},
		{"trojan_grpc", "trojan", "trojan://synthetic-password@trojan.example.invalid:443?security=tls&type=grpc&serviceName=synthetic-service&sni=tls.example.invalid&fp=chrome#Synthetic"},
		{"ss2022", "shadowsocks", "ss://" + url.UserPassword("2022-blake3-aes-128-gcm", syntheticSS2022Key).String() + "@ss.example.invalid:8443#Synthetic"},
		{"hy2_hops", "hysteria2", "hy2://synthetic-password@hy2.example.invalid:443?sni=tls.example.invalid&obfs=salamander&obfs-password=synthetic-obfs&up=30&down=100&mport=5000-5002,8443&hop-interval=20#Synthetic"},
	}
	for _, node := range uri {
		result = append(result, auditCase{ID: "uri_" + node.id, Body: node.body, Protocol: node.protocol})
		result = append(result, auditCase{ID: "base64_uri_" + node.id, Body: base64.StdEncoding.EncodeToString([]byte(node.body + "\n")), Protocol: node.protocol})
	}
	result = append(result,
		auditCase{ID: "clash_raw_http", Protocol: "vmess", Body: "proxies:\n  - {name: Synthetic, type: vmess, server: raw.example.invalid, port: 80, uuid: " + syntheticUUID + ", cipher: aes-128-gcm, network: http, http-opts: {method: GET, path: [/one, /two], headers: {Host: [cdn.example.invalid]}}}\n"},
		auditCase{ID: "clash_xhttp", Protocol: "vless", Body: "proxies:\n  - {name: Synthetic, type: vless, server: xhttp.example.invalid, port: 443, uuid: " + syntheticUUID + ", tls: true, servername: tls.example.invalid, network: xhttp, xhttp-opts: {path: /synthetic, host: cdn.example.invalid, mode: stream-up, no-grpc-header: true, reuse-settings: {max-concurrency: 16-32}}}\n"},
		auditCase{ID: "clash_certificate_pin", Protocol: "trojan", Body: "proxies:\n  - {name: Synthetic, type: trojan, server: pin.example.invalid, port: 443, password: synthetic-password, skip-cert-verify: true, fingerprint: \"" + strings.Repeat("ab", 32) + "\", name-cert-verify: tls.example.invalid}\n"},
		auditCase{ID: "singbox_certificate_pin", Protocol: "trojan", Body: `{"type":"trojan","server":"pin.example.invalid","server_port":443,"password":"synthetic-password","tls":{"enabled":true,"server_name":"tls.example.invalid","certificate_sha256":["` + base64.StdEncoding.EncodeToString(make([]byte, 32)) + `"]}}`},
		auditCase{ID: "singbox_ws_early_data", Protocol: "vless", Body: `{"type":"vless","server":"ws.example.invalid","server_port":443,"uuid":"` + syntheticUUID + `","tls":{"enabled":true,"server_name":"tls.example.invalid"},"transport":{"type":"ws","path":"/synthetic","headers":{"Host":"cdn.example.invalid"},"max_early_data":1024,"early_data_header_name":"Sec-WebSocket-Protocol"}}`},
	)
	result = append(result,
		auditCase{ID: "reject_clash_protocol", Reject: true, Body: "proxies:\n  - {name: Synthetic, type: anytls, server: unsupported.invalid, port: 443, password: synthetic}\n"},
		auditCase{ID: "reject_clash_unknown_field", Reject: true, Body: "proxies:\n  - {name: Synthetic, type: trojan, server: unsupported.invalid, port: 443, password: synthetic, future-wire-option: enabled}\n"},
		auditCase{ID: "reject_clash_group_only", Reject: true, Body: "proxies: []\nproxy-groups:\n  - {name: Synthetic, type: relay, proxies: []}\n"},
		auditCase{ID: "reject_singbox_spki", Reject: true, Body: `{"type":"trojan","server":"unsupported.invalid","server_port":443,"password":"synthetic","tls":{"enabled":true,"certificate_public_key_sha256":["` + base64.StdEncoding.EncodeToString(make([]byte, 32)) + `"]}}`},
		auditCase{ID: "reject_singbox_http_transport", Reject: true, Body: `{"type":"vless","server":"unsupported.invalid","server_port":443,"uuid":"` + syntheticUUID + `","transport":{"type":"http","path":"/synthetic"}}`},
		auditCase{ID: "reject_singbox_detour", Reject: true, Body: `{"type":"vless","server":"unsupported.invalid","server_port":443,"uuid":"` + syntheticUUID + `","detour":"another-proxy"}`},
		auditCase{ID: "reject_uri_ss_plugin", Reject: true, Body: "ss://" + base64.RawURLEncoding.EncodeToString([]byte("aes-128-gcm:synthetic")) + "@unsupported.invalid:443?plugin=obfs"},
		auditCase{ID: "reject_uri_trojan_unknown", Reject: true, Body: "trojan://synthetic@unsupported.invalid:443?security=tls&future-wire-option=enabled"},
		auditCase{ID: "reject_uri_hy2_insecure", Reject: true, Body: "hy2://synthetic@unsupported.invalid:443?insecure=true"},
	)
	return result
}

func prepareCase(spec auditCase) (map[string]interface{}, bool) {
	servers, report, err := xkeen.ParseSubscriptionDetailed(spec.Body)
	if spec.Reject {
		if err != nil && len(servers) == 0 {
			return nil, true
		}
		if err == nil && len(servers) == 1 {
			_, buildErr := xkeen.BuildServerOutbound(servers[0], "synthetic", nil)
			return nil, buildErr != nil
		}
		return nil, false
	}
	if err != nil || len(servers) != 1 || servers[0].Protocol != spec.Protocol || len(servers[0].RawProfile) > 0 || report.SkippedComposite != 0 || report.SkippedUnsupported != 0 {
		return nil, false
	}
	template := map[string]interface{}{"streamSettings": map[string]interface{}{"sockopt": map[string]interface{}{"mark": 255}}}
	outbound, err := xkeen.BuildServerOutbound(servers[0], "synthetic", template)
	return outbound, err == nil
}

func inside(parent, path string) bool {
	rel, err := filepath.Rel(parent, path)
	return err == nil && !filepath.IsAbs(rel) && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

func safeOrdinaryDescendant(anchor, path string) bool {
	if !inside(anchor, path) {
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

func createOutput(raw string) (string, bool) {
	temporary := filepath.Clean(os.TempDir())
	if runtime.GOOS != "windows" {
		temporary = "/tmp"
	}
	if raw == "" {
		path, err := os.MkdirTemp(temporary, "panel-format-audit-")
		return path, err == nil
	}
	if !filepath.IsAbs(raw) {
		return "", false
	}
	path := filepath.Clean(raw)
	parent := filepath.Dir(path)
	if runtime.GOOS != "windows" && inside("/opt/etc", path) {
		if filepath.Dir(parent) != "/opt/etc" || !stageName.MatchString(filepath.Base(parent)) || !outputName.MatchString(filepath.Base(path)) || !safeOrdinaryDescendant("/opt/etc", parent) {
			return "", false
		}
		info, err := os.Stat(parent)
		if err != nil || info.Mode().Perm()&0077 != 0 {
			return "", false
		}
	} else if !inside(temporary, path) || path == temporary || !safeOrdinaryDescendant(temporary, parent) {
		return "", false
	}
	if err := os.Mkdir(path, 0700); err != nil {
		return "", false
	}
	return path, true
}

func coreEnvironment(assets string) []string {
	var env []string
	for _, entry := range os.Environ() {
		key := strings.SplitN(entry, "=", 2)[0]
		switch key {
		case "XRAY_LOCATION_CONFDIR", "XRAY_LOCATION_CONFIG", "XRAY_LOCATION_ASSET":
			continue
		}
		env = append(env, entry)
	}
	return append(env, "XRAY_LOCATION_ASSET="+assets)
}

func validateVersion(core, assets, directory string) bool {
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, core, "version")
	command.Env = coreEnvironment(assets)
	data, err := command.CombinedOutput()
	if len(data) > 1<<20 {
		return false
	}
	if os.WriteFile(filepath.Join(directory, "core-version.log"), data, 0600) != nil {
		return false
	}
	if err != nil {
		return false
	}
	fields := strings.Fields(string(data))
	return len(fields) > 1 && fields[0] == "Xray" && fields[1] == expectedCoreVersion
}

func validateNative(core, assets, directory string, spec auditCase, outbound map[string]interface{}) bool {
	if !safeCaseID.MatchString(spec.ID) {
		return false
	}
	document := map[string]interface{}{"log": map[string]interface{}{"loglevel": "none"}, "inbounds": []interface{}{}, "outbounds": []interface{}{outbound}}
	data, err := json.MarshalIndent(document, "", "  ")
	if err != nil {
		return false
	}
	path := filepath.Join(directory, spec.ID+".json")
	if os.WriteFile(path, data, 0600) != nil {
		return false
	}
	output, err := os.OpenFile(filepath.Join(directory, spec.ID+".log"), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return false
	}
	defer output.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, core, "run", "-test", "-config", path)
	command.Env = coreEnvironment(assets)
	command.Stdin = nil
	command.Stdout = output
	command.Stderr = output
	return command.Run() == nil
}

func summary(total, passed int, failed []string) {
	fmt.Printf("AUDIT_FORMAT_CASES=%d\nAUDIT_FORMAT_PASSED=%d\nAUDIT_FORMAT_FAILED=%d\n", total, passed, total-passed)
	for _, id := range failed {
		if safeCaseID.MatchString(id) {
			fmt.Printf("AUDIT_FORMAT_FAILED_CASE=%s\n", id)
		}
	}
}

func run() int {
	log.SetOutput(io.Discard)
	xkeen.Log = log.Printf
	flags := flag.NewFlagSet("format-audit", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	core := flags.String("core", "/opt/sbin/xray", "installed Xray binary")
	assets := flags.String("assets", "/opt/etc/xray/dat", "Xray assets directory")
	outdir := flags.String("outdir", "", "new private output directory under /tmp or the custom stage")
	keep := flags.Bool("keep", false, "retain temporary logs after a successful audit")
	if flags.Parse(os.Args[1:]) != nil || flags.NArg() != 0 || !filepath.IsAbs(*core) || !filepath.IsAbs(*assets) {
		summary(1, 0, []string{"arguments"})
		return 1
	}
	coreInfo, coreErr := os.Stat(*core)
	assetsInfo, assetsErr := os.Stat(*assets)
	if coreErr != nil || !coreInfo.Mode().IsRegular() || assetsErr != nil || !assetsInfo.IsDir() {
		summary(1, 0, []string{"setup"})
		return 1
	}
	directory, ok := createOutput(*outdir)
	if !ok {
		summary(1, 0, []string{"output_directory"})
		return 1
	}
	auditLog, err := os.OpenFile(filepath.Join(directory, "audit.log"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		summary(1, 0, []string{"private_log"})
		return 1
	}
	defer auditLog.Close()
	log.SetOutput(auditLog)
	if !validateVersion(*core, *assets, directory) {
		log.Print("core_version rejected")
		summary(1, 0, []string{"core_version"})
		return 1
	}
	cases := auditCases()
	passed := 1
	var failed []string
	for _, spec := range cases {
		outbound, valid := prepareCase(spec)
		if valid && !spec.Reject {
			valid = validateNative(*core, *assets, directory, spec, outbound)
		}
		if valid {
			passed++
			log.Print(spec.ID + " passed")
		} else {
			failed = append(failed, spec.ID)
			log.Print(spec.ID + " failed")
		}
	}
	summary(len(cases)+1, passed, failed)
	if len(failed) > 0 {
		return 1
	}
	if !*keep && *outdir == "" {
		// Only the unique directory created by this invocation is removed.
		// Close the log first so this also works in a Windows fixture run.
		log.SetOutput(io.Discard)
		auditLog.Close()
		_ = os.RemoveAll(directory)
	}
	return 0
}

func main() { os.Exit(run()) }
