package cardcontroller

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"slices"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

func TestDomainPolicyPreservesMissingSettingsAndDoesNotOwnDNS(t *testing.T) {
	doc := map[string]interface{}{"mode": "rule", "dns": map[string]interface{}{"enable": false}}
	before, _ := copyDomainValue(doc, 0)
	if err := configureDomainPolicy(doc, true); err != nil {
		t.Fatal(err)
	}
	sniffer := object(doc["sniffer"])
	for _, setting := range []string{"enable", "force-dns-mapping", "parse-pure-ip"} {
		if sniffer[setting] != true {
			t.Fatalf("%s was not enabled", setting)
		}
	}
	if sniffer["override-destination"] != false || doc["log-level"] != "info" {
		t.Fatal("the safe destination/logging policy is absent")
	}
	protocols := object(sniffer["sniff"])
	for _, protocol := range []string{"HTTP", "TLS", "QUIC"} {
		want := []interface{}{443, 8443}
		if protocol == "HTTP" {
			want = []interface{}{80, 8080}
		}
		if !reflect.DeepEqual(object(protocols[protocol])["ports"], want) {
			t.Fatalf("unexpected %s ports", protocol)
		}
	}
	if !reflect.DeepEqual(doc["dns"], object(before)["dns"]) {
		t.Fatal("sniffing changed the DNS listener")
	}
	if got := domainPolicyRules(doc); !slices.Equal(got, []string{
		"AND,((NETWORK,udp),(DST-PORT,443)),XKP-card-guard-quic",
		"AND,((NETWORK,udp),(DST-PORT,8443)),XKP-card-guard-quic",
	}) {
		t.Fatalf("unexpected QUIC guards: %v", got)
	}
	if err := configureDomainPolicy(doc, false); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(doc, before) || len(domainPolicyRules(doc)) != 0 {
		t.Fatal("disable did not restore the exact missing fields")
	}
}

func TestDomainPolicyKeepsFirstSnapshotAndRestoresAfterYAML(t *testing.T) {
	const input = `mode: rule
log-level: warning
sniffer:
  enable: false
  skip-domain: ["+.openai.com", "+.anthropic.com"]
  skip-dst-address: ["104.16.0.0/13"]
  sniff:
    HTTP:
      ports: [8080, "8880-8888"]
      override-destination: true
    TLS:
      ports: [443]
dns:
  enable: false
`
	var doc, original map[string]interface{}
	if yaml.Unmarshal([]byte(input), &doc) != nil || yaml.Unmarshal([]byte(input), &original) != nil {
		t.Fatal("invalid synthetic fixture")
	}
	if err := configureDomainPolicy(doc, true); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"skip-domain", "skip-src-address", "skip-dst-address"} {
		if _, found := object(doc["sniffer"])[key]; found {
			t.Fatal("old exceptions can hide protected service names")
		}
	}
	first, _ := copyDomainValue(doc[domainPolicyKey], 0)
	object(doc["sniffer"])["skip-domain"] = []interface{}{"+.claude.ai"}
	doc["log-level"] = "debug"
	if err := configureDomainPolicy(doc, true); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(first, doc[domainPolicyKey]) {
		t.Fatal("repeat enable replaced the original snapshot")
	}
	body, err := yaml.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	if err := yaml.Unmarshal(body, &doc); err != nil {
		t.Fatal(err)
	}
	if err := configureDomainPolicy(doc, false); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(doc, original) {
		t.Fatalf("original settings changed after restore: %#v", doc)
	}
}

func TestDomainPolicyRejectsDamagedSettingsWithoutMutation(t *testing.T) {
	for _, tc := range []struct {
		name string
		doc  map[string]interface{}
	}{
		{"sniffer scalar", map[string]interface{}{"sniffer": "true"}},
		{"sniffer null", map[string]interface{}{"sniffer": nil}},
		{"sniffer wrong map", map[string]interface{}{"sniffer": map[string]string{"enable": "true"}}},
		{"toggle string", map[string]interface{}{"sniffer": map[string]interface{}{"parse-pure-ip": "true"}}},
		{"protocol scalar", map[string]interface{}{"sniffer": map[string]interface{}{"sniff": "TLS"}}},
		{"protocol value", map[string]interface{}{"sniffer": map[string]interface{}{"sniff": map[string]interface{}{"TLS": true}}}},
		{"invalid port", map[string]interface{}{"sniffer": map[string]interface{}{"sniff": map[string]interface{}{"TLS": map[string]interface{}{"ports": []interface{}{70000}}}}}},
		{"backwards ports", map[string]interface{}{"sniffer": map[string]interface{}{"sniff": map[string]interface{}{"TLS": map[string]interface{}{"ports": []interface{}{"8443-443"}}}}}},
		{"invalid exclusion", map[string]interface{}{"sniffer": map[string]interface{}{"skip-domain": []interface{}{false}}}},
		{"invalid level", map[string]interface{}{"log-level": "verbose"}},
		{"level wrong type", map[string]interface{}{"log-level": true}},
		{"metadata wrong map", map[string]interface{}{domainPolicyKey: []interface{}{true}}},
		{"metadata incomplete", map[string]interface{}{domainPolicyKey: map[string]interface{}{"version": 1, "enabled": true}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			before, err := json.Marshal(tc.doc)
			if err != nil {
				t.Fatal(err)
			}
			if err := configureDomainPolicy(tc.doc, true); err == nil {
				t.Fatal("unsafe/unsupported settings were accepted")
			}
			after, _ := json.Marshal(tc.doc)
			if string(before) != string(after) {
				t.Fatal("rejected settings were partially changed")
			}
		})
	}
}

func TestDomainPolicyRejectsForeignOrInconsistentSnapshot(t *testing.T) {
	for _, mutate := range []func(map[string]interface{}){
		func(m map[string]interface{}) { m["version"] = 2 },
		func(m map[string]interface{}) { m["foreign"] = true },
		func(m map[string]interface{}) { m["enabled"] = false },
		func(m map[string]interface{}) { m["sniffer"] = map[string]interface{}{} },
		func(m map[string]interface{}) { m["sniffer_present"] = true },
		func(m map[string]interface{}) { m["log_level"] = "warning" },
		func(m map[string]interface{}) { m["log_level_present"] = true },
	} {
		doc := map[string]interface{}{}
		if err := configureDomainPolicy(doc, true); err != nil {
			t.Fatal(err)
		}
		mutate(object(doc[domainPolicyKey]))
		if _, err := readDomainPolicy(doc); err == nil {
			t.Fatal("inconsistent ownership snapshot accepted")
		}
		if err := configureDomainPolicy(doc, false); err == nil {
			t.Fatal("damaged snapshot overwrote the current configuration")
		}
	}
}

func TestDomainPolicySnapshotIsIndependentOfCurrentMap(t *testing.T) {
	old := map[string]interface{}{"skip-domain": []interface{}{"+.example.com"}}
	doc := map[string]interface{}{"sniffer": old}
	if err := configureDomainPolicy(doc, true); err != nil {
		t.Fatal(err)
	}
	old["skip-domain"].([]interface{})[0] = "+.changed.example"
	if err := configureDomainPolicy(doc, false); err != nil {
		t.Fatal(err)
	}
	if got := object(doc["sniffer"])["skip-domain"].([]interface{})[0]; got != "+.example.com" {
		t.Fatal("original snapshot aliases the modified input")
	}
}

// A real ClientHello reaches a SOCKS inbound using only an IP destination.
// The sniffer must apply the OpenAI route from SNI, while the same destination
// with an unrelated name remains DIRECT. All listeners and packets are local.
func TestMihomoDomainPolicyKeepsTLSService(t *testing.T) {
	core := os.Getenv("MIHOMO_TEST_BINARY")
	if core == "" {
		t.Skip("set MIHOMO_TEST_BINARY for a real domain-preservation test")
	}
	var destination net.Listener
	var err error
	for _, port := range []int{443, 8443} {
		destination, err = net.Listen("tcp4", fmt.Sprintf("127.0.0.2:%d", port))
		if err == nil {
			break
		}
	}
	if err != nil {
		t.Skip("both loopback TLS ports are in use")
	}
	defer destination.Close()
	proxy, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer proxy.Close()
	reserved, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	socks := reserved.Addr().String()
	reserved.Close()
	directSeen, proxySeen := make(chan bool, 4), make(chan bool, 4)
	go func() {
		for {
			conn, err := destination.Accept()
			if err != nil {
				return
			}
			_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
			var first [1]byte
			n, _ := conn.Read(first[:])
			_ = conn.Close()
			directSeen <- n == 1
		}
	}()
	go func() {
		for {
			conn, err := proxy.Accept()
			if err != nil {
				return
			}
			_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
			req, err := http.ReadRequest(bufio.NewReader(conn))
			if err == nil && req.Method == "CONNECT" {
				_, _ = io.WriteString(conn, "HTTP/1.1 200 Connection established\r\n\r\n")
				var first [1]byte
				n, _ := conn.Read(first[:])
				proxySeen <- n == 1 && first[0] == 0x16 // TLS Handshake record.
			} else {
				proxySeen <- false
			}
			_ = conn.Close()
		}
	}()
	doc := map[string]interface{}{
		"mode": "rule", "socks-port": reserved.Addr().(*net.TCPAddr).Port, "allow-lan": false,
		"proxies": []interface{}{map[string]interface{}{
			"name": "synthetic-openai-proxy", "type": "http", "server": "127.0.0.1", "port": proxy.Addr().(*net.TCPAddr).Port,
		}},
		"proxy-groups": []interface{}{
			map[string]interface{}{"name": "ChatGPT", "type": "select", "proxies": []string{"synthetic-openai-proxy"}},
			map[string]interface{}{"name": quicGuardGroup, "type": "select", "proxies": []string{"REJECT"}},
		},
	}
	if err := configureDomainPolicy(doc, true); err != nil {
		t.Fatal(err)
	}
	doc["rules"] = append(domainPolicyRules(doc), "DOMAIN-SUFFIX,openai.com,ChatGPT", "MATCH,DIRECT")
	dir := t.TempDir()
	config, _ := yaml.Marshal(doc)
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, config, 0600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(core, "-d", dir, "-f", path)
	var coreOutput bytes.Buffer
	cmd.Stdout, cmd.Stderr = &coreOutput, &coreOutput
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		if t.Failed() {
			t.Logf("synthetic Mihomo output:\n%s", coreOutput.String())
		}
	}()
	request := func(name string) {
		t.Helper()
		var conn net.Conn
		until := time.Now().Add(5 * time.Second)
		for time.Now().Before(until) {
			conn, err = net.DialTimeout("tcp4", socks, 100*time.Millisecond)
			if err == nil {
				break
			}
			time.Sleep(20 * time.Millisecond)
		}
		if err != nil {
			t.Fatal("SOCKS listener did not start", err)
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
		_, _ = conn.Write([]byte{5, 1, 0})
		var reply [10]byte
		if _, err := io.ReadFull(conn, reply[:2]); err != nil || reply[1] != 0 {
			t.Fatal("SOCKS authentication failed", err)
		}
		port := destination.Addr().(*net.TCPAddr).Port
		_, _ = conn.Write([]byte{5, 1, 0, 1, 127, 0, 0, 2, byte(port >> 8), byte(port)})
		if _, err := io.ReadFull(conn, reply[:]); err != nil || reply[1] != 0 {
			t.Fatal("SOCKS CONNECT failed", err)
		}
		// Both synthetic destinations deliberately stop the handshake after
		// recording the selected transport. No certificate bypass is required.
		if err := tls.Client(conn, &tls.Config{ServerName: name, MinVersion: tls.VersionTLS12}).Handshake(); err != nil {
			t.Logf("synthetic TLS %s stopped: %v", name, err)
		}
	}
	// A SOCKS listener can accept handshakes while the core's routing workers
	// are still starting. Establish a positive DIRECT control before testing
	// the protected request; retry only this readiness probe, never OpenAI.
	ready := false
	until := time.Now().Add(5 * time.Second)
	for !ready && time.Now().Before(until) {
		request("control.example")
		select {
		case ready = <-directSeen:
		case <-proxySeen:
			t.Fatal("unrelated DIRECT control used the OpenAI proxy")
		case <-time.After(50 * time.Millisecond):
		}
	}
	if !ready {
		t.Fatal("DIRECT control was not reached")
	}
	request("ios.chat.openai.com")
	select {
	case ok := <-proxySeen:
		if !ok {
			t.Fatal("OpenAI route did not use the selected proxy")
		}
	case <-directSeen:
		t.Fatal("OpenAI TLS request escaped through DIRECT")
	case <-time.After(3 * time.Second):
		t.Fatal("TLS domain did not select the OpenAI route")
	}
}
