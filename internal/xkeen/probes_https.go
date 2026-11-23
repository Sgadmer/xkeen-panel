package xkeen

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"crypto/tls"
	"xkeen-panel/internal/models"
)

// ProbeOptions bounds the work done by one isolated core. No production route
// or subscription file is changed by a probe.
type ProbeOptions struct {
	Context     context.Context
	Timeout     time.Duration
	Concurrency int
	StateDir    string
	// OnResult receives each finished measurement. Workers may call it concurrently.
	OnResult func(models.Server)
}

func (o ProbeOptions) report(s models.Server) {
	if o.OnResult != nil {
		o.OnResult(s)
	}
}

var httpsProbeGate = make(chan struct{}, 1)
var errProbeConfig = errors.New("Xray отклонил конфигурацию проверки")

// ProbeStalledError marks a node that answers and then freezes once a few
// kilobytes have passed: the way blocking hits a VPN link itself. An empty
// generate_204 passes through such a node, real pages do not.
const ProbeStalledError = "Сервер отвечает, но связь замирает"

// MaxProbeConcurrency nodes are measured at once by one temporary core.
const MaxProbeConcurrency = 16

// probeTargets are unchanging files on two unrelated CDNs. Their first 32 KB
// pass the 15–20 KB point where a throttled link stalls. Google is avoided:
// its answers vary in size and it refuses many data-centre addresses.
var probeTargets = []string{
	"https://cdn.jsdelivr.net/npm/jquery@3.7.1/dist/jquery.min.js",
	"https://cdnjs.cloudflare.com/ajax/libs/jquery/3.7.1/jquery.min.js",
}

const probeBytes = 32 << 10
const probeAttempt = 5 * time.Second

// probeDownload returns the time to the first response byte, the moment
// Xray's own observatory measures too, so the numbers are comparable. A node
// counts as working only once the first 32 KB arrived within the attempt.
// stalled reports a response that started and never completed.
func probeDownload(ctx context.Context, client *http.Client, timeout time.Duration) (latency int, stalled bool) {
	for _, target := range probeTargets {
		if ctx.Err() != nil {
			return 0, false
		}
		ms, started := probeOnce(ctx, client, target, timeout)
		if ms > 0 {
			return ms, false
		}
		stalled = stalled || started
	}
	return 0, stalled
}

func probeOnce(ctx context.Context, client *http.Client, target string, timeout time.Duration) (int, bool) {
	attempt, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	request, err := http.NewRequestWithContext(attempt, http.MethodGet, target, nil)
	if err != nil {
		return 0, false
	}
	request.Header.Set("Range", "bytes=0-"+strconv.Itoa(probeBytes-1))
	start := time.Now()
	response, err := client.Do(request)
	if err != nil {
		return 0, false
	}
	defer response.Body.Close()
	first := time.Since(start)
	if response.StatusCode != http.StatusOK && response.StatusCode != http.StatusPartialContent {
		return 0, false
	}
	if n, _ := io.CopyN(io.Discard, response.Body, probeBytes); n < probeBytes {
		return 0, true
	}
	return max(int(first/time.Millisecond), 1), false
}

// CheckServersHTTPS measures each node through its own loopback HTTP inbound.
// A single temporary Xray process serves the batch and is always reaped.
func CheckServersHTTPS(rt Runtime, servers []models.Server, options ProbeOptions) ([]models.Server, error) {
	checked := append([]models.Server(nil), servers...)
	var ordinary []models.Server
	var indexes []int
	for i, server := range servers {
		if len(server.RawProfile) == 0 {
			ordinary = append(ordinary, server)
			indexes = append(indexes, i)
		}
	}
	if len(ordinary) > 0 {
		result, err := probeIndependentNodes(rt, ordinary, nodeProbeOptions(options), checkServersHTTPSBatch)
		if err != nil {
			return nil, err
		}
		for i, server := range result {
			checked[indexes[i]] = server
		}
	}
	for i, server := range servers {
		if len(server.RawProfile) == 0 {
			continue
		}
		profileOptions := options
		if profileOptions.Timeout < 20*time.Second {
			profileOptions.Timeout = 20 * time.Second
		}
		result, err := checkServersHTTPSBatch(rt, []models.Server{server}, profileOptions)
		if err != nil {
			if options.Context != nil && options.Context.Err() != nil {
				return nil, fmt.Errorf("проверка отменена")
			}
			checked[i].Latency = -1
			checked[i].ProbeKind = "https"
			checked[i].LastChecked = time.Now()
			checked[i].CheckError = "Профиль не принят ядром или не прошёл HTTPS-проверку"
			options.report(checked[i])
			continue
		}
		checked[i] = result[0]
	}
	return checked, nil
}

// nodeProbeOptions sets the pace of a check of single servers.
//
// probe_concurrency and probe_timeout_ms belong to the old TCP ping. Older
// installs wrote 3 and 8 s there, and a check of 135 servers took eight
// minutes: 55 silent ones cost 16 s each, three at a time. One core
// downloading a few KB per node is light, so the check always runs
// MaxProbeConcurrency nodes at once and gives each file probeAttempt.
func nodeProbeOptions(options ProbeOptions) ProbeOptions {
	options.Timeout, options.Concurrency = probeAttempt, MaxProbeConcurrency
	return options
}

// A provider can publish one invalid outbound alongside healthy configurations.
// Split only on validation failures. An unavailable local core fails the job.
func probeIndependentNodes(rt Runtime, nodes []models.Server, options ProbeOptions, batch func(Runtime, []models.Server, ProbeOptions) ([]models.Server, error)) ([]models.Server, error) {
	checked, err := batch(rt, nodes, options)
	if !errors.Is(err, errProbeConfig) {
		return checked, err
	}
	if len(nodes) == 1 {
		node := nodes[0]
		node.Latency, node.ProbeKind, node.LastChecked = -1, "https", time.Now()
		node.CheckError = errProbeConfig.Error()
		options.report(node)
		return []models.Server{node}, nil
	}
	middle := len(nodes) / 2
	left, err := probeIndependentNodes(rt, nodes[:middle], options, batch)
	if err != nil {
		return nil, err
	}
	right, err := probeIndependentNodes(rt, nodes[middle:], options, batch)
	if err != nil {
		return nil, err
	}
	return append(left, right...), nil
}

func checkServersHTTPSBatch(rt Runtime, servers []models.Server, options ProbeOptions) ([]models.Server, error) {
	parent := options.Context
	if parent == nil {
		parent = context.Background()
	}
	select {
	case httpsProbeGate <- struct{}{}:
	case <-parent.Done():
		return nil, fmt.Errorf("проверка отменена")
	}
	defer func() { <-httpsProbeGate }()
	if rt.Core != CoreXray || rt.CoreBin == "" {
		return nil, fmt.Errorf("HTTPS-проверка требует Xray")
	}
	// The configured timeout belongs to the TCP ping. A download through a
	// VPN node gets at least probeAttempt per file, a complete profile up to 20 s.
	options.Timeout = min(max(options.Timeout, probeAttempt), 20*time.Second)
	if options.Concurrency < 1 {
		options.Concurrency = 3
	}
	options.Concurrency = min(options.Concurrency, MaxProbeConcurrency)
	ctx, cancel := context.WithTimeout(parent, time.Duration(len(servers)/options.Concurrency+1)*options.Timeout*time.Duration(len(probeTargets))+20*time.Second)
	defer cancel()
	base := options.StateDir
	if base != "" {
		if err := os.MkdirAll(base, 0700); err != nil {
			return nil, fmt.Errorf("каталог проверок недоступен")
		}
	}
	dir, err := os.MkdirTemp(base, ".node-probes-")
	if err != nil {
		return nil, fmt.Errorf("каталог проверок недоступен")
	}
	defer os.RemoveAll(dir)
	if err = os.Chmod(dir, 0700); err != nil {
		return nil, fmt.Errorf("не удалось защитить каталог проверок")
	}
	bin := filepath.Join(dir, "xk-node-probe")
	if err := os.Symlink(rt.CoreBin, bin); err != nil {
		return nil, fmt.Errorf("не удалось подготовить проверочное ядро")
	}
	checked := append([]models.Server(nil), servers...)
	ports := make([]int, len(servers))
	var reserved []net.Listener
	defer func() {
		for _, l := range reserved {
			l.Close()
		}
	}()
	var inbounds, outbounds, rules []interface{}
	var profileBundle *ProfileBundle
	for i, server := range servers {
		checked[i].Latency = -1
		checked[i].ProbeKind = "https"
		checked[i].CheckError = ""
		checked[i].LastChecked = time.Now()
		out, buildErr := BuildServerOutbound(server, "probe-node-"+strconv.Itoa(i), map[string]interface{}{
			"streamSettings": map[string]interface{}{"sockopt": map[string]interface{}{"mark": 255}},
		})
		if buildErr != nil {
			checked[i].CheckError = "Настройки сервера не поддерживаются"
			options.report(checked[i])
			continue
		}
		if len(server.RawProfile) > 0 {
			bundle, err := BuildProfileBundle(server, out["tag"].(string), map[string]interface{}{"streamSettings": map[string]interface{}{"sockopt": map[string]interface{}{"mark": 255}}})
			if err != nil {
				return nil, err
			}
			profileBundle = &bundle
			outbounds = append(outbounds, bundle.InternalOutbounds...)
		}
		listener, listenErr := net.Listen("tcp4", "127.0.0.1:0")
		if listenErr != nil {
			return nil, fmt.Errorf("не удалось выделить локальный порт")
		}
		reserved = append(reserved, listener)
		port := listener.Addr().(*net.TCPAddr).Port
		ports[i] = port
		tag := "probe-in-" + strconv.Itoa(i)
		inbounds = append(inbounds, map[string]interface{}{"listen": "127.0.0.1", "port": port, "protocol": "http", "tag": tag, "settings": map[string]interface{}{}})
		outbounds = append(outbounds, out)
		rules = append(rules, map[string]interface{}{"type": "field", "inboundTag": []string{tag}, "outboundTag": out["tag"]})
	}
	if len(outbounds) == 0 {
		return checked, nil
	}
	config := map[string]interface{}{"log": map[string]interface{}{"loglevel": "error"}, "inbounds": inbounds, "outbounds": outbounds, "routing": map[string]interface{}{"rules": rules}}
	if profileBundle != nil {
		bundle := profileBundle
		binding, err := BindProfileRules(*bundle, []string{"probe-in-0"})
		if err != nil {
			return nil, err
		}
		config["outbounds"] = append(outbounds, binding.GuardOutbounds...)
		for key, value := range bundle.Globals {
			if value != nil {
				config[key] = value
			}
		}
		routing := mapOf(config["routing"])
		routing["rules"] = append(append(append([]interface{}{}, binding.OwnedRules...), binding.ClientRules...), rules...)
		routing["balancers"] = bundle.Balancers
		for key, value := range bundle.RoutingGlobals {
			if value != nil {
				routing[key] = value
			}
		}
		for _, raw := range inbounds {
			if len(bundle.Sniffing) > 0 {
				mapOf(raw)["sniffing"] = bundle.Sniffing
			}
		}
	}
	data, err := json.Marshal(config)
	if err != nil {
		return nil, fmt.Errorf("не удалось подготовить конфигурацию проверки")
	}
	conf := filepath.Join(dir, "probe.json")
	if err = os.WriteFile(conf, data, 0600); err != nil {
		return nil, fmt.Errorf("не удалось сохранить конфигурацию проверки")
	}
	log, err := os.OpenFile(filepath.Join(dir, "core.log"), os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, fmt.Errorf("не удалось открыть журнал проверки")
	}
	defer log.Close()
	env := make([]string, 0, len(os.Environ())+1)
	for _, v := range os.Environ() {
		if !strings.HasPrefix(v, "XRAY_LOCATION_CONFDIR=") && !strings.HasPrefix(v, "XRAY_LOCATION_CONFIG=") {
			env = append(env, v)
		}
	}
	if os.Getenv("XRAY_LOCATION_ASSET") == "" {
		assetDir := "/opt/etc/xray/dat"
		if rt.XrayConfDir != "" {
			assetDir = filepath.Join(filepath.Dir(rt.XrayConfDir), "dat")
		}
		if info, e := os.Stat(assetDir); e == nil && info.IsDir() {
			env = append(env, "XRAY_LOCATION_ASSET="+assetDir)
		}
	}
	validate := exec.CommandContext(ctx, bin, "run", "-test", "-config", conf)
	validate.Env = env
	validate.Stdout = log
	validate.Stderr = log
	if err = validate.Run(); err != nil {
		var status *exec.ExitError
		if ctx.Err() != nil || !errors.As(err, &status) || status.ExitCode() <= 0 {
			return nil, fmt.Errorf("не удалось выполнить проверочное ядро")
		}
		if options.StateDir != "" {
			if details, readErr := os.ReadFile(filepath.Join(dir, "core.log")); readErr == nil {
				_ = os.WriteFile(filepath.Join(options.StateDir, "last-probe-error.log"), details, 0600)
			}
		}
		return nil, errProbeConfig
	}
	for _, listener := range reserved {
		listener.Close()
	}
	cmd := exec.CommandContext(ctx, bin, "run", "-config", conf)
	cmd.Env = env
	cmd.Stdout = log
	cmd.Stderr = log
	if err = cmd.Start(); err != nil {
		return nil, fmt.Errorf("не удалось запустить проверочное ядро")
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	defer func() {
		cmd.Process.Kill()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
		}
	}()
	ready := false
	deadline := time.Now().Add(8 * time.Second)
	for time.Now().Before(deadline) {
		all := true
		for _, port := range ports {
			if port == 0 {
				continue
			}
			conn, e := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), 100*time.Millisecond)
			if e != nil {
				all = false
				break
			}
			conn.Close()
		}
		if all {
			ready = true
			break
		}
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("проверка отменена")
		case <-time.After(80 * time.Millisecond):
		}
	}
	if !ready {
		return nil, fmt.Errorf("проверочное ядро не готово; рабочее подключение сохранено")
	}
	roots, _ := x509.SystemCertPool()
	if roots == nil {
		roots = x509.NewCertPool()
	}
	if ca, e := os.ReadFile("/opt/etc/ssl/certs/ca-certificates.crt"); e == nil {
		roots.AppendCertsFromPEM(ca)
	}
	semaphore := make(chan struct{}, options.Concurrency)
	var wg sync.WaitGroup
	for i, port := range ports {
		if port == 0 {
			continue
		}
		wg.Add(1)
		go func(index, localPort int) {
			defer wg.Done()
			select {
			case semaphore <- struct{}{}:
			case <-ctx.Done():
				return
			}
			defer func() { <-semaphore }()
			defer func() {
				checked[index].LastChecked = time.Now()
				options.report(checked[index])
			}()
			proxy, _ := url.Parse("http://" + net.JoinHostPort("127.0.0.1", strconv.Itoa(localPort)))
			// No Accept-Encoding: the byte range must be the same size on the wire.
			transport := &http.Transport{Proxy: http.ProxyURL(proxy), DisableKeepAlives: true, DisableCompression: true, TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}}
			defer transport.CloseIdleConnections()
			client := &http.Client{Transport: transport, CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}
			latency, stalled := probeDownload(ctx, client, options.Timeout)
			if latency > 0 {
				checked[index].Latency = latency
			} else if stalled {
				checked[index].CheckError = ProbeStalledError
			}
		}(i, port)
	}
	wg.Wait()
	if profileBundle != nil && len(checked) > 0 && checked[0].Latency < 0 && options.StateDir != "" {
		if details, readErr := os.ReadFile(filepath.Join(dir, "core.log")); readErr == nil {
			_ = os.WriteFile(filepath.Join(options.StateDir, "last-profile-probe.log"), details, 0600)
		}
	}
	if ctx.Err() != nil {
		return nil, fmt.Errorf("проверка отменена; рабочие настройки сохранены")
	}
	return checked, nil
}
