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

// ProbeLoadError marks a node that answers the router's check but does not
// deliver the first 32 KB of a page.
const ProbeLoadError = "Сервер отвечает, но не загружает страницы"

// routerProbeTimeout is how long the router's Xray check waits for an answer.
const routerProbeTimeout = 5 * time.Second

// probeLikeRouter sends the request of the router's own Xray check: a GET of
// defaultProbeURL on a fresh connection, timed to the answer, 5 s at most. A
// provider's mode is measured this way, through its own core.
func probeLikeRouter(ctx context.Context, client *http.Client) int {
	attempt, cancel := context.WithTimeout(ctx, routerProbeTimeout)
	defer cancel()
	request, err := http.NewRequestWithContext(attempt, http.MethodGet, defaultProbeURL, nil)
	if err != nil {
		return -1
	}
	start := time.Now()
	response, err := client.Do(request)
	if err != nil {
		return -1
	}
	response.Body.Close()
	return max(int(time.Since(start)/time.Millisecond), 1)
}

// awaitObservations waits for the first round of the core's own check, in
// which every subject is probed at once, and returns its results by tag.
func awaitObservations(ctx context.Context, socket string, tags []string) map[string]memberObservation {
	deadline := time.Now().Add(3*routerProbeTimeout + time.Second)
	var seen map[string]memberObservation
	for time.Now().Before(deadline) && ctx.Err() == nil {
		seen = readPoolObservations(ctx, socket)
		done := seen != nil
		for _, tag := range tags {
			if seen[tag].LastTryTime == 0 {
				done = false
				break
			}
		}
		if done {
			break
		}
		select {
		case <-ctx.Done():
		case <-time.After(250 * time.Millisecond):
		}
	}
	return seen
}

// probeDownload tells whether a page loads through a node: a node counts as
// working only once the first 32 KB arrived within the attempt. It returns the
// time to the first byte; stalled reports a response that started and never
// completed. The number shown for a server is not this one, but the router's
// check (see ping.go).
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

// CheckServersHTTPS measures every node the way the router's pool workers do:
// a temporary Xray process runs the same check (its observatory) over all of
// them at once, then a page is loaded through each node that answered. The
// process is always reaped.
func CheckServersHTTPS(rt Runtime, servers []models.Server, options ProbeOptions) ([]models.Server, error) {
	parent := options.Context
	if parent == nil {
		parent = context.Background()
	}
	// One check at a time: the owner's and the panel's own never overlap.
	select {
	case httpsProbeGate <- struct{}{}:
	case <-parent.Done():
		return nil, fmt.Errorf("проверка отменена")
	}
	defer func() { <-httpsProbeGate }()
	checked := append([]models.Server(nil), servers...)
	var ordinary []models.Server
	var indexes []int
	for i, server := range servers {
		if len(server.RawProfile) == 0 {
			ordinary = append(ordinary, server)
			indexes = append(indexes, i)
		}
	}
	// A complete profile needs a core of its own and up to 20 s per file. They
	// used to wait for each other and for all single servers; now they run
	// alongside, a few at a time.
	var wg sync.WaitGroup
	cancelled := false
	var mu sync.Mutex
	slots := make(chan struct{}, profileProbeConcurrency)
	for i, server := range servers {
		if len(server.RawProfile) == 0 {
			continue
		}
		wg.Add(1)
		go func(i int, server models.Server) {
			defer wg.Done()
			select {
			case slots <- struct{}{}:
			case <-parent.Done():
				mu.Lock()
				cancelled = true
				mu.Unlock()
				return
			}
			defer func() { <-slots }()
			profileOptions := options
			if profileOptions.Timeout < 20*time.Second {
				profileOptions.Timeout = 20 * time.Second
			}
			result, err := checkServersHTTPSBatch(rt, []models.Server{server}, profileOptions)
			if err != nil {
				if parent.Err() != nil {
					mu.Lock()
					cancelled = true
					mu.Unlock()
					return
				}
				checked[i].Latency = -1
				checked[i].ProbeKind = "https"
				checked[i].LastChecked = time.Now()
				checked[i].CheckError = "Профиль не принят ядром или не прошёл HTTPS-проверку"
				options.report(checked[i])
				return
			}
			checked[i] = result[0]
		}(i, server)
	}
	var nodesErr error
	chunk := probeChunk()
	for start := 0; start < len(ordinary) && nodesErr == nil; start += chunk {
		end := min(start+chunk, len(ordinary))
		var result []models.Server
		result, nodesErr = probeIndependentNodes(rt, ordinary[start:end], nodeProbeOptions(options), checkServersHTTPSBatch)
		for i, server := range result {
			checked[indexes[start+i]] = server
		}
	}
	wg.Wait()
	if nodesErr != nil {
		return nil, nodesErr
	}
	if cancelled {
		return nil, fmt.Errorf("проверка отменена")
	}
	return checked, nil
}

// Complete profiles checked at once, each by a core of its own.
const profileProbeConcurrency = 3

const observedPrefix = "probe-obs-"

func observedTag(i int) string { return observedPrefix + strconv.Itoa(i) + "-" }

// probeChunk is how many single servers one temporary core checks at once.
// The router's check opens a connection through every one of them at the same
// moment; a router short of memory gets them in parts.
func probeChunk() int {
	const all, part = MaxMultiPoolMembers, 32
	data, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return all
	}
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 3 && fields[0] == "MemAvailable:" {
			if kb, err := strconv.Atoi(fields[1]); err == nil && kb < 256*1024 {
				return part
			}
			break
		}
	}
	return all
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
		checked[i].CheckError, checked[i].LoadError = "", ""
		checked[i].LastChecked = time.Now()
		// A single server is a subject of the core's own check; a provider's
		// mode routes by its own rules and is measured through its inbound.
		tag := observedTag(i)
		if len(server.RawProfile) > 0 {
			tag = "probe-node-" + strconv.Itoa(i)
		}
		out, buildErr := BuildServerOutbound(server, tag, map[string]interface{}{
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
		inbound := "probe-in-" + strconv.Itoa(i)
		inbounds = append(inbounds, map[string]interface{}{"listen": "127.0.0.1", "port": port, "protocol": "http", "tag": inbound, "settings": map[string]interface{}{}})
		outbounds = append(outbounds, out)
		rules = append(rules, map[string]interface{}{"type": "field", "inboundTag": []string{inbound}, "outboundTag": out["tag"]})
	}
	if len(outbounds) == 0 {
		return checked, nil
	}
	config := map[string]interface{}{"log": map[string]interface{}{"loglevel": "error"}, "inbounds": inbounds, "outbounds": outbounds, "routing": map[string]interface{}{"rules": rules}}
	// The router's own check, configured as in the pool workers: every subject
	// at once, as soon as the core starts. Its results come over a private
	// socket in the check's directory.
	var socket string
	var observed []string
	if profileBundle == nil {
		if path := filepath.Join(dir, "obs.sock"); len(path) <= 102 {
			for i := range servers {
				if ports[i] != 0 {
					observed = append(observed, observedTag(i))
				}
			}
			socket = path
			config["observatory"] = map[string]interface{}{
				"subjectSelector": []interface{}{observedPrefix}, "probeURL": defaultProbeURL,
				"probeInterval": "1h", "enableConcurrency": true,
			}
			addPoolMetrics(config, socket)
		}
	}
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
	client := func(localPort int) (*http.Client, func()) {
		proxy, _ := url.Parse("http://" + net.JoinHostPort("127.0.0.1", strconv.Itoa(localPort)))
		// No Accept-Encoding: the byte range must be the same size on the wire.
		transport := &http.Transport{Proxy: http.ProxyURL(proxy), DisableKeepAlives: true, DisableCompression: true, TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}}
		return &http.Client{Transport: transport, CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}, transport.CloseIdleConnections
	}
	finish := func(index int) {
		checked[index].LastChecked = time.Now()
		options.report(checked[index])
	}
	// The number: the router's check. Single servers get it from the core's
	// observatory; a provider's mode gets the same request through its inbound.
	var wg sync.WaitGroup
	answered := make([]bool, len(ports))
	if socket != "" {
		results := awaitObservations(ctx, socket, observed)
		for i, port := range ports {
			if port == 0 {
				continue
			}
			o := results[observedTag(i)]
			if o.Alive && o.Delay > 0 && o.Delay < 600000 {
				checked[i].Latency, answered[i] = int(o.Delay), true
			}
		}
	} else {
		for i, port := range ports {
			if port == 0 {
				continue
			}
			wg.Add(1)
			go func(index, localPort int) {
				defer wg.Done()
				c, done := client(localPort)
				defer done()
				if ms := probeLikeRouter(ctx, c); ms > 0 {
					checked[index].Latency, answered[index] = ms, true
				}
			}(i, port)
		}
		wg.Wait()
	}
	// The verdict: a page must load through a server that answered. A node
	// whose link freezes after the first kilobytes, the way blocking hits a
	// VPN link, keeps its number but is marked as not loading pages.
	semaphore := make(chan struct{}, options.Concurrency)
	for i, port := range ports {
		if port == 0 {
			continue
		}
		if !answered[i] {
			checked[i].CheckError = PingNoAnswer
			finish(i)
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
			defer finish(index)
			c, done := client(localPort)
			defer done()
			if loaded, stalled := probeDownload(ctx, c, options.Timeout); loaded <= 0 {
				checked[index].LoadError = ProbeLoadError
				if stalled {
					checked[index].LoadError = ProbeStalledError
				}
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
