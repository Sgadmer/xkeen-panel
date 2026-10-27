package xkeen

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"fmt"
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
}

var httpsProbeGate = make(chan struct{}, 1)

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
		result, err := checkServersHTTPSBatch(rt, ordinary, options)
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
			continue
		}
		checked[i] = result[0]
	}
	return checked, nil
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
	if options.Timeout < 2*time.Second {
		options.Timeout = 8 * time.Second
	}
	if options.Timeout > 20*time.Second {
		options.Timeout = 20 * time.Second
	}
	if options.Concurrency < 1 {
		options.Concurrency = 3
	}
	if options.Concurrency > 6 {
		options.Concurrency = 6
	}
	ctx, cancel := context.WithTimeout(parent, time.Duration(len(servers)/options.Concurrency+1)*options.Timeout+20*time.Second)
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
		return nil, fmt.Errorf("нет поддерживаемых серверов для проверки")
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
		if !strings.HasPrefix(v, "XRAY_LOCATION_CONFDIR=") && !strings.HasPrefix(v,"XRAY_LOCATION_CONFIG=") {
			env = append(env, v)
		}
	}
	if os.Getenv("XRAY_LOCATION_ASSET")=="" {
		assetDir:="/opt/etc/xray/dat"
		if rt.XrayConfDir!="" { assetDir=filepath.Join(filepath.Dir(rt.XrayConfDir),"dat") }
		if info,e:=os.Stat(assetDir);e==nil&&info.IsDir() { env=append(env,"XRAY_LOCATION_ASSET="+assetDir) }
	}
	validate := exec.CommandContext(ctx, bin, "run", "-test", "-config", conf)
	validate.Env = env
	validate.Stdout = log
	validate.Stderr = log
	if err = validate.Run(); err != nil {
		if options.StateDir != "" {
			if details, readErr := os.ReadFile(filepath.Join(dir, "core.log")); readErr == nil {
				_ = os.WriteFile(filepath.Join(options.StateDir, "last-probe-error.log"), details, 0600)
			}
		}
		return nil, fmt.Errorf("Xray не принял конфигурацию подписки; рабочие настройки сохранены")
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
			nodeCtx, nodeCancel := context.WithTimeout(ctx, options.Timeout)
			defer nodeCancel()
			proxy, _ := url.Parse("http://" + net.JoinHostPort("127.0.0.1", strconv.Itoa(localPort)))
			transport := &http.Transport{Proxy: http.ProxyURL(proxy), DisableKeepAlives: true, TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}}
			defer transport.CloseIdleConnections()
			client := &http.Client{Transport: transport, Timeout: options.Timeout, CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}
			for targetIndex, target := range []string{"https://www.gstatic.com/generate_204", "https://cp.cloudflare.com/generate_204"} {
				attemptCtx := nodeCtx
				attemptCancel := func() {}
				if targetIndex == 0 {
					attemptCtx, attemptCancel = context.WithTimeout(nodeCtx, options.Timeout/2)
				}
				request, e := http.NewRequestWithContext(attemptCtx, http.MethodGet, target, nil)
				if e != nil {
					attemptCancel()
					continue
				}
				start := time.Now()
				response, e := client.Do(request)
				if e != nil {
					attemptCancel()
					continue
				}
				response.Body.Close()
				attemptCancel()
				if response.StatusCode == http.StatusNoContent {
					checked[index].Latency = int(time.Since(start) / time.Millisecond)
					if checked[index].Latency < 1 {
						checked[index].Latency = 1
					}
					break
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
