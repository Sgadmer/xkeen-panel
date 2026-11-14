package xkeen

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"xkeen-panel/internal/models"
)

var workers = struct {
	sync.Mutex
	children map[string]*os.Process
}{children: make(map[string]*os.Process)}

func serviceWorkerRoot(rt Runtime) (string, error) {
	if rt.Core != CoreXray || !filepath.IsAbs(rt.XrayConfDir) || !filepath.IsAbs(rt.CoreBin) {
		return "", fmt.Errorf("для составного профиля требуется локальный Xray")
	}
	return filepath.Join(filepath.Dir(rt.XrayConfDir), "xkeen-panel-service-workers"), nil
}

func privateWorkerDir(path string) error {
	if err := os.Mkdir(path, 0700); err != nil && !os.IsExist(err) {
		return err
	}
	st, err := os.Lstat(path)
	if err != nil || !st.IsDir() || st.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("каталог профилей недоступен")
	}
	return os.Chmod(path, 0700)
}

func serviceWorkerCredentials(dir string) (serviceWorkerKey, error) {
	path := filepath.Join(dir, "identity")
	var key serviceWorkerKey
	data, err := os.ReadFile(path)
	if err == nil {
		if json.Unmarshal(data, &key) != nil || key.Port <= 0 || key.Port > 65535 || key.User == "" {
			return key, fmt.Errorf("повреждены параметры локального профиля")
		}
		if _, err := tls.X509KeyPair([]byte(key.Cert), []byte(key.Key)); err != nil {
			return key, fmt.Errorf("повреждены ключи локального профиля")
		}
		return key, nil
	}
	if !os.IsNotExist(err) {
		return key, err
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return key, err
	}
	defer listener.Close()
	key, err = newServiceWorkerKey(listener.Addr().(*net.TCPAddr).Port)
	if err != nil {
		return key, err
	}
	data, err = json.Marshal(key)
	if err != nil {
		return key, err
	}
	return key, writeFileAtomic(path, data, 0600)
}

func workerPeerCheck(key serviceWorkerKey) error {
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM([]byte(key.Cert)) {
		return errors.New("некорректный корневой сертификат")
	}
	dialer := &net.Dialer{Timeout: 300 * time.Millisecond}
	conn, err := tls.DialWithDialer(dialer, "tcp4", key.address(), &tls.Config{RootCAs: roots, ServerName: workerHostname, MinVersion: tls.VersionTLS12, NextProtos: []string{"http/1.1"}})
	if err != nil {
		return err
	}
	conn.Close()
	return nil
}

func workerEnv(rt Runtime) []string {
	var env []string
	for _, v := range os.Environ() {
		name, _, _ := strings.Cut(v, "=")
		switch strings.ToUpper(name) {
		case "XRAY_LOCATION_CONFDIR", "XRAY_LOCATION_CONFIG", "XRAY_LOCATION_ASSET", "XRAY.LOCATION.CONFDIR", "XRAY.LOCATION.CONFIG", "XRAY.LOCATION.ASSET", "GOGC", "GOMEMLIMIT", "GOMAXPROCS":
			continue
		}
		env = append(env, v)
	}
	return append(env, "XRAY_LOCATION_ASSET="+filepath.Join(filepath.Dir(rt.XrayConfDir), "dat"),
		"GOGC=35", "GOMEMLIMIT=24MiB", "GOMAXPROCS=1")
}

// Refuse a new process before the validation run on a memory-starved router.
// A working and already authenticated worker is reusable under pressure.
func workerMemoryAvailable(data []byte) bool {
	values := make(map[string]uint64)
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) != 3 || fields[2] != "kB" {
			continue
		}
		n, err := strconv.ParseUint(fields[1], 10, 64)
		if err == nil {
			values[strings.TrimSuffix(fields[0], ":")] = n
		}
	}
	available, ok := values["MemAvailable"]
	if !ok {
		free, ok := values["MemFree"]
		if !ok {
			return false
		}
		available = free + values["Buffers"] + values["Cached"]
		if available > values["Shmem"] {
			available -= values["Shmem"]
		} else {
			return false
		}
	}
	return available >= 48*1024
}

func preferWorkerOOM(pid int) error {
	if runtime.GOOS != "linux" {
		return nil
	}
	return os.WriteFile(filepath.Join("/proc", strconv.Itoa(pid), "oom_score_adj"), []byte("950"), 0600)
}

// A separate executable name prevents XKeen's normal pidof/killall handling
// for the router's main xray process from identifying these workers as that core.
func workerBinary(rt Runtime, root string) (string, error) {
	if runtime.GOOS != "linux" {
		return rt.CoreBin, nil
	}
	path := filepath.Join(root, "xkp-svc-core")
	if err := os.Symlink(rt.CoreBin, path); err != nil && !os.IsExist(err) {
		return "", err
	}
	target, err := os.Readlink(path)
	if err != nil || target != rt.CoreBin {
		return "", fmt.Errorf("не удалось проверить бинарный файл рабочего профиля")
	}
	return path, nil
}

func workerPID(dir string) (*os.Process, bool) {
	if p := workers.children[dir]; p != nil {
		return p, true
	}
	pid, ok := readPIDFile(filepath.Join(dir, "pid"))
	if !ok || runtime.GOOS != "linux" {
		return nil, false
	}
	cmdline, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "cmdline"))
	if err != nil {
		return nil, false
	}
	root := filepath.Dir(filepath.Dir(dir))
	expected := []string{filepath.Join(root, "xkp-svc-core"), "run", "-config", filepath.Join(dir, "config.json"), ""}
	if !bytes.Equal(cmdline, []byte(strings.Join(expected, "\x00"))) {
		return nil, false
	}
	proc, err := os.FindProcess(pid)
	return proc, err == nil
}

// PrepareServiceProfile can be called on each reconciliation, including panel
// startup. An immutable generation gets its own loopback identity so a failed
// transaction cannot repoint a previously committed route.
func PrepareServiceProfile(rt Runtime, targetID string, server models.Server, tag string, template map[string]interface{}) (map[string]interface{}, error) {
	if tag == "" {
		return nil, profileError()
	}
	key, err := prepareProfileWorker(rt, targetID, server, template)
	if err != nil {
		return nil, err
	}
	return key.outbound(tag), nil
}

func prepareProfileWorker(rt Runtime, targetID string, server models.Server, template map[string]interface{}) (*serviceWorkerKey, error) {
	if !profileHashPattern.MatchString(targetID) {
		return nil, profileError()
	}
	root, err := serviceWorkerRoot(rt)
	if err != nil {
		return nil, err
	}
	profile := ProfileIdentity(server)
	if profile == "" {
		return nil, profileError()
	}
	raw, err := json.Marshal([]interface{}{"v1", profile, mapOf(mapOf(template["streamSettings"])["sockopt"])["mark"]})
	if err != nil {
		return nil, profileError()
	}
	hash := sha256.Sum256(raw)
	target := filepath.Join(root, targetID)
	dir := filepath.Join(target, hex.EncodeToString(hash[:]))
	workers.Lock()
	defer workers.Unlock()
	for _, path := range []string{root, target, dir} {
		if err := privateWorkerDir(path); err != nil {
			return nil, err
		}
	}
	key, err := serviceWorkerCredentials(dir)
	if err != nil {
		return nil, err
	}
	if _, ok := workerPID(dir); ok && workerPeerCheck(key) == nil {
		return &key, nil
	}
	if runtime.GOOS == "linux" {
		data, err := os.ReadFile("/proc/meminfo")
		if err != nil || !workerMemoryAvailable(data) {
			return nil, fmt.Errorf("для запуска дополнительного Xray недостаточно свободной памяти; текущие подключения сохранены")
		}
	}
	// Keep the old generation untouched if a different process owns the port.
	listener, err := net.Listen("tcp4", key.address())
	if err != nil {
		return nil, fmt.Errorf("не удалось проверить владельца порта локального профиля")
	}
	defer listener.Close()
	config, err := serviceWorkerConfig(server, template, key)
	if err != nil {
		return nil, err
	}
	if server.GeneratedPool {
		if socket := poolStatusSocket(filepath.Dir(rt.XrayConfDir), targetID, key.Port); socket != "" {
			if err := preparePoolStatusSocket(socket); err != nil {
				return nil, err
			}
			addPoolMetrics(config, socket)
		}
	}
	data, err := json.Marshal(config)
	if err != nil {
		return nil, profileError()
	}
	path := filepath.Join(dir, "config.json")
	if err = writeFileAtomic(path, data, 0600); err != nil {
		return nil, err
	}
	binary, err := workerBinary(rt, root)
	if err != nil {
		return nil, err
	}
	env := workerEnv(rt)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	check := exec.CommandContext(ctx, binary, "run", "-test", "-config", path)
	check.Env = env
	if err = check.Start(); err != nil {
		return nil, fmt.Errorf("не удалось запустить проверку конфигурации Xray")
	}
	if err = preferWorkerOOM(check.Process.Pid); err != nil && !os.IsNotExist(err) {
		check.Process.Kill()
		check.Wait()
		return nil, fmt.Errorf("не удалось выставить приоритет памяти проверки Xray")
	}
	if err = check.Wait(); err != nil {
		return nil, fmt.Errorf("Xray не принял конфигурацию защищённого профиля")
	}
	listener.Close()
	cmd := exec.Command(binary, "run", "-config", path)
	cmd.Env = env
	cmd.SysProcAttr = detachedProcessAttrs()
	if err = cmd.Start(); err != nil {
		return nil, fmt.Errorf("не удалось запустить защищённый профиль")
	}
	if err = preferWorkerOOM(cmd.Process.Pid); err != nil {
		cmd.Process.Kill()
		cmd.Wait()
		return nil, fmt.Errorf("не удалось выставить приоритет памяти защищённого профиля")
	}
	done := make(chan struct{})
	workers.children[dir] = cmd.Process
	go func() {
		cmd.Wait()
		close(done)
		workers.Lock()
		defer workers.Unlock()
		if workers.children[dir] == cmd.Process {
			delete(workers.children, dir)
		}
	}()
	if err = writeFileAtomic(filepath.Join(dir, "pid"), []byte(strconv.Itoa(cmd.Process.Pid)), 0600); err != nil {
		cmd.Process.Kill()
		return nil, err
	}
	deadline := time.Now().Add(8 * time.Second)
	var peerError error
	for time.Now().Before(deadline) {
		select {
		case <-done:
			return nil, fmt.Errorf("защищённый профиль завершился при запуске")
		default:
		}
		peerError = workerPeerCheck(key)
		if peerError == nil {
			return &key, nil
		}
		time.Sleep(80 * time.Millisecond)
	}
	cmd.Process.Kill()
	<-done
	delete(workers.children, dir)
	return nil, fmt.Errorf("Xray не подтвердил локальный TLS-профиль: %w", peerError)
}

// PruneServiceProfiles runs only after a successful main configuration commit.
// It also removes orphaned preparations after the next panel reconciliation.
func PruneServiceProfiles(rt Runtime, keep map[string]bool) error {
	root, err := serviceWorkerRoot(rt)
	if err != nil {
		return err
	}
	workers.Lock()
	defer workers.Unlock()
	targets, err := os.ReadDir(root)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	var failures []error
	for _, target := range targets {
		if !target.IsDir() || !profileHashPattern.MatchString(target.Name()) || keep[target.Name()] {
			continue
		}
		path := filepath.Join(root, target.Name())
		versions, e := os.ReadDir(path)
		if e != nil {
			failures = append(failures, e)
			continue
		}
		for _, version := range versions {
			if !version.IsDir() || !profileHashPattern.MatchString(version.Name()) {
				continue
			}
			dir := filepath.Join(path, version.Name())
			if proc, ok := workerPID(dir); ok {
				if err := proc.Kill(); err != nil && !errors.Is(err, os.ErrProcessDone) {
					failures = append(failures, err)
					continue
				}
			}
			if raw, err := os.ReadFile(filepath.Join(dir, "identity")); err == nil {
				var key struct{ Port int }
				if json.Unmarshal(raw, &key) == nil {
					if socket := poolStatusSocket(filepath.Dir(rt.XrayConfDir), target.Name(), key.Port); socket != "" {
						os.Remove(socket)
						os.Remove(socket + ".lock")
					}
				}
			}
			if err := os.RemoveAll(dir); err != nil {
				failures = append(failures, err)
			}
		}
		if err := os.Remove(path); err != nil {
			failures = append(failures, err)
		}
	}
	return errors.Join(failures...)
}
