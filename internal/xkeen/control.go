package xkeen

import (
	"bytes"
	"context"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

var (
	restartMu            sync.Mutex
	restarting           bool
	OnRestartStateChange func(restarting bool)
	BeforeServiceControl func(verb string) error

	runningMu        sync.Mutex
	runningCached    bool
	runningKnown     bool
	runningCore      string
	runningCheckedAt time.Time
)

const (
	restartTimeout = 180 * time.Second
	quickTimeout   = 60 * time.Second
)

// runXkeen runs the dispatcher and captures its output.
//
// XKEEN_FOREGROUND=1 disables the fork's self-detach: without a TTY (which is
// always our case) `xkeen -start|-stop|-restart` re-execs itself through
// start-stop-daemon -b and returns immediately, so Wait() would report success
// while the restart is still running.
//
// Output goes to a temp file rather than a pipe because the proxy core inherits
// our descriptors — with a pipe Wait() blocks until the core exits.
func runXkeen(dispatcher string, timeout time.Duration, args ...string) (string, error) {
	if dispatcher == "" {
		return "", fmt.Errorf("путь к xkeen не задан")
	}
	controlled := len(args) > 0 && (args[0] == "-restart" || args[0] == "-stop" || args[0] == "-start")
	if controlled && BeforeServiceControl != nil {
		if err := BeforeServiceControl(args[0]); err != nil {
			return "", err
		}
	}

	out, err := os.CreateTemp("", "xkeen-out-*")
	if err != nil {
		return "", fmt.Errorf("не удалось создать временный файл: %w", err)
	}
	defer os.Remove(out.Name())
	defer out.Close()

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, dispatcher, args...)
	cmd.Env = append(os.Environ(), "XKEEN_FOREGROUND=1")
	cmd.Stdout = out
	cmd.Stderr = out
	cmd.SysProcAttr = detachedProcessAttrs()

	runErr := cmd.Run()
	if controlled {
		runningMu.Lock()
		runningCheckedAt = time.Time{}
		runningMu.Unlock()
	}

	body, _ := os.ReadFile(out.Name())
	text := strings.TrimSpace(string(ansiRe.ReplaceAll(body, nil)))

	if ctx.Err() == context.DeadlineExceeded {
		return text, fmt.Errorf("команда xkeen %s не завершилась за %s", strings.Join(args, " "), timeout)
	}

	if runErr == nil && controlled && BeforeServiceControl != nil {
		runErr = BeforeServiceControl(args[0])
	}
	return text, runErr
}

// Restart restarts the proxy core via `xkeen -restart`. Concurrent restarts are
// skipped, and the busy flag now spans the whole operation.
func Restart(dispatcher string) (string, error) {
	restartMu.Lock()
	if restarting {
		restartMu.Unlock()
		log.Printf("[RESTART] Пропущен — уже идёт рестарт")
		return "restart already in progress", nil
	}
	restarting = true
	restartMu.Unlock()

	if OnRestartStateChange != nil {
		OnRestartStateChange(true)
	}

	log.Printf("[RESTART] Запуск: %s -restart", dispatcher)

	go func() {
		output, err := runXkeen(dispatcher, restartTimeout, "-restart")

		restartMu.Lock()
		restarting = false
		restartMu.Unlock()

		if OnRestartStateChange != nil {
			OnRestartStateChange(false)
		}

		if err != nil {
			log.Printf("[RESTART] Ошибка: %v (%s)", err, output)
		} else {
			log.Printf("[RESTART] Завершён успешно")
		}
	}()

	return "restart initiated", nil
}

// RestartAndWait reports the dispatcher's actual result to transactional callers.
func RestartAndWait(dispatcher string) (string, error) {
	restartMu.Lock()
	if restarting {
		restartMu.Unlock()
		return "", fmt.Errorf("перезапуск ядра уже выполняется")
	}
	restarting = true
	restartMu.Unlock()
	if OnRestartStateChange != nil {
		OnRestartStateChange(true)
	}
	defer func() {
		restartMu.Lock()
		restarting = false
		restartMu.Unlock()
		if OnRestartStateChange != nil {
			OnRestartStateChange(false)
		}
	}()
	return runXkeen(dispatcher, restartTimeout, "-restart")
}

// Start starts the proxy core. The `on` argument mirrors what `xkeen -start`
// passes to the init script, so autostart state is not consulted.
func Start(dispatcher string) (string, error) {
	return runXkeen(dispatcher, restartTimeout, "-start")
}

// SetAutostart makes XKeen start the proxy on boot, or stop doing so.
func SetAutostart(dispatcher string, on bool) (string, error) {
	state := "off"
	if on {
		state = "on"
	}
	return runXkeen(dispatcher, quickTimeout, "-auto", state)
}

// Stop stops the proxy core.
func Stop(dispatcher string) (string, error) {
	return runXkeen(dispatcher, quickTimeout, "-stop")
}

// Status returns the human-readable output of `xkeen -status`.
func Status(dispatcher string) (string, error) {
	return runXkeen(dispatcher, quickTimeout, "-status")
}

// TestConfig validates the config of the active core: `-xtest` runs
// `xray -format=json -test`, `-mtest` does the same for Mihomo. Both propagate
// the core's exit code, so a non-nil error means the config is broken.
func TestConfig(dispatcher, core string) (string, error) {
	flag := "-xtest"
	if core == CoreMihomo {
		flag = "-mtest"
	}
	return runXkeen(dispatcher, quickTimeout, flag)
}

// IsRestarting reports whether a restart is in flight.
func IsRestarting() bool {
	restartMu.Lock()
	defer restartMu.Unlock()
	return restarting
}

// IsRunning reports whether the proxy core process is alive. Cached for 2s —
// polling /proc on every SSE push is expensive on a router.
func IsRunning(core string) bool {
	running, _ := CoreProcessStatus(core)
	return running
}

// CoreProcessStatus distinguishes an unobservable process table from a
// completed scan that found no proxy. A missed read must not mean "stopped".
func CoreProcessStatus(core string) (running, known bool) {
	if core == "" {
		core = CoreXray
	}

	runningMu.Lock()
	defer runningMu.Unlock()

	if core == runningCore && time.Since(runningCheckedAt) < 2*time.Second {
		return runningCached, runningKnown
	}

	runningCached, runningKnown = coreProcessStatus("/proc", "/opt/var/run", core)
	runningCore = core
	runningCheckedAt = time.Now()

	return runningCached, runningKnown
}

func coreProcessStatus(proc, run, core string) (running, known bool) {
	if pid, ok := readPIDFile(filepath.Join(run, core+".pid")); ok {
		if match, _ := corePID(proc, strconv.Itoa(pid), core); match {
			return true, true
		}
	}

	entries, err := os.ReadDir(proc)
	if err != nil {
		return false, false
	}

	known = true
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		if _, err := strconv.Atoi(e.Name()); err != nil {
			continue
		}
		match, err := corePID(proc, e.Name(), core)
		if match {
			return true, true
		}
		if err != nil && !os.IsNotExist(err) {
			known = false
		}
	}

	return false, known
}

func readPIDFile(path string) (int, bool) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, false
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil || pid <= 0 {
		return 0, false
	}
	return pid, true
}

func corePID(proc, pid, core string) (bool, error) {
	data, err := os.ReadFile(filepath.Join(proc, pid, "cmdline"))
	if err != nil {
		return false, err
	}
	exe, args, _ := bytes.Cut(data, []byte{0})
	if filepath.Base(string(exe)) != core {
		return false, nil
	}
	if core == CoreXray {
		// Xray also runs isolated workers and temporary tests for Mihomo.
		for _, helper := range []string{"/xkeen-panel-cards/", "/xkeen-panel-service-workers/", "/.node-probes-", "/xkeen-panel-sitecheck-"} {
			if bytes.Contains(args, []byte(helper)) {
				return false, nil
			}
		}
	}
	return true, nil
}
