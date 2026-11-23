package main

import (
	"log"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"strconv"
	"syscall"
	"time"
)

// The panel runs as a child of a small supervisor, so a crash does not leave
// the router without its panel until the next reboot. The init scripts start,
// stop and recognise the supervisor exactly as they did the panel itself.
const (
	supervisedEnv = "XKEEN_PANEL_SUPERVISED"
	// The child stopped so that the updated binary can take its place.
	exitNewVersion = 75
	// A child that ran this long counts as healthy again.
	healthyRun = 10 * time.Minute
)

var restartDelays = []time.Duration{5 * time.Second, 15 * time.Second, 30 * time.Second, time.Minute, 2 * time.Minute, 5 * time.Minute}

var (
	// This process was started by the supervisor.
	underSupervisor bool
	// How many times in a row the supervisor started the panel again.
	restartsBefore int
)

// takeSupervision reads the supervisor's mark and removes it, so programs the
// panel starts, such as the update guard that may start the panel through its
// init script, do not pass it on to a panel that has no supervisor.
func takeSupervision() {
	value, ok := os.LookupEnv(supervisedEnv)
	if !ok {
		return
	}
	os.Unsetenv(supervisedEnv)
	underSupervisor = true
	restartsBefore, _ = strconv.Atoi(value)
}

// restartDelay grows with repeated failures, so a panel that can not start
// does not fill the log.
func restartDelay(failures int) time.Duration {
	return restartDelays[min(max(failures, 1), len(restartDelays))-1]
}

// nextFailures counts a failure, forgetting earlier ones after a healthy run.
func nextFailures(failures int, ranFor time.Duration) int {
	if ranFor >= healthyRun {
		failures = 0
	}
	return failures + 1
}

func supervise(binPath string) int {
	// The child's death signal follows the thread that started it.
	runtime.LockOSThread()
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM)
	failures := 0
	for {
		started := time.Now()
		cmd := exec.Command(binPath, os.Args[1:]...)
		cmd.Args[0] = os.Args[0]
		cmd.Env = append(os.Environ(), supervisedEnv+"="+strconv.Itoa(failures))
		cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
		cmd.SysProcAttr = childProcAttrs()
		if err := cmd.Start(); err != nil {
			log.Printf("Панель не запустилась: %v", err)
			return 1
		}
		done := make(chan int, 1)
		go func() {
			cmd.Wait()
			done <- cmd.ProcessState.ExitCode()
		}()
		var code int
		select {
		case sig := <-signals:
			cmd.Process.Signal(sig)
			<-done
			return 0
		case code = <-done:
		}
		switch code {
		case 0:
			return 0
		case exitNewVersion:
			// Same PID and name, so the init script keeps recognising the process
			err := syscall.Exec(binPath, os.Args, os.Environ())
			log.Printf("Не удалось запустить новую версию: %v", err)
			return 1
		}
		failures = nextFailures(failures, time.Since(started))
		wait := restartDelay(failures)
		log.Printf("Панель завершилась с ошибкой (код %d) — запускаю снова через %s", code, wait)
		select {
		case <-signals:
			return 0
		case <-time.After(wait):
		}
	}
}
