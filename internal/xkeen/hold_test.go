package xkeen

import (
	"errors"
	"fmt"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeFirewall keeps one filter table per tool, enough for the hold's edits.
type fakeFirewall struct {
	sync.Mutex
	forward map[string][]string
	chain   map[string][]string
	exists  map[string]bool
	wiped   int // rewrites still to simulate before a snapshot
}

func newFakeFirewall() *fakeFirewall {
	return &fakeFirewall{
		forward: map[string][]string{
			"iptables":  {"-A FORWARD -d 160.79.104.0/23 -j DROP", "-A FORWARD -d 153.61.224.0/22 -j DROP", "-A FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT"},
			"ip6tables": {"-A FORWARD -d 2607:6bc0::/48 -j DROP", "-A FORWARD -j ACCEPT"},
		},
		chain:  map[string][]string{},
		exists: map[string]bool{},
	}
}

func (f *fakeFirewall) remove(tool, rule string) {
	for i, have := range f.forward[tool] {
		if have == rule {
			f.forward[tool] = append(append([]string{}, f.forward[tool][:i]...), f.forward[tool][i+1:]...)
			return
		}
	}
}

func (f *fakeFirewall) edit(tool string, args []string) error {
	switch {
	case len(args) == 4 && args[0] == "-D" && args[1] == "FORWARD":
		f.remove(tool, holdJump)
	case len(args) == 5 && args[0] == "-I" && args[1] == "FORWARD":
		at, err := strconv.Atoi(args[2])
		if err != nil || at < 1 || at > len(f.forward[tool])+1 {
			return fmt.Errorf("bad position %q", args[2])
		}
		rules := append([]string{}, f.forward[tool][:at-1]...)
		f.forward[tool] = append(append(rules, holdJump), f.forward[tool][at-1:]...)
	case len(args) == 2 && args[0] == "-F":
		f.chain[tool] = nil
	case len(args) == 2 && args[0] == "-X":
		f.exists[tool] = false
	case len(args) > 2 && args[0] == "-A" && args[1] == holdChain:
		f.chain[tool] = append(f.chain[tool], strings.Join(args, " "))
	default:
		return fmt.Errorf("unexpected edit %v", args)
	}
	return nil
}

func (f *fakeFirewall) exec(stdin, name string, args ...string) (string, error) {
	f.Lock()
	defer f.Unlock()
	if tool, restore := strings.CutSuffix(name, "-restore"); restore {
		for _, line := range strings.Split(strings.TrimSpace(stdin), "\n") {
			switch {
			case line == "*filter" || line == "COMMIT":
			case line == ":"+holdChain+" - [0:0]":
				f.exists[tool], f.chain[tool] = true, nil
			default:
				if err := f.edit(tool, strings.Fields(line)); err != nil {
					return "", err
				}
			}
		}
		return "", nil
	}
	if len(args) == 3 && args[2] == "-S" {
		if f.wiped > 0 {
			// The firmware rewrote the table: the hold is gone.
			f.wiped--
			f.remove(name, holdJump)
			f.exists[name], f.chain[name] = false, nil
		}
		lines := []string{"-P FORWARD ACCEPT"}
		if f.exists[name] {
			lines = append(lines, "-N "+holdChain)
		}
		lines = append(append(lines, f.forward[name]...), f.chain[name]...)
		return strings.Join(lines, "\n") + "\n", nil
	}
	return "", f.edit(name, args)
}

// held reports that both tables drop forwarded traffic right below the filter.
func (f *fakeFirewall) held() bool {
	f.Lock()
	defer f.Unlock()
	for tool, at := range map[string]int{"iptables": 2, "ip6tables": 1} {
		rules := f.chain[tool]
		if len(f.forward[tool]) <= at || f.forward[tool][at] != holdJump || len(rules) == 0 || rules[len(rules)-1] != "-A "+holdChain+" -j DROP" {
			return false
		}
	}
	return true
}

func (f *fakeFirewall) clean() bool {
	f.Lock()
	defer f.Unlock()
	for _, tool := range []string{"iptables", "ip6tables"} {
		if f.exists[tool] || len(f.chain[tool]) > 0 || strings.Contains(strings.Join(f.forward[tool], "\n"), holdChain) {
			return false
		}
	}
	return true
}

func useFakeFirewall(t *testing.T) *fakeFirewall {
	t.Helper()
	fw := newFakeFirewall()
	oldExec, oldTool, oldMarker, oldInterval, oldDispatch, oldStatus, oldReleasable := holdExec, holdHasTool, holdMarker, holdInterval, dispatch, coreStatus, HoldReleasable
	holdExec, holdHasTool = fw.exec, func(string) bool { return true }
	holdMarker, holdInterval, HoldReleasable = filepath.Join(t.TempDir(), "hold"), time.Millisecond, nil
	t.Cleanup(func() {
		lowerHold()
		// Let the keeper see the release before the fakes go away.
		for deadline := time.Now().Add(time.Second); time.Now().Before(deadline); time.Sleep(time.Millisecond) {
			holdState.Lock()
			keeping := holdState.keeping
			holdState.Unlock()
			if !keeping {
				break
			}
		}
		holdExec, holdHasTool, holdMarker, holdInterval, dispatch, coreStatus, HoldReleasable = oldExec, oldTool, oldMarker, oldInterval, oldDispatch, oldStatus, oldReleasable
	})
	return fw
}

func TestHoldSitsRightBelowTheClaudeFilter(t *testing.T) {
	snapshot := "-P FORWARD ACCEPT\n-A FORWARD -d 160.79.104.0/23 -j DROP\n-A FORWARD -j ACCEPT\n"
	batch, ready := holdPlan([]string{"10.0.0.0/8"}, snapshot)
	if ready || !strings.Contains(batch, "-I FORWARD 2 -j XKP_HOLD\n") || !strings.Contains(batch, "-A XKP_HOLD -d 10.0.0.0/8 -j RETURN\n-A XKP_HOLD -j DROP\n") {
		t.Fatalf("unexpected plan ready=%t:\n%s", ready, batch)
	}
	// A jump below an ACCEPT lets traffic through: it is moved up.
	low := snapshot + "-A FORWARD -j XKP_HOLD\n-A XKP_HOLD -d 10.0.0.0/8 -j RETURN\n-A XKP_HOLD -j DROP\n"
	if batch, ready = holdPlan([]string{"10.0.0.0/8"}, low); ready || !strings.Contains(batch, "-D FORWARD -j XKP_HOLD\n-I FORWARD 2 -j XKP_HOLD\n") {
		t.Fatalf("a jump below ACCEPT was accepted, ready=%t:\n%s", ready, batch)
	}
	held := "-A FORWARD -d 160.79.104.0/23 -j DROP\n-A FORWARD -j XKP_HOLD\n-A FORWARD -j ACCEPT\n-A XKP_HOLD -d 10.0.0.0/8 -j RETURN\n-A XKP_HOLD -j DROP\n"
	if _, ready = holdPlan([]string{"10.0.0.0/8"}, held); !ready {
		t.Fatal("a correct hold was not recognised")
	}
}

func TestHeldRestartPausesTheInternetOnlyWhileTheCoreIsDown(t *testing.T) {
	fw := useFakeFirewall(t)
	coreStatus = func(string) (bool, bool) { return true, true }
	dispatch = func(_ string, _ time.Duration, args ...string) (string, error) {
		if len(args) != 1 || args[0] != "-restart" {
			t.Errorf("unexpected dispatcher call %v", args)
		}
		if !fw.held() || !TrafficHeld() {
			t.Error("the core was restarted without a hold")
		}
		// The firmware rewrites the table mid-restart: the keeper restores the hold.
		fw.Lock()
		fw.wiped = 1
		fw.Unlock()
		for deadline := time.Now().Add(time.Second); !fw.held() && time.Now().Before(deadline); {
			time.Sleep(time.Millisecond)
		}
		if !fw.held() {
			t.Error("the hold did not come back after a firewall rewrite")
		}
		return "ok", nil
	}
	if _, err := RestartHeld("xkeen", CoreMihomo); err != nil {
		t.Fatal(err)
	}
	if TrafficHeld() || !fw.clean() {
		t.Fatal("the hold outlived a successful restart")
	}
}

func TestFailedHeldRestartKeepsTheInternetPaused(t *testing.T) {
	fw := useFakeFirewall(t)
	coreStatus = func(string) (bool, bool) { return false, true }
	dispatch = func(string, time.Duration, ...string) (string, error) { return "", nil }
	_, err := RestartHeld("xkeen", CoreMihomo)
	if err == nil || !strings.Contains(err.Error(), "приостановлен") {
		t.Fatalf("a core that did not start was reported as %v", err)
	}
	if !TrafficHeld() || !fw.held() {
		t.Fatal("traffic was released although the core is down")
	}

	// The next start brings interception back and ends the hold.
	old := BeforeServiceControl
	BeforeServiceControl = nil
	defer func() { BeforeServiceControl = old }()
	if _, err := Start("xkeen"); err != nil {
		t.Fatal(err)
	}
	if TrafficHeld() || !fw.clean() {
		t.Fatal("the hold outlived a successful start")
	}
}

func TestHoldEndsWhenNoKillSwitchNeedsIt(t *testing.T) {
	fw := useFakeFirewall(t)
	dispatch = func(string, time.Duration, ...string) (string, error) { return "", errors.New("exit status 1") }
	if _, err := RestartHeld("xkeen", CoreMihomo); err == nil {
		t.Fatal("a failed dispatcher was reported as success")
	}
	if !fw.held() {
		t.Fatal("traffic was released although the restart failed")
	}
	HoldReleasable = func() bool { return true }
	for deadline := time.Now().Add(2 * time.Second); TrafficHeld() && time.Now().Before(deadline); {
		time.Sleep(time.Millisecond)
	}
	if TrafficHeld() || !fw.clean() {
		t.Fatal("the hold stayed after every kill switch was turned off")
	}
}

func TestRestartIsRefusedWhenTheHoldCanNotBeRaised(t *testing.T) {
	useFakeFirewall(t)
	holdExec = func(string, string, ...string) (string, error) { return "", errors.New("locked") }
	dispatch = func(string, time.Duration, ...string) (string, error) {
		t.Error("the core was restarted without a hold")
		return "", nil
	}
	if _, err := RestartHeld("xkeen", CoreMihomo); err == nil || TrafficHeld() {
		t.Fatalf("restart without a hold: err=%v held=%t", err, TrafficHeld())
	}
}
