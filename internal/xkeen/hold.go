package xkeen

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"sync"
	"time"
)

// A traffic hold pauses everything the router forwards to the internet. The
// panel raises it for a restart under a kill switch: while the core is down
// nothing may leave directly. The home network itself keeps working.

const holdChain = "XKP_HOLD"

// On tmpfs: a reboot clears the hold together with the firewall.
var holdMarker = "/tmp/xkeen-panel-hold"

// Destinations a hold leaves alone: home networks and multicast.
var holdFamilies = []struct {
	tool  string
	local []string
}{
	{"iptables", []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16", "224.0.0.0/4"}},
	{"ip6tables", []string{"fc00::/7", "fe80::/10", "ff00::/8"}},
}

var (
	// Tests replace both.
	holdExec = func(stdin, name string, args ...string) (string, error) {
		cmd := exec.Command(name, args...)
		cmd.Stdin = strings.NewReader(stdin)
		out, err := cmd.CombinedOutput()
		return string(out), err
	}
	holdHasTool = func(name string) bool { _, err := exec.LookPath(name); return err == nil }

	holdInterval = 250 * time.Millisecond

	// holdOps keeps the keeper and a release from interleaving firewall edits.
	holdOps   sync.Mutex
	holdState struct {
		sync.Mutex
		wanted, keeping bool
	}

	// HoldReleasable reports that no kill switch needs the hold any more. A
	// hold left by a failed restart is dropped then.
	HoldReleasable func() bool

	// The Claude filter's own rules stay above the hold.
	guardRule = regexp.MustCompile(`^-A FORWARD -d \S+ -j DROP$`)
)

const holdJump = "-A FORWARD -j " + holdChain

// holdPlan reads `<tool> -t filter -S` and returns the restore batch that
// raises the hold, or ready when the table already holds.
func holdPlan(local []string, snapshot string) (batch string, ready bool) {
	want := make([]string, 0, len(local)+1)
	for _, prefix := range local {
		want = append(want, "-A "+holdChain+" -d "+prefix+" -j RETURN")
	}
	want = append(want, "-A "+holdChain+" -j DROP")

	var have []string
	lead, jumps, leading, first := 0, 0, true, -1
	for _, line := range strings.Split(snapshot, "\n") {
		line = strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(line, "-A "+holdChain+" "):
			have = append(have, line)
		case line == holdJump:
			if jumps++; first < 0 && leading {
				first = lead
			}
		case strings.HasPrefix(line, "-A FORWARD "):
			if leading && guardRule.MatchString(line) {
				lead++
			} else {
				leading = false
			}
		}
	}
	// Ready: the chain is exact and its jump sits right below the filter rules.
	if jumps == 1 && first == lead && strings.Join(have, "\n") == strings.Join(want, "\n") {
		return "", true
	}
	lines := append([]string{"*filter", ":" + holdChain + " - [0:0]"}, want...)
	for ; jumps > 0; jumps-- {
		lines = append(lines, "-D FORWARD -j "+holdChain)
	}
	lines = append(lines, fmt.Sprintf("-I FORWARD %d -j %s", lead+1, holdChain), "COMMIT")
	return strings.Join(lines, "\n") + "\n", false
}

// engageHold raises the hold in both address families and confirms it.
func engageHold() error {
	for _, family := range holdFamilies {
		if !holdHasTool(family.tool) {
			if family.tool == "iptables" {
				return errors.New("на роутере нет iptables")
			}
			continue
		}
		ready := false
		var last error
		// The firewall lock may be busy for a moment: a failed edit is retried.
		for attempt := 0; attempt < 5 && !ready; attempt++ {
			snapshot, err := holdExec("", family.tool, "-t", "filter", "-S")
			if err != nil {
				last = fmt.Errorf("%s: %v", family.tool, err)
				time.Sleep(100 * time.Millisecond)
				continue
			}
			var batch string
			if batch, ready = holdPlan(family.local, snapshot); !ready {
				if out, err := holdExec(batch, family.tool+"-restore", "--noflush"); err != nil {
					last = fmt.Errorf("%s-restore: %v %s", family.tool, err, strings.TrimSpace(out))
					time.Sleep(100 * time.Millisecond)
				}
			}
		}
		if !ready {
			if last == nil {
				last = fmt.Errorf("%s: правило не закрепилось", family.tool)
			}
			return last
		}
	}
	return nil
}

// releaseHold removes every trace of the hold.
func releaseHold() error {
	var failed error
	for _, family := range holdFamilies {
		if !holdHasTool(family.tool) {
			continue
		}
		clean := false
		for attempt := 0; attempt < 5 && !clean; attempt++ {
			snapshot, err := holdExec("", family.tool, "-t", "filter", "-S")
			if err != nil {
				time.Sleep(100 * time.Millisecond)
				continue
			}
			if !strings.Contains(snapshot, holdChain) {
				clean = true
				break
			}
			for n := strings.Count(snapshot, holdJump); n > 0; n-- {
				holdExec("", family.tool, "-D", "FORWARD", "-j", holdChain)
			}
			holdExec("", family.tool, "-F", holdChain)
			holdExec("", family.tool, "-X", holdChain)
		}
		if !clean {
			failed = fmt.Errorf("%s: не удалось снять приостановку", family.tool)
		}
	}
	return failed
}

// TrafficHeld reports that the panel is pausing the internet for devices.
func TrafficHeld() bool {
	holdState.Lock()
	defer holdState.Unlock()
	return holdState.wanted
}

func raiseHold() error {
	holdOps.Lock()
	defer holdOps.Unlock()
	if err := engageHold(); err != nil {
		releaseHold()
		return err
	}
	os.WriteFile(holdMarker, nil, 0o600)
	holdState.Lock()
	holdState.wanted = true
	start := !holdState.keeping
	holdState.keeping = true
	holdState.Unlock()
	if start {
		go keepHold()
	}
	return nil
}

func lowerHold() error {
	holdState.Lock()
	holdState.wanted = false
	holdState.Unlock()
	holdOps.Lock()
	defer holdOps.Unlock()
	os.Remove(holdMarker)
	return releaseHold()
}

// keepHold puts the hold back if the firmware rewrites the firewall, and drops
// a hold nobody needs any more.
func keepHold() {
	for tick := 1; ; tick++ {
		time.Sleep(holdInterval)
		holdOps.Lock()
		holdState.Lock()
		wanted := holdState.wanted
		if !wanted {
			holdState.keeping = false
		}
		holdState.Unlock()
		if !wanted {
			releaseHold()
			holdOps.Unlock()
			return
		}
		if err := engageHold(); err != nil && Log != nil {
			Log("Приостановка интернета не подтверждена: %v", err)
		}
		holdOps.Unlock()
		if tick%20 == 0 && !IsRestarting() && HoldReleasable != nil && HoldReleasable() {
			if Log != nil {
				Log("Kill switch выключен: приостановка интернета снята")
			}
			lowerHold()
		}
	}
}

// ResumeHold restores a hold that a panel restart interrupted: the core may
// still be down.
func ResumeHold() {
	if _, err := os.Stat(holdMarker); err == nil {
		if err := raiseHold(); err != nil && Log != nil {
			Log("Приостановка интернета не восстановлена: %v", err)
		}
	}
}
