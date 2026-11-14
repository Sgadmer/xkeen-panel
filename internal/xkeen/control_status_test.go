package xkeen

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCoreProcessStatus(t *testing.T) {
	dir := t.TempDir()
	proc, run := filepath.Join(dir, "proc"), filepath.Join(dir, "run")
	check := func(core string, alive, known bool) {
		t.Helper()
		a, k := coreProcessStatus(proc, run, core)
		if alive != a || known != k {
			t.Fatalf("%s process status = %t,%t; want %t,%t", core, a, k, alive, known)
		}
	}
	put := func(p, data string) {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(p), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
	}
	check(CoreMihomo, false, false)
	put(filepath.Join(proc, "20", "cmdline"), "/bin/sh\x00/opt/sbin/mihomo\x00")
	put(filepath.Join(run, "mihomo.pid"), "20")
	check(CoreMihomo, false, true)
	put(filepath.Join(proc, "21", "cmdline"), "/opt/sbin/mihomo\x00-f\x00/opt/etc/xkeen-panel/config.yaml\x00")
	check(CoreMihomo, true, true)
	put(filepath.Join(proc, "22", "cmdline"), "/opt/sbin/xray\x00-c\x00/opt/etc/xkeen-panel-cards/a/config.json\x00")
	check(CoreXray, false, true)
	put(filepath.Join(proc, "23", "cmdline"), "/opt/sbin/xray\x00run\x00")
	check(CoreXray, true, true)
}
