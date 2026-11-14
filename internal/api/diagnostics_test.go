package api

import (
	"os"
	"path/filepath"
	"testing"
)

func TestRouterTemperatureUsesHottestReadableMillidegreeSensor(t *testing.T) {
	root := t.TempDir()
	paths := []string{filepath.Join(root, "missing")}
	for name, raw := range map[string]string{"cpu": "48300\n", "wifi": "57210", "broken": "999999", "invalid": "-"} {
		p := filepath.Join(root, name)
		if err := os.WriteFile(p, []byte(raw), 0600); err != nil {
			t.Fatal(err)
		}
		paths = append(paths, p)
	}
	if got := routerTemperature(paths); got == nil || *got != 57.21 {
		t.Fatalf("unexpected temperature: %v", got)
	}
	if routerTemperature(paths[:1]) != nil {
		t.Fatal("missing sensor rendered as a reading")
	}
}

func TestRouterLoadFromProc(t *testing.T) {
	prev := readCPU("cpu 10 2 10 100 3 1 1 0 4 1\ncpu0 10 2 10 100\n")
	curr := readCPU("cpu 20 2 20 125 8 1 1 0 8 2\ncpu0 20 2 20 125\n")
	if p := cpuPercent(prev, curr); p == nil || *p != 40 || curr.cores != 1 {
		t.Fatalf("%+v %+v %v", prev, curr, p)
	}
	if cpuPercent(curr, prev) != nil || cpuPercent(curr, curr) != nil {
		t.Fatal("invalid tick delta")
	}
	total, used := memoryUsage("MemTotal: 1000 kB\nMemAvailable: 350 kB\nMemFree: 75 kB")
	if total != 1000 || used != 650 {
		t.Fatalf("%d %d", total, used)
	}
}
