package monitor

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"xkeen-panel/internal/models"
)

func TestJournalKeepsLinesFromBeforeRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "panel.log")
	earlier := "2026-01-01 00:00:01 [SUBSCRIPTION] before the restart\n2026-01-01 00:00:02 Watchdog включён\n"
	if err := os.WriteFile(path, []byte(earlier), 0600); err != nil {
		t.Fatal(err)
	}
	w := NewWatchdog(&models.Config{LogFile: path}, nil, nil)
	file, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	w.logFile = file

	w.Log("after the restart")
	lines := w.GetLogs(200)
	if len(lines) != 3 || !strings.Contains(lines[0], "before the restart") || !strings.Contains(lines[2], "after the restart") {
		t.Fatalf("the journal lost what was written before the restart: %q", lines)
	}
	// Asking for fewer lines than memory holds does not touch the file.
	if recent := w.GetLogs(1); len(recent) != 1 || !strings.Contains(recent[0], "after the restart") {
		t.Fatalf("recent lines: %q", recent)
	}
}

func TestWorkingRouteIsReportedOnceUntilItChanges(t *testing.T) {
	w := NewWatchdog(&models.Config{}, nil, nil)
	count := func(mark string) int {
		n := 0
		for _, line := range w.GetLogs(0) {
			if strings.Contains(line, mark) {
				n++
			}
		}
		return n
	}
	for i := 0; i < 5; i++ {
		w.logHealthy("[OK] route works (%dms)", 70+i)
	}
	if count("[OK]") != 1 {
		t.Fatalf("%d lines for an unchanged working route, want 1", count("[OK]"))
	}
	w.logUnhealthy("[FAIL] route is down")
	w.logUnhealthy("[FAIL] route is down")
	if count("[FAIL]") != 2 {
		t.Fatal("a failure must be written every time")
	}
	w.logHealthy("[OK] route works again")
	if count("[OK]") != 2 {
		t.Fatal("the recovery after a failure was not written")
	}
}
