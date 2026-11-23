package main

import (
	"os"
	"testing"
	"time"
)

func TestRestartDelayGrowsAndCaps(t *testing.T) {
	want := map[int]time.Duration{0: 5 * time.Second, 1: 5 * time.Second, 2: 15 * time.Second, 4: time.Minute, 6: 5 * time.Minute, 40: 5 * time.Minute}
	for failures, delay := range want {
		if got := restartDelay(failures); got != delay {
			t.Fatalf("restartDelay(%d) = %s, want %s", failures, got, delay)
		}
	}
}

func TestSupervisionMarkIsNotInherited(t *testing.T) {
	t.Setenv(supervisedEnv, "3")
	takeSupervision()
	defer func() { underSupervisor, restartsBefore = false, 0 }()
	if !underSupervisor || restartsBefore != 3 {
		t.Fatalf("mark not read: %v %d", underSupervisor, restartsBefore)
	}
	if _, ok := os.LookupEnv(supervisedEnv); ok {
		t.Fatal("programs the panel starts would inherit the mark")
	}
}

func TestHealthyRunForgetsFailures(t *testing.T) {
	if got := nextFailures(5, time.Minute); got != 6 {
		t.Fatalf("a quick crash must count: %d", got)
	}
	if got := nextFailures(5, healthyRun); got != 1 {
		t.Fatalf("a healthy run must reset the count: %d", got)
	}
}
