package monitor

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"xkeen-panel/internal/models"
	"xkeen-panel/internal/xkeen"
)

func newWatchdog(t *testing.T, cfg *models.Config) *Watchdog {
	t.Helper()
	sub := xkeen.NewSubscriptionManager(t.TempDir())
	return NewWatchdog(cfg, sub, xkeen.NewDetector(t.TempDir(), "", "", "", "", "", ""))
}

func TestBlacklist(t *testing.T) {
	w := newWatchdog(t, &models.Config{BlacklistTTLSec: 300})

	w.blacklistServer("uriA")

	if !w.isBlacklisted("uriA") {
		t.Fatal("uriA must be blacklisted")
	}
	if w.isBlacklisted("other") {
		t.Fatal("other must not be blacklisted")
	}

	w.ClearBlacklist("uriA")
	if w.isBlacklisted("uriA") {
		t.Fatal("uriA must be cleared from the blacklist")
	}
}

func TestBlacklistExpiry(t *testing.T) {
	w := newWatchdog(t, &models.Config{BlacklistTTLSec: 300})

	w.blacklist["x"] = time.Now().Add(-time.Second)

	if w.isBlacklisted("x") {
		t.Fatal("an expired entry must not count as active")
	}

	w.mu.Lock()
	_, exists := w.blacklist["x"]
	w.mu.Unlock()
	if exists {
		t.Fatal("an expired entry must be removed from the map")
	}
}

func TestBlacklistTTLZero(t *testing.T) {
	w := newWatchdog(t, &models.Config{BlacklistTTLSec: 0})

	w.blacklistServer("uriZ")
	if w.isBlacklisted("uriZ") {
		t.Fatal("with TTL=0 blacklistServer must be a no-op")
	}
}

func TestAutomaticServerUsesSubscriptionCountry(t *testing.T) {
	w := newWatchdog(t, &models.Config{AutoSwitchAvoidCountries: []string{"RU", "BY"}})

	cases := []struct {
		name string
		s    models.Server
		want bool
	}{
		{"allowed country", models.Server{Country: "NL"}, true},
		{"avoided country", models.Server{Country: "RU"}, false},
		{"unknown country", models.Server{Address: "ru.relay.example"}, true},
		{"Somalia with a Russian relay", models.Server{Name: "🇸🇴 Обход", Address: "ru.relay.example", Country: "SO"}, true},
		{"excluded label with a foreign relay", models.Server{Address: "se.relay.example", Country: "RU"}, false},
		{"unlabelled hostname from a previous import", models.Server{Address: "ru.relay.example", Name: "ru.relay.example", Country: "RU"}, true},
		{"old text-only subscription label", models.Server{Name: "Сомали", Address: "ru.relay.example"}, true},
		{"override wins", models.Server{Country: "RU", CountryOverride: "NL"}, true},
		{"override avoided", models.Server{Country: "NL", CountryOverride: "RU"}, false},
	}
	for _, c := range cases {
		if got := w.AutomaticServerAllowed(c.s); got != c.want {
			t.Errorf("%s: isServerAllowed = %v, want %v", c.name, got, c.want)
		}
	}
}

func TestRotateLog(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "watchdog.log")

	var buf bytes.Buffer
	for i := 0; buf.Len() < 2<<20; i++ {
		fmt.Fprintf(&buf, "log line number %08d with padding text to make lines longer zzzzz\n", i)
	}
	original := append([]byte(nil), buf.Bytes()...)
	if err := os.WriteFile(path, original, 0644); err != nil {
		t.Fatal(err)
	}

	rotateLog(path, 1<<20, 256<<10)

	rotated, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if int64(len(rotated)) > 256<<10 {
		t.Fatalf("size after rotation %d > %d", len(rotated), 256<<10)
	}
	if len(rotated) == 0 || len(rotated) >= len(original) {
		t.Fatalf("unexpected size after rotation %d (original %d)", len(rotated), len(original))
	}
	if !bytes.HasSuffix(original, rotated) {
		t.Fatal("content after rotation must be a suffix of the original")
	}
	if before := original[len(original)-len(rotated)-1]; before != '\n' {
		t.Fatalf("rotation is not on a line boundary, previous byte = %q", before)
	}

	smallPath := filepath.Join(dir, "small.log")
	small := []byte("just a few bytes\nsecond line\n")
	if err := os.WriteFile(smallPath, small, 0644); err != nil {
		t.Fatal(err)
	}
	rotateLog(smallPath, 1<<20, 256<<10)
	got, err := os.ReadFile(smallPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, small) {
		t.Fatal("a small file must not change")
	}
}
