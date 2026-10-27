package xkeen

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

const manualSourceURI = "vless://11111111-2222-3333-4444-555555555555@server.example:443?type=tcp&security=tls#Private%20Server"

func TestManualSourceImportPersistsWithoutRemoteRefresh(t *testing.T) {
	dir := t.TempDir()
	sm := NewSubscriptionManager(dir)
	servers, err := sm.ImportContent(manualSourceURI, "server")
	if err != nil || len(servers) != 1 {
		t.Fatalf("manual import failed: %v", err)
	}
	if sm.CanRefresh() || sm.GetData().URL != "" || sm.GetData().SourceKind != "server" {
		t.Fatal("manual source became a remote subscription")
	}
	before := sm.GetData()
	if _, err := sm.Refresh(); err == nil {
		t.Fatal("manual source must not fetch a remote URL")
	}
	if !reflect.DeepEqual(before, sm.GetData()) {
		t.Fatal("refresh changed manual state")
	}
	next := NewSubscriptionManager(dir)
	if err := next.Load(); err != nil {
		t.Fatal(err)
	}
	loaded := next.GetData()
	if next.CanRefresh() || loaded.URL != "" || loaded.SourceKind != before.SourceKind || !loaded.LastUpdated.Equal(before.LastUpdated) || !reflect.DeepEqual(loaded.Servers, before.Servers) {
		t.Fatal("manual source did not survive reload")
	}
	raw, err := os.ReadFile(filepath.Join(dir, "subscription.json"))
	if err != nil || !strings.Contains(string(raw), "source_kind") {
		t.Fatal("local source state missing")
	}
}

func TestInvalidManualSourceDoesNotReplaceWorkingCredentials(t *testing.T) {
	sm := NewSubscriptionManager(t.TempDir())
	if _, err := sm.ImportContent(manualSourceURI, "file"); err != nil {
		t.Fatal(err)
	}
	before := sm.GetData()
	for _, tc := range []struct{ body, kind string }{{"https://do-not-fetch.example/private", "server"}, {"invalid confidential text", "file"}, {manualSourceURI, "unknown"}, {strings.Repeat("x", (4<<20)+1), "file"}} {
		_, err := sm.ImportContent(tc.body, tc.kind)
		if err == nil {
			t.Fatal("invalid source accepted")
		}
		if strings.Contains(err.Error(), "confidential") || strings.Contains(err.Error(), "do-not-fetch") {
			t.Fatal("source content leaked in error")
		}
		if !reflect.DeepEqual(before, sm.GetData()) {
			t.Fatal("invalid source changed previous data")
		}
	}
}
