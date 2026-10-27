package components

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func installNativeGeoAlias(t *testing.T, m *Manager, id string, absolute bool) (GeoSource, string, string, string) {
	t.Helper()
	source, ok := geoSource(id)
	if !ok {
		t.Fatal("fixture source missing")
	}
	alias := m.logicalGeodataPath(source)
	target := m.nativeGeoAliases()[alias]
	writeTest(t, target, []byte("previous-native-dataset"))
	link := filepath.Base(target)
	if absolute {
		link = target
	}
	if err := os.Symlink(link, alias); err != nil {
		t.Skipf("symlink fixture unavailable: %v", err)
	}
	return source, alias, target, link
}

func TestComponentsNativeGeoAliasSnapshotUpdateAndRollback(t *testing.T) {
	for _, id := range []string{"geosite-zkeen", "geoip-zkeen"} {
		for _, absolute := range []bool{false, true} {
			t.Run(id+map[bool]string{false: "/relative", true: "/absolute"}[absolute], func(t *testing.T) {
				m, _ := testManager(t)
				source, alias, target, link := installNativeGeoAlias(t, m, id, absolute)
				for _, component := range []string{"xkeen", "settings", "geodata"} {
					if size, err := m.snapshotBytes(component); err != nil || size <= 0 {
						t.Fatalf("size %s: %d %v", component, size, err)
					}
				}
				enabled := true
				if _, err := m.Preview(context.Background(), PlanRequest{Component: "settings", Setting: "verbose", Enabled: &enabled}); err != nil {
					t.Fatal("native aliases blocked settings preview:", err)
				}
				backup, err := m.captureBackup("xkeen", "2.1")
				if err != nil {
					t.Fatal(err)
				}
				if err := m.verifyXkeenPreserved(backup); err != nil {
					t.Fatal(err)
				}
				work := t.TempDir()
				writeTest(t, filepath.Join(work, "0"), []byte("new-panel-dataset"))
				plan := Plan{Component: "geodata", Artifacts: []Artifact{{Target: source.Filename}}}
				if err := m.installPayload(context.Background(), plan, work); err != nil {
					t.Fatal(err)
				}
				if current, err := os.Readlink(alias); err != nil || current != link {
					t.Fatalf("alias was replaced: %q %v", current, err)
				}
				if body, _ := os.ReadFile(target); string(body) != "new-panel-dataset" {
					t.Fatal("panel did not update native target")
				}
				// The stock updater continues to write the same canonical file.
				if err := os.WriteFile(target, []byte("native-refresh"), 0600); err != nil {
					t.Fatal(err)
				}
				if body, _ := os.ReadFile(alias); string(body) != "native-refresh" {
					t.Fatal("native refresh lost alias association")
				}
				if err := m.restoreBackup(backup); err != nil {
					t.Fatal(err)
				}
				if body, _ := os.ReadFile(target); string(body) != "previous-native-dataset" {
					t.Fatal("rollback lost original target")
				}
				if current, err := os.Readlink(alias); err != nil || current != link {
					t.Fatalf("rollback lost alias: %q %v", current, err)
				}
			})
		}
	}
}

func TestComponentsNativeGeoAliasRejectsWrongTargetsAndChains(t *testing.T) {
	for _, kind := range []string{"outside", "wrong-basename", "traversal", "chain", "directory"} {
		t.Run(kind, func(t *testing.T) {
			m, _ := testManager(t)
			source, alias, target, _ := installNativeGeoAlias(t, m, "geosite-zkeen", false)
			if err := os.Remove(alias); err != nil {
				t.Fatal(err)
			}
			link := filepath.Base(target)
			switch kind {
			case "outside":
				link = filepath.Join(t.TempDir(), "zkeen.dat")
				writeTest(t, link, []byte("outside-unchanged"))
			case "wrong-basename":
				link = "other.dat"
			case "traversal":
				link = "../dat/zkeen.dat"
			case "chain":
				if err := os.Remove(target); err != nil {
					t.Fatal(err)
				}
				writeTest(t, target+".next", []byte("chain-unchanged"))
				if err := os.Symlink(filepath.Base(target)+".next", target); err != nil {
					t.Fatal(err)
				}
			case "directory":
				if err := os.Remove(target); err != nil {
					t.Fatal(err)
				}
				if err := os.Mkdir(target, 0700); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.Symlink(link, alias); err != nil {
				t.Fatal(err)
			}
			originalLink, err := os.Readlink(alias)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := m.snapshotBytes("settings"); err == nil {
				t.Fatal("unsafe alias passed size check")
			}
			if _, err := m.captureBackup("xkeen", "2.1"); err == nil {
				t.Fatal("unsafe alias was backed up")
			}
			if _, err := m.geodataWritePath(source); err == nil {
				t.Fatal("unsafe alias accepted for write")
			}
			if current, _ := os.Readlink(alias); current != originalLink {
				t.Fatal("rejection changed link")
			}
		})
	}
}

func TestComponentsNativeGeoAliasRollbackRejectsTamperingBeforeMutation(t *testing.T) {
	m, rt := testManager(t)
	_, alias, target, link := installNativeGeoAlias(t, m, "geosite-zkeen", false)
	backup, err := m.captureBackup("xkeen", "2.1")
	if err != nil {
		t.Fatal(err)
	}
	manifest := filepath.Join(m.backupRoot(), backup.ID, "manifest.json")
	raw, err := os.ReadFile(manifest)
	if err != nil {
		t.Fatal(err)
	}
	var doc backupDocument
	if err = json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	for i := range doc.Entries {
		if doc.Entries[i].Path == alias {
			doc.Entries[i].Link = "../../outside.dat"
		}
	}
	altered, _ := json.Marshal(doc)
	if err = os.WriteFile(manifest, altered, 0600); err != nil {
		t.Fatal(err)
	}
	writeTest(t, rt.RoutingFile, []byte("keep-current-config"))
	writeTest(t, target, []byte("keep-current-geodata"))
	if err = m.restoreBackup(backup); err == nil {
		t.Fatal("tampered link accepted")
	}
	if body, _ := os.ReadFile(rt.RoutingFile); string(body) != "keep-current-config" {
		t.Fatal("failed restore modified config")
	}
	if body, _ := os.ReadFile(target); string(body) != "keep-current-geodata" {
		t.Fatal("failed restore modified geodata")
	}
	if current, _ := os.Readlink(alias); current != link {
		t.Fatal("failed restore modified alias")
	}
}

func TestComponentsNativeGeoAliasRegistrationPreservesLinkRepresentation(t *testing.T) {
	m, _ := testManager(t)
	_, alias, target, _ := installNativeGeoAlias(t, m, "geoip-zkeen", false)
	backup, err := m.captureBackup("xkeen", "2.1")
	if err != nil {
		t.Fatal(err)
	}
	if err = os.Remove(alias); err != nil {
		t.Fatal(err)
	}
	if err = os.Symlink(target, alias); err != nil {
		t.Fatal(err)
	}
	if err = m.verifyXkeenPreserved(backup); err == nil {
		t.Fatal("registration changed alias unnoticed")
	}
	if err = m.restoreBackup(backup); err != nil {
		t.Fatal(err)
	}
	if current, _ := os.Readlink(alias); current != filepath.Base(target) {
		t.Fatal("rollback failed to restore original link")
	}
}

func TestComponentsNativeGeoAliasFailedJobRollsBackCanonicalData(t *testing.T) {
	m, _ := testManager(t)
	_, alias, target, link := installNativeGeoAlias(t, m, "geosite-zkeen", false)
	body := []byte("verified-new-native-dataset")
	var address string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/payload" {
			_, _ = w.Write(body)
			return
		}
		_ = json.NewEncoder(w).Encode(githubRelease{Version: "test-release", Assets: []Asset{{Name: "zkeen.dat", Size: int64(len(body)), Digest: digestOf(body), URL: address + "/payload"}}})
	}))
	defer server.Close()
	address = server.URL
	m.apiBase = address
	if err := m.SetGeodata(GeoSettings{Sources: []string{"geosite-zkeen"}, Day: -1}); err != nil {
		t.Fatal(err)
	}
	restarts := 0
	m.opts.Restart = func(context.Context) error {
		restarts++
		if restarts == 1 {
			return fmt.Errorf("fixture HTTPS refusal")
		}
		return nil
	}
	plan, err := m.Preview(context.Background(), PlanRequest{Component: "geodata"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = m.Apply(plan.ID); err != nil {
		t.Fatal(err)
	}
	job := waitJob(t, m)
	if !job.RolledBack || job.Error == "" {
		t.Fatalf("expected rolled-back failure: %+v", job)
	}
	if current, _ := os.Readlink(alias); current != link {
		t.Fatal("failed transaction replaced native alias")
	}
	if current, _ := os.ReadFile(target); string(current) != "previous-native-dataset" {
		t.Fatal("failed transaction lost native dataset")
	}
}

func TestComponentsNativeGeoAliasRestoresOriginalAbsence(t *testing.T) {
	m, _ := testManager(t)
	_, alias, target, _ := installNativeGeoAlias(t, m, "geosite-zkeen", false)
	if err := os.Remove(alias); err != nil {
		t.Fatal(err)
	}
	backup, err := m.captureBackup("xkeen", "2.1")
	if err != nil {
		t.Fatal(err)
	}
	if err = os.Symlink(filepath.Base(target), alias); err != nil {
		t.Fatal(err)
	}
	if err = m.restoreBackup(backup); err != nil {
		t.Fatal(err)
	}
	if _, err = os.Lstat(alias); !os.IsNotExist(err) {
		t.Fatal("rollback left newly created alias")
	}
	if body, _ := os.ReadFile(target); string(body) != "previous-native-dataset" {
		t.Fatal("rollback lost canonical file")
	}
}

func TestComponentsNativeGeoAliasMissingTargetCanBeDownloadedAndReverted(t *testing.T) {
	m, _ := testManager(t)
	source, alias, target, link := installNativeGeoAlias(t, m, "geosite-zkeen", false)
	if err := os.Remove(target); err != nil {
		t.Fatal(err)
	}
	backup, err := m.captureBackup("geodata", "test-release")
	if err != nil {
		t.Fatal(err)
	}
	work := t.TempDir()
	writeTest(t, filepath.Join(work, "0"), []byte("downloaded"))
	if err = m.installPayload(context.Background(), Plan{Component: "geodata", Artifacts: []Artifact{{Target: source.Filename}}}, work); err != nil {
		t.Fatal(err)
	}
	if err = m.restoreBackup(backup); err != nil {
		t.Fatal(err)
	}
	if _, err = os.Lstat(target); !os.IsNotExist(err) {
		t.Fatal("rollback left downloaded target that was absent")
	}
	if current, _ := os.Readlink(alias); current != link {
		t.Fatal("rollback lost originally dangling alias")
	}
}
