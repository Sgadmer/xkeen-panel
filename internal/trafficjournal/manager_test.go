package trafficjournal

import (
	"context"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"xkeen-panel/internal/trafficlog"
)

func managerFixture(t *testing.T) (*Manager, Volume, *atomic.Bool) {
	t.Helper()
	root := t.TempDir()
	data := filepath.Join(root, "settings")
	disk := filepath.Join(root, "external")
	for _, path := range []string{data, disk} {
		if err := os.Mkdir(path, 0700); err != nil {
			t.Fatal(err)
		}
	}
	manager := New(context.Background(), data)
	manager.memory = func() (int64, int64) { return 1 << 30, 512 << 20 }
	available := &atomic.Bool{}
	available.Store(true)
	volume := Volume{ID: "external-fixture", Label: "External test", MountPath: disk, FreeBytes: 1 << 30, TotalBytes: 2 << 30, Available: true, SuggestedPath: filepath.Join(disk, "journal")}
	manager.volumes = func() []Volume { copy := volume; copy.Available = available.Load(); return []Volume{copy} }
	t.Cleanup(func() {
		if store := manager.store.Swap(nil); store != nil {
			_ = store.Close()
		}
	})
	return manager, volume, available
}

func TestHistoryManagerDisabledAllocatesNoArchive(t *testing.T) {
	manager, volume, _ := managerFixture(t)
	if manager.Active() || manager.Status().Enabled {
		t.Fatal("advanced history must default off")
	}
	manager.Record(trafficlog.Entry{At: time.Now(), Kind: "connection", Device: "192.0.2.10", Host: "example.com"})
	if _, err := os.Stat(volume.SuggestedPath); !os.IsNotExist(err) {
		t.Fatal("disabled history created a directory")
	}
	page, _, err := manager.Query(context.Background(), trafficlog.Query{Limit: 50})
	if err != nil || len(page.Events) != 0 {
		t.Fatal("disabled history queried or returned a database")
	}
}

func TestHistoryManagerRequiresSelectedMountedExternalStorage(t *testing.T) {
	manager, volume, available := managerFixture(t)
	enabled := true
	if _, err := manager.Apply(context.Background(), Patch{Enabled: &enabled}); err == nil {
		t.Fatal("enabled without selecting a disk")
	}
	outside := filepath.Join(filepath.Dir(volume.MountPath), "internal")
	if _, err := manager.Apply(context.Background(), Patch{Enabled: &enabled, StorageID: &volume.ID, Path: &outside}); err == nil {
		t.Fatal("accepted internal storage")
	}
	available.Store(false)
	if _, err := manager.Apply(context.Background(), Patch{Enabled: &enabled, StorageID: &volume.ID, Path: &volume.SuggestedPath}); err == nil {
		t.Fatal("accepted an unavailable disk")
	}
	if _, err := os.Stat(volume.SuggestedPath); !os.IsNotExist(err) {
		t.Fatal("unavailable storage caused fallback creation")
	}
	available.Store(true)
	manager.memory = func() (int64, int64) { return 64 << 20, 12 << 20 }
	if _, err := manager.Apply(context.Background(), Patch{Enabled: &enabled, StorageID: &volume.ID, Path: &volume.SuggestedPath}); err == nil {
		t.Fatal("opened database under memory pressure")
	}
}

func TestHistoryDestinationRejectsSymlinkEscape(t *testing.T) {
	_, volume, _ := managerFixture(t)
	outside := t.TempDir()
	link := filepath.Join(volume.MountPath, "elsewhere")
	if err := os.Symlink(outside, link); err != nil {
		t.Skip("symlinks unavailable on this test host")
	}
	if _, err := resolveDestination(volume, filepath.Join(link, "journal")); err == nil {
		t.Fatal("journal escaped the selected device through a symlink")
	}
}

func TestHistoryManagerPersistsSelectionAndStableIdentity(t *testing.T) {
	if !trafficlog.Supported() {
		t.Skip(trafficlog.SupportReason())
	}
	manager, volume, _ := managerFixture(t)
	enabled := true
	currentIP := "192.0.2.10"
	manager.SetDeviceProvider(func() []DeviceIdentity {
		return []DeviceIdentity{{IP: currentIP, MAC: "02:00:00:00:00:10", Name: "Example phone"}}
	})
	if _, err := manager.Apply(context.Background(), Patch{Enabled: &enabled, StorageID: &volume.ID, Path: &volume.SuggestedPath}); err != nil {
		t.Fatal(err)
	}
	manager.Record(trafficlog.Entry{At: time.Now(), Kind: "connection", Device: currentIP, Host: "chat.example", Network: "TCP", Route: []string{"Example VPN", "Original server"}, Exit: &trafficlog.Exit{Kind: "server", Name: "Original server", Country: "US"}})
	currentIP = "192.0.2.11"
	manager.refreshDevices()
	manager.Record(trafficlog.Entry{At: time.Now(), Kind: "connection", Device: currentIP, Host: "chat.example", Network: "TCP", Route: []string{"Example VPN", "New server"}, Exit: &trafficlog.Exit{Kind: "server", Name: "New server", Country: "DE"}})
	if err := manager.store.Load().Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	page, _, err := manager.Query(context.Background(), trafficlog.Query{Device: "mac:02:00:00:00:00:10", Limit: 50})
	if err != nil || len(page.Events) != 2 {
		t.Fatalf("stable identity lost after DHCP change: %v %d", err, len(page.Events))
	}
	if page.Events[0].Exit.Name != "New server" || page.Events[1].Exit.Name != "Original server" {
		t.Fatal("historical routes were rewritten")
	}
	wrongID := "missing-device"
	if _, err := manager.Apply(context.Background(), Patch{StorageID: &wrongID}); err == nil || !manager.Active() {
		t.Fatal("invalid setting interrupted the previous writer")
	}
	enabled = false
	if _, err := manager.Apply(context.Background(), Patch{Enabled: &enabled}); err != nil {
		t.Fatal(err)
	}
	if manager.Active() {
		t.Fatal("disabled journal kept a database open")
	}
	reloaded := New(context.Background(), filepath.Dir(manager.configPath))
	reloaded.volumes = manager.volumes
	reloaded.memory = manager.memory
	if reloaded.config.Path != volume.SuggestedPath || reloaded.config.Enabled {
		t.Fatal("saved selection/default-off state did not survive restart")
	}
	enabled = true
	if _, err := manager.Apply(context.Background(), Patch{Enabled: &enabled}); err != nil {
		t.Fatal(err)
	}
	page, _, err = manager.Query(context.Background(), trafficlog.Query{Device: "mac:02:00:00:00:00:10", Limit: 50})
	if err != nil || len(page.Events) != 2 {
		t.Fatal("saved history was erased when the journal reopened")
	}
}

func TestHistoryManagerCoalescesShortRetriesWithoutExtendingOldRows(t *testing.T) {
	if !trafficlog.Supported() {
		t.Skip(trafficlog.SupportReason())
	}
	m, volume, _ := managerFixture(t)
	enabled := true
	if _, err := m.Apply(context.Background(), Patch{Enabled: &enabled, StorageID: &volume.ID, Path: &volume.SuggestedPath}); err != nil {
		t.Fatal(err)
	}
	at := time.Now().UTC().Truncate(time.Minute).Add(2 * time.Second)
	entry := trafficlog.Entry{At: at, Kind: "quic", Device: "192.0.2.10", Host: "192.0.2.20", Port: "443", Network: "UDP", Route: []string{"Блокировка QUIC"}}
	m.Record(entry)
	entry.At = at.Add(time.Second)
	m.Record(entry)
	entry.At = at.Add(16 * time.Second)
	m.Record(entry)
	if err := m.store.Load().Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	page, _, err := m.Query(context.Background(), trafficlog.Query{Limit: 10})
	if err != nil || len(page.Events) != 2 {
		t.Fatal("retries did not produce independent short windows")
	}
	if !page.Events[1].At.Equal(at) || page.Events[1].Count != 2 || page.Events[0].Count != 1 {
		t.Fatal("retry aggregation moved an old row forward or lost its count")
	}
}
