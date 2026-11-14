package components

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"xkeen-panel/internal/xkeen"
)

func mihomoSettingsManager(t *testing.T) (*Manager, xkeen.Runtime) {
	t.Helper()
	m, rt := testManager(t)
	rt.Core = xkeen.CoreMihomo
	rt.CoreBin = m.path("/opt/sbin/mihomo")
	rt.MihomoConf = m.path("/opt/etc/mihomo/config.yaml")
	m.opts.Runtime = func() xkeen.Runtime { return rt }
	m.opts.Validate = func(context.Context, string) error {
		t.Error("a Mihomo setting invoked Xray validation")
		return nil
	}
	m.opts.Restart = func(context.Context) error {
		t.Error("a local setting interrupted the VPN core")
		return nil
	}
	writeTest(t, rt.CoreBin, []byte("synthetic Mihomo"))
	writeTest(t, rt.MihomoConf, []byte("mode: rule\n"))
	writeTest(t, m.path("/proc/sys/net/ipv6/conf/all/disable_ipv6"), []byte("0\n"))
	return m, rt
}

func previewSetting(t *testing.T, m *Manager, id string, enabled bool) Plan {
	t.Helper()
	plan, err := m.Preview(context.Background(), PlanRequest{Component: "settings", Setting: id, Enabled: &enabled})
	if err != nil {
		t.Fatal(err)
	}
	return plan
}

func readSettingFile(t *testing.T, path string) string {
	t.Helper()
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(body)
}

func TestMihomoCommonSettingsCapabilities(t *testing.T) {
	m, _ := mihomoSettingsManager(t)
	m.opts.Restart = nil // A running Xray and its restart callback are optional here.
	writeTest(t, m.path("/opt/var/spool/cron/crontabs/root"), []byte("0 4 * * * /opt/sbin/xkeen -ug\n"))
	state := m.State()
	if state.Supported || !state.SettingsSupported {
		t.Fatal("common settings and component upgrades must report independent capabilities")
	}
	for _, id := range []string{"autostart", "verbose", "backup", "ipv6", "native_geodata_schedule"} {
		s, ok := m.setting(id)
		if !ok || !s.Supported || strings.TrimSpace(s.Hint) == "" {
			t.Errorf("%s missing or unavailable: %+v", id, s)
		}
	}
	on := true
	for _, req := range []PlanRequest{
		{Component: "settings", Setting: "dns", Enabled: &on},
		{Component: "settings", Setting: "router_proxy", Enabled: &on},
		{Component: "settings", Setting: "native_geodata_schedule", Enabled: &on},
		{Component: "geodata"}, {Component: "xkeen", Version: "2.1"}, {Component: "xray", Version: "v25.1.1"},
	} {
		if _, err := m.Preview(context.Background(), req); err == nil {
			t.Errorf("unsupported preview accepted: %+v", req)
		}
	}
}

func TestMihomoSettingApplyUndoAndRecoveryKeepVPN(t *testing.T) {
	for _, tc := range []struct {
		id, assignment, updated string
		desired                 bool
	}{
		{"autostart", "start_auto=\"on\"", "start_auto=\"off\"", false},
		{"backup", "backup=\"on\"", "backup=\"off\"", false},
		{"verbose", "extended_msg=\"off\"", "extended_msg=\"on\"", true},
		{"ipv6", "ipv6_support=\"on\"", "ipv6_support=\"off\"", false},
	} {
		t.Run(tc.id, func(t *testing.T) {
			m, rt := mihomoSettingsManager(t)
			initial := "#!/bin/sh\n# keep this comment\n" + tc.assignment + "\nother_flag=\"on\"\n"
			writeTest(t, rt.InitScript, []byte(initial))
			info, err := os.Stat(rt.InitScript)
			if err != nil {
				t.Fatal(err)
			}
			plan := previewSetting(t, m, tc.id, tc.desired)
			if plan.Change == nil || plan.Change.Current == tc.desired || plan.Change.Desired != tc.desired {
				t.Fatalf("incorrect preview: %+v", plan.Change)
			}
			if _, err = m.Apply(plan.ID); err != nil {
				t.Fatal(err)
			}
			job := waitJob(t, m)
			if job.Error != "" || job.BackupID == "" {
				t.Fatalf("apply: %+v", job)
			}
			backup, err := m.readBackup(job.BackupID)
			if err != nil || backup.Setting != tc.id || len(backup.Entries) != 1 || backup.Entries[0].Path != rt.InitScript || len(backup.Kernel) > 0 {
				t.Fatalf("setting backup exceeded its scope or could not be read: %v", err)
			}
			if got := readSettingFile(t, rt.InitScript); got != strings.Replace(initial, tc.assignment, tc.updated, 1) {
				t.Fatalf("unrelated init content changed: %q", got)
			}
			newInfo, err := os.Stat(rt.InitScript)
			if err != nil || newInfo.Mode().Perm() != info.Mode().Perm() {
				t.Fatal("init permissions changed")
			}
			if _, err = m.Apply(plan.ID); err == nil {
				t.Fatal("the same plan was applied twice")
			}
			// A newly selected service route and a fresh subscription must survive undo.
			config := "mode: rule\nrules: [MATCH,Example]\n"
			writeTest(t, rt.MihomoConf, []byte(config))
			subscription := filepath.Join(m.opts.DataDir, "subscription.json")
			writeTest(t, subscription, []byte(`{"generation":2}`))
			if _, err = m.Rollback(job.BackupID); err != nil {
				t.Fatal(err)
			}
			undo := waitJob(t, m)
			if undo.Error != "" || !undo.RolledBack || readSettingFile(t, rt.InitScript) != initial {
				t.Fatalf("undo: %+v", undo)
			}
			if readSettingFile(t, rt.MihomoConf) != config || readSettingFile(t, subscription) != `{"generation":2}` {
				t.Fatal("undo overwrote newer network state")
			}
			if got := readSettingFile(t, m.path("/proc/sys/net/ipv6/conf/all/disable_ipv6")); got != "0\n" {
				t.Fatal("a saved boot preference affected live IPv6")
			}
			if tc.id == "autostart" {
				// Simulate process loss after writing one setting but before acceptance.
				writeTest(t, rt.InitScript, []byte(strings.Replace(initial, tc.assignment, tc.updated, 1)))
				if err = m.writePending(pendingOperation{BackupID: job.BackupID, Job: job, WasRunning: true}); err != nil {
					t.Fatal(err)
				}
				reopened := New(m.opts)
				reopened.Recover(context.Background())
				if got := waitJob(t, reopened); !got.RolledBack || readSettingFile(t, rt.InitScript) != initial {
					t.Fatalf("interrupted operation not recovered: %+v", got)
				}
			}
		})
	}
}

func TestMihomoScheduleRemovesOnlyNativeJobs(t *testing.T) {
	m, _ := mihomoSettingsManager(t)
	path := m.path("/opt/var/spool/cron/crontabs/root")
	others := "# disabled: /opt/sbin/xkeen -ug\n0 7 * * * logger 'xkeen -ug'\n0 9 * * * /opt/bin/update-database\n\n"
	native := "0 4 * * * /opt/sbin/xkeen -ug\n"
	writeTest(t, path, []byte(others+native))
	plan := previewSetting(t, m, "native_geodata_schedule", false)
	if _, err := m.Apply(plan.ID); err != nil {
		t.Fatal(err)
	}
	job := waitJob(t, m)
	if job.Error != "" || readSettingFile(t, path) != others {
		t.Fatalf("native schedule disable: %+v; %q", job, readSettingFile(t, path))
	}
	if _, err := m.Rollback(job.BackupID); err != nil {
		t.Fatal(err)
	}
	if job = waitJob(t, m); job.Error != "" || readSettingFile(t, path) != others+native {
		t.Fatalf("native schedule undo: %+v", job)
	}
}

func TestMihomoStaleSettingPreviewAndRollbackPreserveEdits(t *testing.T) {
	m, rt := mihomoSettingsManager(t)
	initial := readSettingFile(t, rt.InitScript)
	plan := previewSetting(t, m, "autostart", false)
	edited := initial + "# operator edited the service file after preview\n"
	writeTest(t, rt.InitScript, []byte(edited))
	if _, err := m.Apply(plan.ID); err == nil {
		if job := waitJob(t, m); job.Error == "" {
			t.Fatal("stale preview applied")
		}
	}
	if got := readSettingFile(t, rt.InitScript); got != edited {
		t.Fatal("stale preview overwrote newer state")
	}

	plan = previewSetting(t, m, "autostart", false)
	if _, err := m.Apply(plan.ID); err != nil {
		t.Fatal(err)
	}
	job := waitJob(t, m)
	if job.Error != "" {
		t.Fatalf("retry: %+v", job)
	}
	after := readSettingFile(t, rt.InitScript) + "# operator edited the service file after apply\n"
	writeTest(t, rt.InitScript, []byte(after))
	if _, err := m.Rollback(job.BackupID); err == nil {
		if rolled := waitJob(t, m); rolled.Error == "" {
			t.Fatal("stale rollback succeeded")
		}
	}
	if readSettingFile(t, rt.InitScript) != after {
		t.Fatal("stale rollback overwrote newer state")
	}
}

func TestMihomoDoesNotApplyAPlanOrBackupFromXray(t *testing.T) {
	m, rt := testManager(t)
	backup, err := m.captureBackup("settings", "legacy Xray setting")
	if err != nil {
		t.Fatal(err)
	}
	if err := m.markBackupCurrent(backup.ID); err != nil {
		t.Fatal(err)
	}
	plan := previewSetting(t, m, "autostart", false)
	rt.Core = xkeen.CoreMihomo
	m.opts.Runtime = func() xkeen.Runtime { return rt }
	m.opts.Restart = func(context.Context) error {
		t.Error("stale Xray operation restarted Mihomo")
		return nil
	}
	before := readSettingFile(t, rt.InitScript)
	if _, err := m.Apply(plan.ID); err == nil {
		if job := waitJob(t, m); job.Error == "" {
			t.Fatal("Xray preview applied after changing core")
		}
	}
	if _, err := m.Rollback(backup.ID); err == nil {
		if job := waitJob(t, m); job.Error == "" {
			t.Fatal("Xray snapshot restored over Mihomo")
		}
	}
	if readSettingFile(t, rt.InitScript) != before {
		t.Fatal("stale Xray operations changed the service")
	}
}

func TestXrayGeodataKeepsNativeScheduleConflictWithRedirect(t *testing.T) {
	m, _ := testManager(t)
	writeTest(t, m.path("/opt/var/spool/cron/crontabs/root"), []byte("0 4 * * * /opt/sbin/xkeen -ug >/dev/null 2>&1\n"))
	schedule := GeoSettings{Sources: []string{"geoip-v2fly"}, Auto: true, Day: -1}
	if err := m.SetGeodata(schedule); err == nil {
		t.Fatal("enabled a second automatic geodata writer on Xray")
	}
}
