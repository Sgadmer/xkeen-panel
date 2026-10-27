package xkeen

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"testing"
)

func profileApplyDocument(t *testing.T, path string) map[string]interface{} {
	t.Helper()
	var document map[string]interface{}
	if err := ReadJSONC(path, &document); err != nil {
		t.Fatal(err)
	}
	return document
}

func profileApplyWrite(t *testing.T, path string, document map[string]interface{}) {
	t.Helper()
	raw, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
}

func profileApplyBaseline(t *testing.T) (Runtime, string, string, map[string]interface{}) {
	t.Helper()
	rt, path := pooledConfDir(t)
	routing := profileApplyDocument(t, rt.RoutingFile)
	routing["dns"] = map[string]interface{}{"servers": []interface{}{"9.9.9.9"}, "tag": "router-dns"}
	routing["policy"] = map[string]interface{}{"system": map[string]interface{}{"statsOutboundUplink": true}}
	profileApplyWrite(t, rt.RoutingFile, routing)
	inboundPath := filepath.Join(rt.XrayConfDir, "03_inbounds.json")
	profileApplyWrite(t, inboundPath, map[string]interface{}{"inbounds": []interface{}{
		map[string]interface{}{"tag": "redirect", "protocol": "dokodemo-door", "port": 12345, "sniffing": map[string]interface{}{"enabled": false, "routeOnly": false}},
		map[string]interface{}{"tag": "tproxy", "protocol": "dokodemo-door", "port": 12346},
	}})
	return rt, path, inboundPath, profileApplyDocument(t, rt.RoutingFile)
}

func TestProfileApplyOrdinaryRestoresDNSObserversAndSniffing(t *testing.T) {
	rt, path, inboundPath, baseline := profileApplyBaseline(t)
	beforeInbound := profileApplyDocument(t, inboundPath)
	profile := profileServer(t, profileFixture())
	if err := SetManualOutbound(rt, path, profile); err != nil {
		t.Fatal(err)
	}
	applied := profileApplyDocument(t, rt.RoutingFile)
	if applied["burstObservatory"] == nil || applied["observatory"] != nil || reflect.DeepEqual(applied["dns"], baseline["dns"]) {
		t.Fatal("profile did not install its own global policy")
	}
	if err := SetManualOutbound(rt, path, poolServers()[0]); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(profileApplyDocument(t, rt.RoutingFile), baseline) {
		t.Fatal("profile to ordinary selection did not restore the exact DNS/observer/routing policy")
	}
	if !reflect.DeepEqual(profileApplyDocument(t, inboundPath), beforeInbound) {
		t.Fatal("profile to ordinary selection did not restore existing and absent sniffing values")
	}
	if HasActiveProfile(path) {
		t.Fatal("ordinary selection left an active profile marker")
	}
	for _, tag := range outboundTags(t, path) {
		if IsProfileInternalTag(tag) {
			t.Fatal("ordinary selection retained internal profile outbounds")
		}
	}
}

func TestProfileApplyReapplyKeepsOriginalBaseline(t *testing.T) {
	rt, path, inboundPath, baseline := profileApplyBaseline(t)
	beforeInbound := profileApplyDocument(t, inboundPath)
	profile := profileServer(t, profileFixture())
	for count := 0; count < 3; count++ {
		if err := SetManualOutbound(rt, path, profile); err != nil {
			t.Fatal(err)
		}
	}
	if got := NodeKeyForTag(path, DefaultPoolSelector, ManualTag); got != NodeKeyOfServer(profile) {
		t.Fatal("same-profile identity cannot use the watchdog no-restart path")
	}
	if err := SetManualOutbound(rt, path, poolServers()[1]); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(profileApplyDocument(t, rt.RoutingFile), baseline) || !reflect.DeepEqual(profileApplyDocument(t, inboundPath), beforeInbound) {
		t.Fatal("reapply captured the active profile as the router baseline")
	}
}

func TestProfileApplyCombinedOutboundsRoutingDocument(t *testing.T) {
	rt, path, _, _ := profileApplyBaseline(t)
	combined := profileApplyDocument(t, path)
	for key, value := range profileApplyDocument(t, rt.RoutingFile) {
		combined[key] = value
	}
	profileApplyWrite(t, path, combined)
	if err := os.Remove(rt.RoutingFile); err != nil {
		t.Fatal(err)
	}
	rt.RoutingFile = path
	if err := SetManualOutbound(rt, path, profileServer(t, profileFixture())); err != nil {
		t.Fatal(err)
	}
	applied := profileApplyDocument(t, path)
	if applied["burstObservatory"] == nil {
		t.Fatal("combined config lost profile global policy when its outbound list was written")
	}
	owned := false
	for _, raw := range asSlice(mapOf(applied["routing"])["rules"]) {
		for _, tag := range stringList(mapOf(raw)["inboundTag"]) {
			if len(tag) > len(profileInboundPrefix) && tag[:len(profileInboundPrefix)] == profileInboundPrefix {
				owned = true
			}
		}
	}
	if !owned {
		t.Fatal("combined config lost scoped provider routes")
	}
}

func TestProfileApplyRemovesShadowingGlobalsInOtherFragments(t *testing.T) {
	rt, path, _, _ := profileApplyBaseline(t)
	foreign := filepath.Join(rt.XrayConfDir, "99_globals.json")
	original := map[string]interface{}{"dns": map[string]interface{}{"servers": []interface{}{"192.0.2.53"}}, "observatory": map[string]interface{}{"subjectSelector": []interface{}{"sub-"}, "probeInterval": "1m"}, "policy": nil}
	profileApplyWrite(t, foreign, original)
	if err := SetManualOutbound(rt, path, profileServer(t, profileFixture())); err != nil {
		t.Fatal(err)
	}
	active := profileApplyDocument(t, foreign)
	if active["dns"] != nil || active["observatory"] != nil {
		t.Fatal("a later config fragment still overrides the provider DNS/observer policy")
	}
	if err := SetManualOutbound(rt, path, poolServers()[0]); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(profileApplyDocument(t, foreign), original) {
		t.Fatal("ordinary selection did not restore fragment globals")
	}
}

func TestProfileApplyPoolRefreshPreservesProviderObserverInterval(t *testing.T) {
	rt, path, _, _ := profileApplyBaseline(t)
	fixture := profileFixture()
	delete(fixture, "burstObservatory")
	fixture["observatory"] = map[string]interface{}{"subjectSelector": []interface{}{"node-"}, "probeInterval": "7m", "probeURL": "https://example.invalid/generate_204"}
	if err := SetManualOutbound(rt, path, profileServer(t, fixture)); err != nil {
		t.Fatal(err)
	}
	if _, err := RefreshPool(rt, path, "", poolServers()[:1], PoolState{Selector: DefaultPoolSelector, BalancerTag: DefaultBalancerTag}, PoolSelection{MaxNodes: 1}); err != nil {
		t.Fatal(err)
	}
	observatory := mapOf(profileApplyDocument(t, rt.RoutingFile)["observatory"])
	if observatory["probeInterval"] != "7m" {
		t.Fatal("ordinary pool refresh rewrote the active provider observer interval")
	}
}

func TestProfileApplyValidatorFailureRestoresAllFilesAndBackups(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("fake dispatcher is a POSIX shell executable; run on native Linux")
	}
	rt, path, _, _ := profileApplyBaseline(t)
	paths, err := filepath.Glob(filepath.Join(rt.XrayConfDir, "*.json"))
	if err != nil {
		t.Fatal(err)
	}
	before := map[string][]byte{}
	for _, file := range paths {
		if err := os.WriteFile(file+".bak", []byte("synthetic original backup"), 0600); err != nil {
			t.Fatal(err)
		}
		for _, capture := range []string{file, file + ".bak"} {
			data, err := os.ReadFile(capture)
			if err != nil {
				t.Fatal(err)
			}
			before[capture] = data
		}
	}
	marker := filepath.Join(rt.XrayConfDir, "validator-called")
	dispatcher := filepath.Join(rt.XrayConfDir, "fake-dispatcher")
	if err := os.WriteFile(dispatcher, []byte("#!/bin/sh\nprintf called > '"+marker+"'\nexit 1\n"), 0700); err != nil {
		t.Fatal(err)
	}
	rt.Installed = true
	rt.Dispatcher = dispatcher
	if err := SetManualOutbound(rt, path, profileServer(t, profileFixture())); err == nil {
		t.Fatal("rejected validator result was committed")
	}
	if _, err := os.Stat(marker); err != nil {
		t.Fatal("test did not reach the post-write validator")
	}
	for file, want := range before {
		got, err := os.ReadFile(file)
		if err != nil || !bytes.Equal(got, want) {
			t.Fatal("failed profile apply changed a managed document or its previous backup")
		}
	}
	if HasActiveProfile(path) {
		t.Fatal("rejected profile left saved state")
	}
}
