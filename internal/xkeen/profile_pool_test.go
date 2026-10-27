package xkeen

import (
	"path/filepath"
	"strings"
	"testing"

	"xkeen-panel/internal/models"
)

func TestOnlyProfilesPoolFailsClosedUntilManualActivation(t *testing.T) {
	for _, bootstrap := range []bool{false, true} {
		name := "enable-existing"
		if bootstrap {
			name = "bootstrap-fresh"
		}
		t.Run(name, func(t *testing.T) {
			var rt Runtime
			var path string
			if bootstrap {
				rt, path = freshInstallDir(t, false)
			} else {
				rt, path = liveConfDir(t)
				profileApplyWrite(t, filepath.Join(rt.XrayConfDir, "03_inbounds.json"), map[string]interface{}{"inbounds": []interface{}{
					map[string]interface{}{"tag": "redirect", "protocol": "dokodemo-door", "port": 12345},
					map[string]interface{}{"tag": "tproxy", "protocol": "dokodemo-door", "port": 12346},
				}})
			}
			profile := profileServer(t, profileFixture())
			profile.RawURI = ProfileIdentity(profile)
			servers := []models.Server{profile}
			if len(SelectPoolServers(servers, PoolSelection{})) != 0 {
				t.Fatal("provider profile entered the ordinary auto pool")
			}
			var state PoolState
			var err error
			if bootstrap {
				state, err = Bootstrap(rt, path, servers, PoolOptions{})
			} else {
				state, err = EnablePool(rt, path, servers, PoolOptions{})
			}
			if err != nil || !state.Enabled {
				t.Fatalf("profile-only subscription could not initialize safe pool: %v", err)
			}
			config := profileApplyDocument(t, path)
			outbounds := asSlice(config["outbounds"])
			if len(outbounds) == 0 || mapOf(outbounds[0])["protocol"] != "blackhole" || outboundTag(mapOf(outbounds[0])) != DefaultPoolSelector+"guard" {
				t.Fatal("unselected profile subscription did not default to a closed guard")
			}
			for _, raw := range outbounds {
				outbound := mapOf(raw)
				if strings.HasPrefix(outboundTag(outbound), DefaultPoolSelector) && outbound["protocol"] != "blackhole" {
					t.Fatal("profile-only bootstrap accidentally exposed a live ordinary node")
				}
			}
			if err := SetManualOutbound(rt, path, profile); err != nil {
				t.Fatal(err)
			}
			if !HasActiveProfile(path) || NodeKeyForTag(path, DefaultPoolSelector, ManualTag) != NodeKeyOfServer(profile) {
				t.Fatal("profile-only pool could not activate its explicit manual choice")
			}
			config = profileApplyDocument(t, path)
			guardFound := false
			internalFound := false
			for _, raw := range asSlice(config["outbounds"]) {
				outbound := mapOf(raw)
				tag := outboundTag(outbound)
				if tag == DefaultPoolSelector+"guard" && outbound["protocol"] == "blackhole" {
					guardFound = true
				}
				if IsProfileInternalTag(tag) && outbound["protocol"] == "vless" {
					internalFound = true
				}
			}
			if !guardFound || !internalFound {
				t.Fatal("manual profile activation lost either the outer fail-closed guard or internal provider nodes")
			}
		})
	}
}
