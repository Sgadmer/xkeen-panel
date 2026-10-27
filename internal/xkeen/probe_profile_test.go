package xkeen

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestEnsureProbeRoutePreservesActiveProfileAcrossStartup(t *testing.T) {
	rt, path, _, _ := profileApplyBaseline(t)
	const address = "127.0.0.1:10086"
	if ready, changed, err := EnsureProbeRoute(rt, address, ReadTopology(rt)); err != nil || !ready || !changed {
		t.Fatalf("initial ordinary probe setup failed: %v", err)
	}
	profile := profileServer(t, profileFixture())
	if err := SetManualOutbound(rt, path, profile); err != nil {
		t.Fatal(err)
	}
	inboundPath := filepath.Join(rt.XrayConfDir, probeInboundFile)
	inbound := mapOf(asSlice(profileApplyDocument(t, inboundPath)["inbounds"])[0])
	if mapOf(inbound["sniffing"])["enabled"] != true {
		t.Fatal("test did not install provider sniffing on panel-probe")
	}
	routingBefore, err := os.ReadFile(rt.RoutingFile)
	if err != nil {
		t.Fatal(err)
	}
	inboundBefore, err := os.ReadFile(inboundPath)
	if err != nil {
		t.Fatal(err)
	}
	for attempt := 0; attempt < 3; attempt++ {
		ready, changed, err := EnsureProbeRoute(rt, address, ReadTopology(rt))
		if err != nil || !ready || changed {
			t.Fatalf("startup rewrote an already-installed profile probe: ready=%v changed=%v error=%v", ready, changed, err)
		}
		routingAfter, _ := os.ReadFile(rt.RoutingFile)
		inboundAfter, _ := os.ReadFile(inboundPath)
		if !bytes.Equal(routingBefore, routingAfter) || !bytes.Equal(inboundBefore, inboundAfter) {
			t.Fatal("startup altered provider routes or probe sniffing")
		}
	}
	if err := SetManualOutbound(rt, path, poolServers()[0]); err != nil {
		t.Fatal(err)
	}
	if ready, changed, err := EnsureProbeRoute(rt, address, ReadTopology(rt)); err != nil || !ready || changed {
		t.Fatal("ordinary probe no longer works after leaving a provider profile")
	}
}

func TestOwnedProfileProbeRuleRequiresValidNamespaceAndExactInput(t *testing.T) {
	owned := "xkp-" + strings.Repeat("a", 64) + "-bound-probe"
	for _, test := range []struct {
		tag    string
		inputs []interface{}
		want   bool
	}{
		{owned, []interface{}{ProbeInboundTag}, true},
		{owned, []interface{}{ProbeInboundTag, "redirect"}, false},
		{owned, []interface{}{"redirect"}, false},
		{"xkp-not-a-profile-bound-probe", []interface{}{ProbeInboundTag}, false},
		{"", []interface{}{ProbeInboundTag}, false},
	} {
		routing := map[string]interface{}{"rules": []interface{}{map[string]interface{}{"ruleTag": test.tag, "inboundTag": test.inputs}}}
		if got := hasOwnedProfileProbeRule(routing); got != test.want {
			t.Fatal("profile probe ownership accepted an untrusted namespace or a mixed inbound rule")
		}
	}
}
