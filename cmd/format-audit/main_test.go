package main

import (
	"path/filepath"
	"testing"
)

func TestSyntheticAuditCasesParseBuildAndRejectWithoutCore(t *testing.T) {
	cases := auditCases()
	seen := map[string]bool{}
	positive, negative := 0, 0
	for _, spec := range cases {
		if !safeCaseID.MatchString(spec.ID) || seen[spec.ID] {
			t.Fatal("invalid or duplicate case identifier")
		}
		seen[spec.ID] = true
		outbound, ok := prepareCase(spec)
		if !ok {
			t.Fatalf("synthetic case %s failed before native validation", spec.ID)
		}
		if spec.Reject {
			negative++
		} else {
			positive++
			if outbound == nil {
				t.Fatal("positive case has no outbound")
			}
		}
	}
	if positive != 29 || negative != 9 {
		t.Fatalf("coverage changed: positive=%d rejected=%d", positive, negative)
	}
}

func TestAuditOutputRequiresNewIsolatedDirectory(t *testing.T) {
	parent := t.TempDir()
	path := filepath.Join(parent, "format-audit")
	created, ok := createOutput(path)
	if !ok || created != path {
		t.Fatal("isolated temporary output rejected")
	}
	if _, ok := createOutput(path); ok {
		t.Fatal("existing directory was accepted")
	}
	if _, ok := createOutput(filepath.Dir(parent)); ok {
		t.Fatal("existing temporary parent was accepted")
	}
	if _, ok := createOutput("/opt/etc/xray/configs/format-audit"); ok {
		t.Fatal("production output path was accepted")
	}
}
