package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"xkeen-panel/internal/models"
	"xkeen-panel/internal/xkeen"
)

type input struct {
	SourceFile   string `json:"source_file"`
	BaselineData string `json:"baseline_data"`
	DataDir      string `json:"data_dir"`
	CoreBin      string `json:"core_bin"`
}

func die(code string) { fmt.Fprintln(os.Stderr, "AUDIT_UNIVERSAL_ERROR="+code); os.Exit(1) }

func main() {
	inputPath := flag.String("input", "", "private input path")
	flag.Parse()
	raw, err := os.ReadFile(*inputPath)
	if err != nil {
		die("input")
	}
	var in input
	if json.Unmarshal(raw, &in) != nil || !filepath.IsAbs(in.SourceFile) || !filepath.IsAbs(in.BaselineData) || !filepath.IsAbs(in.DataDir) || !filepath.IsAbs(in.CoreBin) {
		die("input_format")
	}
	stage := filepath.Dir(in.SourceFile)
	if filepath.Dir(in.DataDir) != stage || filepath.Dir(in.BaselineData) != stage || !strings.HasPrefix(filepath.Base(stage), "xkeen-universal-stage.") {
		die("input_scope")
	}
	if _, err = os.Stat(in.DataDir); !os.IsNotExist(err) {
		die("output_exists")
	}
	raw, err = os.ReadFile(in.SourceFile)
	if err != nil {
		die("source")
	}
	servers, report, err := xkeen.ParseSubscriptionDetailed(string(raw))
	if err != nil {
		die("parse")
	}
	if report.SkippedComposite>0 {
		var profiles []json.RawMessage
		if json.Unmarshal(raw,&profiles)==nil {
			index:=0
			for _,profile:=range profiles {
				var doc struct{ Outbounds []json.RawMessage `json:"outbounds"` }
				if json.Unmarshal(profile,&doc)!=nil||len(doc.Outbounds)<4 { continue }
				index++
				_,profileErr:=xkeen.BuildProfileBundle(models.Server{RawProfile:profile},xkeen.ManualTag,nil)
				if profileErr!=nil { fmt.Printf("AUDIT_UNIVERSAL_PROFILE_REJECT_%d=%s\n",index,xkeen.ProfileRenderPhase(profileErr)) }
			}
		}
	}
	baselineRaw, err := os.ReadFile(filepath.Join(in.BaselineData, "subscription.json"))
	if err != nil {
		die("baseline")
	}
	var baseline models.SubscriptionData
	if json.Unmarshal(baselineRaw, &baseline) != nil {
		die("baseline_format")
	}
	if os.Mkdir(in.DataDir, 0700) != nil {
		die("output")
	}
	checked, err := xkeen.CheckServersHTTPS(xkeen.Runtime{Core: xkeen.CoreXray, CoreBin: in.CoreBin}, servers, xkeen.ProbeOptions{Timeout: 8 * time.Second, Concurrency: 3, StateDir: in.DataDir})
	if err != nil {
		die("probe")
	}
	activeIdentity := ""
	for _, s := range baseline.Servers {
		if s.Active {
			activeIdentity = xkeen.ServerIdentity(s)
		}
	}
	active := 0
	ordinaryPass, profilePass, profileFail := 0, 0, 0
	for i := range checked {
		checked[i].ID = i
		checked[i].Active = false
		if xkeen.ServerIdentity(checked[i]) == activeIdentity {
			active = i
		}
		if len(checked[i].RawProfile) > 0 {
			if checked[i].Latency >= 0 {
				profilePass++
			} else {
				profileFail++
			}
		} else if checked[i].Latency >= 0 {
			ordinaryPass++
		}
	}
	checked[active].Active = true
	state := struct {
		models.SubscriptionData
		ImportReport xkeen.ImportReport `json:"import_report"`
	}{models.SubscriptionData{URL: baseline.URL, Servers: checked, ActiveID: active, LastUpdated: time.Now()}, report}
	raw, err = json.MarshalIndent(state, "", "  ")
	if err != nil {
		die("serialize")
	}
	if os.WriteFile(filepath.Join(in.DataDir, "subscription.json"), raw, 0600) != nil {
		die("save")
	}
	client, err := os.ReadFile(filepath.Join(in.BaselineData, "subscription-client.json"))
	if err != nil {
		die("client")
	}
	if os.WriteFile(filepath.Join(in.DataDir, "subscription-client.json"), client, 0600) != nil {
		die("client_save")
	}
	fmt.Printf("AUDIT_UNIVERSAL_IMPORTED=%d\nAUDIT_UNIVERSAL_PROFILES=%d\nAUDIT_UNIVERSAL_PROFILE_PASS=%d\nAUDIT_UNIVERSAL_PROFILE_FAIL=%d\nAUDIT_UNIVERSAL_ORDINARY_PASS=%d\nAUDIT_UNIVERSAL_SKIPPED_COMPOSITE=%d\nAUDIT_UNIVERSAL_SKIPPED_UNSUPPORTED=%d\n", len(checked), report.ImportedProfiles, profilePass, profileFail, ordinaryPass, report.SkippedComposite, report.SkippedUnsupported)
	if report.ImportedProfiles != 2 || profilePass != 2 {
		os.Exit(1)
	}
}
