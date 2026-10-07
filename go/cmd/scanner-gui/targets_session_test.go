package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"reachability-scanner/engine"
)

// Pasted IP lists and added ASNs are session drafts: they never reach disk, so
// closing the app clears them. Domain lists and every other setting survive.
func TestIPListsAreNotSaved(t *testing.T) {
	t.Setenv("WHITEDNS_CONFIG_DIR", t.TempDir())
	s := defaultSettings()
	asn := []ASNPick{{ASN: "AS13335", Family: "both", Ranges: 26107}}
	s.Targets[ModeDNS] = ModeTargets{TargetsText: "1.1.1.1", ASNs: asn, InputFile: "resolvers.txt", IPFamily: "ipv4"}
	s.Targets[ModeHTTP] = ModeTargets{TargetType: engine.TargetIP, TargetsText: "104.16.0.0/16", ASNs: asn, Inputs: map[string]TargetInput{
		engine.TargetIP:     {TargetsText: "104.16.0.0/16", ASNs: asn},
		engine.TargetDomain: {TargetsText: "edge.example.com"},
	}}
	s.Targets[ModeCustom] = ModeTargets{TargetType: engine.TargetDomain, TargetsText: "edge.example.com"}
	if err := saveSettings(s); err != nil {
		t.Fatal(err)
	}
	got := loadSettings()
	dns, http, custom := got.Targets[ModeDNS], got.Targets[ModeHTTP], got.Targets[ModeCustom]
	if dns.TargetsText != "" || dns.ASNs != nil || http.TargetsText != "" || http.ASNs != nil || http.Inputs[engine.TargetIP].TargetsText != "" || http.Inputs[engine.TargetIP].ASNs != nil {
		t.Fatalf("IP lists were saved: %+v %+v", dns, http)
	}
	if dns.InputFile != "resolvers.txt" || dns.IPFamily != "ipv4" || http.Inputs[engine.TargetDomain].TargetsText != "edge.example.com" || custom.TargetsText != "edge.example.com" {
		t.Fatalf("other target settings were lost: %+v %+v %+v", dns, http, custom)
	}
	if s.Targets[ModeHTTP].Inputs[engine.TargetIP].TargetsText == "" {
		t.Fatal("saving cleared the in-memory list")
	}
}

// ASNs are expanded into targets.txt only when the scan starts, after the
// pasted list; non-clean pages keep their own IP version.
func TestASNsExpandAtScanStartWithPageIPVersion(t *testing.T) {
	s := defaultSettings()
	s.Targets[ModeDNS] = ModeTargets{TargetsText: "1.1.1.1", IPFamily: "ipv6", ASNs: []ASNPick{{ASN: "AS58224", Family: "ipv4"}}}
	dir := t.TempDir()
	cfg, err := s.toScanConfig(ModeDNS, dir)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(filepath.Join(dir, "targets.txt"))
	want, _ := engine.ASNRanges([]string{"AS58224"}, "ipv4")
	lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
	if lines[0] != "1.1.1.1" || len(lines) != 1+len(want) || lines[1] != want[0] {
		t.Fatalf("targets.txt has %d lines (want %d), starting %q", len(lines), 1+len(want), lines[:2])
	}
	if cfg.IPFamily != "ipv6" {
		t.Fatalf("the DNS page's IP version was dropped: %q", cfg.IPFamily)
	}
	s.Targets[ModeSNI] = ModeTargets{ASNs: []ASNPick{{ASN: "AS58224"}}}
	if _, err := s.toScanConfig(ModeSNI, t.TempDir()); err != nil {
		t.Fatalf("an ASN alone is a valid target list: %v", err)
	}
	s.Targets[ModeSNI] = ModeTargets{}
	if _, err := s.toScanConfig(ModeSNI, t.TempDir()); err == nil {
		t.Fatal("no targets at all must be refused")
	}
}

func TestDeleteResultsRewritesTheRun(t *testing.T) {
	dir := t.TempDir()
	a := &App{state: "STOPPED", results: newStore(), run: RunInfo{Dir: dir, Mode: ModeHTTP}}
	for i, e := range []string{"", "TCP_FAILED", "", "TCP_FAILED"} {
		a.results.add(&engine.ScanResult{Label: string(rune('a' + i)), Error: e})
	}
	if n, err := a.DeleteResults(Query{}, []int{1}); n != 1 || err != nil {
		t.Fatal(n, err)
	}
	if n, err := a.DeleteResults(Query{Tab: TabDead}, nil); n != 2 || err != nil {
		t.Fatal(n, err)
	}
	if row := a.results.add(&engine.ScanResult{Label: "e"}); row.Seq != 5 {
		t.Fatalf("a deleted row's Seq was reused: %d", row.Seq)
	}
	if c := a.results.snapshotCounts(); c[TabAll] != 2 || c[TabOK] != 2 || c[TabDead] != 0 {
		t.Fatalf("counts after delete: %v", c)
	}
	loaded := newStore()
	if err := loaded.loadCSV(filepath.Join(dir, "results.csv")); err != nil || len(loaded.all()) != 1 || loaded.all()[0].Label != "c" {
		t.Fatalf("results.csv after delete: %v %+v", err, loaded.all())
	}
	if info := readRunInfo(dir, ModeHTTP); info.Counts[TabAll] != 1 {
		t.Fatalf("run.json tallies after delete: %v", info.Counts)
	}
	a.busy = true
	if _, err := a.DeleteResults(Query{}, nil); err == nil {
		t.Fatal("deleting during a scan must be refused")
	}
}
