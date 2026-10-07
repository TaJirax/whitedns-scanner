package mobile

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"reachability-scanner/engine"
)

func TestMobileUsesAllSharedModesAndIsolatesSNI(t *testing.T) {
	for _, mode := range engine.ScanModes() {
		cfg := engine.DefaultConfig()
		cfg.MaxConcurrent = 20
		cfg.MinConcurrent = 2
		cfg.TargetType = "ip"
		cfg.DnsTxtDomain = "txt.example.com"
		cfg.ProxyTestURL = "https://example.com"
		cfg.CustomPorts = []int{443}
		cfg.AntiDPI = true
		out, err := buildConfig(request{Mode: mode.ID, Provider: "cloudflare", Options: cfg})
		if err != nil {
			t.Fatalf("%s: %v", mode.ID, err)
		}
		if out.SNIScan != (mode.ID == "sni") {
			t.Fatalf("SNI scope: %s", mode.ID)
		}
		if !out.Streaming || out.StreamingAuto {
			t.Fatal("mobile must stream")
		}
	}
}
func TestMobileScanResultsExportsAndSelectedSpeed(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(r.Host)) }))
	defer origin.Close()
	s, err := NewScanner(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if s.rows != nil {
			s.rows.Close()
		}
	}()
	cfg := engine.DefaultConfig()
	cfg.MaxConcurrent = 2
	cfg.MinConcurrent = 1
	cfg.AutoConcurrency = false
	cfg.TargetType = "ip"
	cfg.RetryCount = 0
	raw, _ := json.Marshal(request{Mode: "http", Provider: "cloudflare", Targets: origin.URL, Options: cfg})
	if err = s.Start(string(raw)); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(3 * time.Second)
	var status snapshot
	for {
		json.Unmarshal([]byte(s.Snapshot()), &status)
		if !status.Busy {
			break
		}
		if time.Now().After(deadline) {
			s.Stop()
			t.Fatal("scan stuck")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if status.State != "completed" || status.Open != 1 || status.Done != 1 {
		t.Fatalf("status: %+v", status)
	}
	rows, err := s.Results(0, 100)
	if err != nil {
		t.Fatal(err)
	}
	var parsed []engine.ScanResult
	json.Unmarshal([]byte(rows), &parsed)
	if len(parsed) != 1 || parsed[0].ServiceTotal != 9 {
		t.Fatalf("mobile lost nine checks: %s", rows)
	}
	if _, err = s.TestSpeed("stale", 1, origin.URL, 1, 1); err == nil {
		t.Fatal("stale speed selection accepted")
	}
	// For a plain-IP speed test the HTTP mode must not be treated as an HTTP proxy.
	if _, err = s.TestSpeed(status.Run, 1, origin.URL, 1, 1); err != nil {
		t.Fatal(err)
	}
	if _, err = os.Stat(filepath.Join(s.root, "runs", status.Run, "results.csv")); err != nil {
		t.Fatal(err)
	}
	if _, err = s.Reports(); err != nil {
		t.Fatal(err)
	}
	restored, _ := NewScanner(s.root)
	defer func() {
		if restored.rows != nil {
			restored.rows.Close()
		}
	}()
	if err = restored.LoadRun(status.Run); err != nil {
		t.Fatal(err)
	}
	if got, err := restored.Results(0, 100); err != nil || got != rows {
		t.Fatalf("restored rows differ: %s %v", got, err)
	}
	if _, err = restored.TestSpeed(status.Run, 1, origin.URL, 0, 1); err == nil {
		t.Fatal("out-of-range speed duration accepted")
	}
	// Desktop result categories: the one reachable row is "ok", none are "dead".
	var page struct {
		Rows   []queryRow     `json:"rows"`
		Total  int            `json:"total"`
		Counts map[string]int `json:"counts"`
	}
	for _, c := range []struct { // "ok" last: its row is checked below
		tab  string
		want int
	}{{"dead", 0}, {"all", 1}, {"ok", 1}} {
		tab, want := c.tab, c.want
		got, err := restored.Query(`{"tab":"` + tab + `","sortBy":"latency","limit":50}`)
		if err != nil {
			t.Fatal(err)
		}
		json.Unmarshal([]byte(got), &page)
		if page.Total != want || len(page.Rows) != want || page.Counts["ok"] != 1 || page.Counts["all"] != 1 {
			t.Fatalf("%s query: %s", tab, got)
		}
	}
	if page.Rows[0].Seq != 1 || page.Rows[0].Category != "ok" {
		t.Fatalf("query row: %+v", page.Rows[0])
	}
	exported, err := restored.Export(`{"tab":"ok"}`)
	if err != nil {
		t.Fatal(err)
	}
	if reports, _ := restored.Reports(); !strings.Contains(reports, `"kind":"Filtered export (CSV)"`) || !strings.Contains(reports, filepath.Base(exported)) {
		t.Fatalf("export not listed: %s", reports)
	}
	if err = restored.LoadRun("../escape"); err == nil {
		t.Fatal("invalid run accepted")
	}
}
