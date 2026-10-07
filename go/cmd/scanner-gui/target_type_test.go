package main

import (
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"reachability-scanner/engine"
)

func TestCleanTargetSelectionUsesOnlySelectedProfile(t *testing.T) {
	s := defaultSettings()
	s.Targets[ModeCustom] = ModeTargets{TargetType: engine.TargetDomain, TargetsText: "203.0.113.1", CustomPorts: "80", Inputs: map[string]TargetInput{
		engine.TargetIP:     {TargetsText: "203.0.113.1", CustomPorts: "443"},
		engine.TargetDomain: {TargetsText: "edge.example.com:8443", CustomPorts: "8443"},
	}}
	cfg, err := s.toScanConfig(ModeCustom, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	text, err := os.ReadFile(cfg.InputFile)
	if err != nil || string(text) != "edge.example.com:8443\n" || cfg.TargetType != engine.TargetDomain || len(cfg.CustomPorts) != 1 || cfg.CustomPorts[0] != 8443 {
		t.Fatalf("domain selection used stale IP inputs: %+v %q %v", cfg, text, err)
	}
	domainCache := cfg.CacheFile
	target := s.Targets[ModeCustom]
	target.TargetType = engine.TargetIP
	s.Targets[ModeCustom] = target
	cfg, err = s.toScanConfig(ModeCustom, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	text, _ = os.ReadFile(cfg.InputFile)
	if string(text) != "203.0.113.1\n" || cfg.CustomPorts[0] != 443 || cfg.TargetType != engine.TargetIP || cfg.CacheFile == domainCache {
		t.Fatalf("IP selection: %+v %q", cfg, text)
	}
}

func TestCleanTargetSelectionRejectsWrongTypeInPastesAndFiles(t *testing.T) {
	for _, tc := range []struct{ kind, text, hint string }{
		{engine.TargetIP, "edge.example.com", "Edge domains"},
		{engine.TargetDomain, "192.0.2.0/24", "Cloudflare clean IP finder"},
	} {
		for _, fileInput := range []bool{false, true} {
			s := defaultSettings()
			input := TargetInput{TargetsText: tc.text}
			if fileInput {
				path := filepath.Join(t.TempDir(), "targets.txt")
				if err := os.WriteFile(path, []byte(tc.text), 0600); err != nil {
					t.Fatal(err)
				}
				input = TargetInput{InputFile: path}
			}
			s.Targets[ModeHTTP] = ModeTargets{TargetType: tc.kind, Inputs: map[string]TargetInput{tc.kind: input}}
			if _, err := s.toScanConfig(ModeHTTP, t.TempDir()); err == nil || !strings.Contains(err.Error(), tc.hint) {
				t.Fatalf("wrong type was accepted: %s, file=%v, error=%v", tc.kind, fileInput, err)
			}
		}
	}
	s := defaultSettings()
	s.Targets[ModeHTTP] = ModeTargets{TargetType: "invalid", TargetsText: "192.0.2.1"}
	if _, err := s.toScanConfig(ModeHTTP, t.TempDir()); err == nil {
		t.Fatal("invalid selection must fail")
	}
	// Previously saved mixed lists remain compatible through the old shape.
	s.Targets[ModeHTTP] = ModeTargets{TargetsText: "192.0.2.1\nedge.example.com"}
	if _, err := s.toScanConfig(ModeHTTP, t.TempDir()); err != nil {
		t.Fatalf("legacy inputs: %v", err)
	}
}

func TestCleanTargetSelectionPersistsInRunAndResults(t *testing.T) {
	t.Setenv("WHITEDNS_CONFIG_DIR", t.TempDir())
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(204) }))
	defer server.Close()
	_, port, _ := net.SplitHostPort(server.Listener.Addr().String())
	s := defaultSettings()
	s.OutputDir = t.TempDir()
	s.AutoConcurrency = false
	s.MaxConcurrent = 1
	s.StreamingAuto = false
	s.RetryCount = 0
	s.Targets[ModeCustom] = ModeTargets{TargetType: engine.TargetIP, Inputs: map[string]TargetInput{
		engine.TargetIP:     {TargetsText: "127.0.0.1", CustomPorts: port},
		engine.TargetDomain: {TargetsText: "edge.example.com", CustomPorts: "8443"},
	}}
	app := &App{state: "IDLE", results: newStore()}
	if err := app.StartScan(ModeCustom, s); err != nil {
		t.Fatal(err)
	}
	waitStopped(t, app)
	stats := app.GetStats()
	if stats.TargetType != engine.TargetIP || stats.Counts[TabOK] != 1 {
		t.Fatalf("typed scan failed: %+v", stats)
	}
	runs := app.ListRuns()
	if len(runs) != 1 || runs[0].TargetType != engine.TargetIP || runs[0].Targets != "pasted list" {
		t.Fatalf("run selection lost: %+v", runs)
	}
	loaded, err := app.LoadRun(runs[0].Dir)
	if err != nil || loaded.TargetType != engine.TargetIP {
		t.Fatalf("loaded selection: %+v %v", loaded, err)
	}
	if _, err := os.Stat(filepath.Join(s.OutputDir, "Custom ports", "ip-last_passed.txt")); err != nil {
		t.Fatal(err)
	}
	saved := loadSettings()
	if saved.Targets[ModeCustom].Inputs[engine.TargetDomain].TargetsText != "edge.example.com" || saved.Targets[ModeCustom].TargetType != engine.TargetIP {
		t.Fatal("inactive profile or selection lost during save")
	}
}

func TestEdgeDomainSelectionRunsDomainProbe(t *testing.T) {
	t.Setenv("WHITEDNS_CONFIG_DIR", t.TempDir())
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Host != "localhost" {
			t.Errorf("domain Host was lost: %q", r.Host)
		}
		w.WriteHeader(204)
	}))
	listener, err := net.Listen("tcp", "[::]:0")
	if err != nil {
		server.Close()
		t.Skipf("dual-stack loopback unavailable: %v", err)
	}
	server.Listener.Close()
	server.Listener = listener
	server.StartTLS()
	defer server.Close()
	_, port, _ := net.SplitHostPort(server.Listener.Addr().String())
	conn, err := net.Dial("tcp", net.JoinHostPort("localhost", port))
	if err != nil {
		t.Skipf("localhost cannot reach the test listener: %v", err)
	}
	conn.Close()
	s := defaultSettings()
	s.OutputDir = t.TempDir()
	s.AutoConcurrency = false
	s.MaxConcurrent = 1
	s.StreamingAuto = false
	s.RetryCount = 0
	s.Targets[ModeHTTP] = ModeTargets{TargetType: engine.TargetDomain, Inputs: map[string]TargetInput{
		engine.TargetDomain: {TargetsText: "https://localhost:" + port},
		engine.TargetIP:     {TargetsText: "192.0.2.1"},
	}}
	app := &App{state: "IDLE", results: newStore()}
	if err := app.StartScan(ModeHTTP, s); err != nil {
		t.Fatal(err)
	}
	waitStopped(t, app)
	results := app.QueryResults(Query{Tab: TabAll, Limit: 10})
	if len(results.Rows) != 1 || results.Rows[0].Category != TabOK || !strings.Contains(results.Rows[0].Label, "localhost") || app.GetStats().TargetType != engine.TargetDomain {
		t.Fatalf("domain profile was not probed: %+v", results)
	}
	if runs := app.ListRuns(); len(runs) != 1 || runs[0].TargetType != engine.TargetDomain {
		t.Fatalf("domain run metadata: %+v", runs)
	}
}
