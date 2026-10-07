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

func retrySetting(n int) *int { return &n }

func TestCDNProfilesHaveIndependentInputsAndRequestOptions(t *testing.T) {
	s := defaultSettings()
	s.Targets[ModeCustom] = ModeTargets{TargetType: engine.TargetDomain, EdgeProvider: "cloudflare", Inputs: map[string]TargetInput{engine.TargetDomain: {TargetsText: "stale.example", CustomPorts: "80"}}, EdgeInputs: map[string]TargetInput{
		"cloudflare": {TargetsText: "cf.example", CustomPorts: "443,8443", TimeoutSecs: 7, RetryCount: retrySetting(0), UserAgent: "cf-agent"},
		"fastly":     {TargetsText: "fastly.example", CustomPorts: "80,443", TimeoutSecs: 12, RetryCount: retrySetting(3), UserAgent: "fastly-agent"},
		"akamai":     {TargetsText: "akamai.example", CustomPorts: "8443", TimeoutSecs: 15, RetryCount: retrySetting(1), UserAgent: "akamai-agent"},
		"custom":     {TargetsText: "custom.example", CustomPorts: "9000", TimeoutSecs: 9, RetryCount: retrySetting(2), UserAgent: "custom-agent"},
	}}
	caches := map[string]bool{}
	for _, provider := range (&App{}).GetEdgeProviders() {
		if _, ok := s.Targets[ModeCustom].EdgeInputs[provider.ID]; !ok {
			continue
		}
		selection := s.Targets[ModeCustom]
		selection.EdgeProvider = provider.ID
		s.Targets[ModeCustom] = selection
		expected := selection.EdgeInputs[provider.ID]
		cfg, err := s.toScanConfig(ModeCustom, t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		raw, _ := os.ReadFile(cfg.InputFile)
		if string(raw) != expected.TargetsText+"\n" || cfg.EdgeProvider != provider.ID || cfg.TimeoutSecs != expected.TimeoutSecs || cfg.RetryCount != *expected.RetryCount || cfg.UserAgent != expected.UserAgent {
			t.Fatalf("wrong profile: %+v %q", cfg, raw)
		}
		if caches[cfg.CacheFile] {
			t.Fatal("CDN providers share a passed-target cache")
		}
		caches[cfg.CacheFile] = true
		if !strings.Contains(filepath.Base(cfg.CacheFile), "domain-"+provider.ID+"-") {
			t.Fatal("provider missing from cache path")
		}
	}
}

func TestCloudflarePortExpansionIsOnlyOfferedToCloudflare(t *testing.T) {
	s := defaultSettings()
	for _, provider := range (&App{}).GetEdgeProviders() {
		s.Targets[ModeHTTPAll] = ModeTargets{TargetType: engine.TargetDomain, EdgeProvider: provider.ID, EdgeInputs: map[string]TargetInput{provider.ID: {TargetsText: "edge.example"}}}
		cfg, err := s.toScanConfig(ModeHTTPAll, t.TempDir())
		if provider.ID == "cloudflare" || provider.ID == "cloudflare-pages" {
			if err != nil || !cfg.ScanAllPorts {
				t.Fatalf("Cloudflare deep scan: %+v %v", cfg, err)
			}
		} else if err == nil {
			t.Fatalf("Cloudflare port set applied to %s", provider.ID)
		}
	}
	s.Targets[ModeHTTP] = ModeTargets{TargetType: engine.TargetDomain, EdgeProvider: "unknown", TargetsText: "edge.example"}
	if _, err := s.toScanConfig(ModeHTTP, t.TempDir()); err == nil {
		t.Fatal("unknown provider accepted")
	}
}

func TestProviderRequestSettingsReachProbeAndReports(t *testing.T) {
	t.Setenv("WHITEDNS_CONFIG_DIR", t.TempDir())
	seen := make(chan string, 2)
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { seen <- r.UserAgent(); w.WriteHeader(204) }))
	listener, err := net.Listen("tcp", "[::]:0")
	if err != nil {
		server.Close()
		t.Skipf("dual-stack unavailable: %v", err)
	}
	server.Listener.Close()
	server.Listener = listener
	server.StartTLS()
	defer server.Close()
	_, port, _ := net.SplitHostPort(listener.Addr().String())
	c, err := net.Dial("tcp", net.JoinHostPort("localhost", port))
	if err != nil {
		t.Skipf("localhost unavailable: %v", err)
	}
	c.Close()
	s := defaultSettings()
	s.OutputDir = t.TempDir()
	s.StreamingAuto = false
	s.AutoConcurrency = false
	s.MaxConcurrent = 1
	s.Targets[ModeHTTP] = ModeTargets{TargetType: engine.TargetDomain, EdgeProvider: "fastly", EdgeInputs: map[string]TargetInput{
		"fastly":     {TargetsText: "https://localhost:" + port, TimeoutSecs: 3, RetryCount: retrySetting(0), UserAgent: "selected-fastly-profile"},
		"cloudflare": {TargetsText: "not-selected.example", UserAgent: "not-selected"},
	}}
	app := &App{state: "IDLE", results: newStore()}
	if err := app.StartScan(ModeHTTP, s); err != nil {
		t.Fatal(err)
	}
	waitStopped(t, app)
	if agent := <-seen; agent != "selected-fastly-profile" {
		t.Fatalf("User-Agent = %q", agent)
	}
	stats := app.GetStats()
	if stats.EdgeProvider != "fastly" || stats.Counts[TabOK] != 1 {
		t.Fatalf("provider scan: %+v", stats)
	}
	runs := app.ListRuns()
	if len(runs) != 1 || runs[0].EdgeProvider != "fastly" {
		t.Fatalf("provider report: %+v", runs)
	}
	loaded, err := app.LoadRun(runs[0].Dir)
	if err != nil || loaded.EdgeProvider != "fastly" {
		t.Fatalf("loaded provider: %+v %v", loaded, err)
	}
}
