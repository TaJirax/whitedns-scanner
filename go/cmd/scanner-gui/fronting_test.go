package main

import (
	"slices"
	"testing"

	"reachability-scanner/engine"
)

// The fronting domains lead the service checks, and any one domain answering
// through an IP makes it clean (nothing is required); the quick check fronts
// through the first one.
func TestFrontingDomainsDecideCleanIPs(t *testing.T) {
	s := defaultSettings()
	in := TargetInput{TargetsText: "104.16.0.1", ServiceChecks: true, PlatformDomainsText: "my-worker.me.workers.dev\nsite.pages.dev"}
	s.Targets[ModeHTTP] = ModeTargets{TargetType: engine.TargetIP, Inputs: map[string]TargetInput{engine.TargetIP: in}}
	cfg, err := s.toScanConfig(ModeHTTP, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.RequiredProbeDomains) != 0 || !slices.Equal(cfg.ProbeDomains[:2], []string{"my-worker.me.workers.dev", "site.pages.dev"}) || len(cfg.ProbeDomains) != 9 {
		t.Fatalf("any domain must make an IP clean: required=%v probes=%v", cfg.RequiredProbeDomains, cfg.ProbeDomains)
	}
	in.ServiceChecks = false
	s.Targets[ModeHTTP] = ModeTargets{TargetType: engine.TargetIP, Inputs: map[string]TargetInput{engine.TargetIP: in}}
	if cfg, err = s.toScanConfig(ModeHTTP, t.TempDir()); err != nil || cfg.FrontingHost != "my-worker.me.workers.dev" || len(cfg.ProbeDomains) != 0 {
		t.Fatalf("the quick check must front through the first domain: %v %+v", err, cfg)
	}
}

func TestCleanIPsAreFastestFirstAndUnique(t *testing.T) {
	st := newStore()
	for _, r := range []engine.ScanResult{
		{ResolvedIP: "104.16.0.2", Port: 443, LatencyMs: 300},
		{ResolvedIP: "104.16.0.1", Port: 443, LatencyMs: 90},
		{ResolvedIP: "104.16.0.3", Port: 443, LatencyMs: 50, Error: "TLS_FAILED: timeout"},
		{ResolvedIP: "104.16.0.1", Port: 443, LatencyMs: 120},
		{ResolvedIP: "2606:4700::1", Port: 8443, LatencyMs: 200},
	} {
		st.add(&r)
	}
	if got := st.cleanIPs(); got != "104.16.0.1:443\n[2606:4700::1]:8443\n104.16.0.2:443\n" {
		t.Fatalf("clean IPs:\n%s", got)
	}
}
