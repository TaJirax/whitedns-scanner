package main

import (
	"strings"
	"testing"

	"reachability-scanner/engine"
)

func TestManualConcurrencyAcceptedForEveryMode(t *testing.T) {
	for _, mode := range engine.ScanModes() {
		t.Run(mode.ID, func(t *testing.T) {
			s := defaultSettings()
			s.AutoConcurrency, s.MaxConcurrent, s.MinConcurrent = false, 7, 200
			s.Targets[mode.ID] = ModeTargets{TargetsText: "127.0.0.1", CustomPorts: "443"}
			s.DnsTxtDomain = "txt.example.com"
			cfg, err := s.toScanConfig(mode.ID, t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			if cfg.AutoConcurrency || cfg.MaxConcurrent != 7 {
				t.Fatalf("manual worker setting was changed: %+v", cfg)
			}
		})
	}
}

func TestAutomaticConcurrencyRejectsInvertedBounds(t *testing.T) {
	s := defaultSettings()
	s.AutoConcurrency, s.MaxConcurrent, s.MinConcurrent = true, 7, 200
	s.Targets[ModeHTTP] = ModeTargets{TargetsText: "127.0.0.1"}
	if _, err := s.toScanConfig(ModeHTTP, t.TempDir()); err == nil || !strings.Contains(err.Error(), "minimum workers") {
		t.Fatalf("invalid automatic bounds were accepted: %v", err)
	}
}
