package main

import (
	"reachability-scanner/engine"
	"reflect"
	"runtime"
	"testing"
)

func TestCLISelectsEverySharedMode(t *testing.T) {
	for _, mode := range engine.ScanModes() {
		t.Run(mode.ID, func(t *testing.T) {
			cfg := engine.DefaultConfig()
			cfg.ProxyTestURL = "https://example.com/"
			cfg.DnsTxtDomain = "example.test"
			if mode.ID == "custom" {
				cfg.CustomPorts = []int{8443}
			}
			if err := configureScanMode(cfg, mode.ID); err != nil {
				t.Fatal(err)
			}
			if cfg.ModeID() != mode.ID || cfg.ModeName() != mode.Name {
				t.Fatalf("mode selection: %+v", cfg)
			}
			if cfg.SNIScan != (mode.ID == "sni") {
				t.Fatal("SNI leaked into another mode")
			}
		})
	}
}

func TestCLIRejectsInvalidModesAndInputs(t *testing.T) {
	for _, mode := range []string{"unknown", "custom", "txt"} {
		cfg := engine.DefaultConfig()
		if configureScanMode(cfg, mode) == nil {
			t.Fatalf("accepted incomplete %s mode", mode)
		}
	}
	cfg := engine.DefaultConfig()
	cfg.SpoofedSNI = "bad/name"
	if configureScanMode(cfg, "sni") == nil {
		t.Fatal("invalid forged SNI accepted")
	}
	if configureScanMode(cfg, "http") != nil {
		t.Fatal("SNI validation leaked into HTTP")
	}
	cfg.ProxyTestURL = "ftp://example.com"
	if configureScanMode(cfg, "http-proxy") == nil {
		t.Fatal("invalid proxy test URL accepted")
	}
	ports, err := parsePortsString("80,443,8002-8000,443")
	if err != nil || !reflect.DeepEqual(ports, []int{80, 443, 8000, 8001, 8002}) {
		t.Fatalf("ports=%v err=%v", ports, err)
	}
	for _, bad := range []string{"0", "65536", "bad", "80-x"} {
		if _, err := parsePortsString(bad); err == nil {
			t.Fatalf("accepted ports %q", bad)
		}
	}
}

func TestCLIFolderOpener(t *testing.T) {
	program := map[string]string{"windows": "explorer", "linux": "xdg-open", "darwin": "open"}[runtime.GOOS]
	if program == "" {
		t.Skip("unsupported desktop")
	}
	cmd := outputDirCommand("folder & reports")
	if !reflect.DeepEqual(cmd.Args, []string{program, "folder & reports"}) {
		t.Fatal(cmd.Args)
	}
}
