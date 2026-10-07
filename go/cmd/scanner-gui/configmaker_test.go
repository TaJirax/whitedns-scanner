package main

import (
	"os"
	"strings"
	"testing"
)

func TestConfigMakerRewritesAndExtracts(t *testing.T) {
	a := &App{settings: Settings{OutputDir: t.TempDir()}, results: newStore()}
	configs := "vless://uuid@old.example.com:443?security=tls&sni=w.me.workers.dev#a\ntrojan://pw@1.2.3.4:443#b"
	targets := "104.16.0.1:443\n104.16.0.2:8443\nnot an ip"
	if info := a.ConfigMakerInspect(configs, targets); info.Configs != 2 || info.Targets != 2 || !strings.Contains(info.Summary, "vless") {
		t.Fatalf("inspect: %+v", info)
	}
	res, err := a.ConfigMakerRewrite(configs, targets)
	if err != nil || res.Count != 2 || !strings.Contains(res.Text, "@104.16.0.1:443") || !strings.Contains(res.Text, "@104.16.0.2:8443") || !strings.Contains(res.Text, "sni=w.me.workers.dev") {
		t.Fatalf("rewrite: %v %+v", err, res)
	}
	if saved, _ := os.ReadFile(res.Path); strings.TrimSpace(string(saved)) != res.Text {
		t.Fatalf("saved file differs: %q", saved)
	}
	ips, err := a.ConfigMakerExtract(res.Text)
	if err != nil || ips.Text != "104.16.0.1:443\n104.16.0.2:8443" {
		t.Fatalf("extract: %v %+v", err, ips)
	}
	if _, err := a.ConfigMakerRewrite("  ", targets); err == nil {
		t.Fatal("empty configs must be refused")
	}
}
