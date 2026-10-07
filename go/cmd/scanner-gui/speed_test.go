package main

import (
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestSettingsRestrictForgedSNIToSNIMode(t *testing.T) {
	s := defaultSettings()
	s.DnsTxtDomain = "txt.example.com"
	s.SpoofedSNI = "forged.example"
	for _, mode := range (&App{}).GetScanModes() {
		s.Targets[mode.ID] = ModeTargets{TargetsText: "127.0.0.1", CustomPorts: "443,8000-8001"}
		dir := filepath.Join(t.TempDir(), "run")
		if err := os.MkdirAll(dir, 0700); err != nil {
			t.Fatal(err)
		}
		cfg, err := s.toScanConfig(mode.ID, dir)
		if err != nil {
			t.Fatalf("%s: %v", mode.ID, err)
		}
		if cfg.SNIScan != (mode.ID == ModeSNI) {
			t.Fatalf("forged SNI enabled for %s", mode.ID)
		}
		if mode.ID == ModeHTTPProxy && cfg.ProxyMode != "http" {
			t.Fatal("HTTP proxy config")
		}
		if mode.ID == ModeSOCKSProxy && cfg.ProxyMode != "socks5" {
			t.Fatal("SOCKS proxy config")
		}
	}
	s.SpoofedSNI = "https://bad.example/path"
	if _, err := s.toScanConfig(ModeSNI, t.TempDir()); err == nil {
		t.Fatal("malformed SNI must be rejected")
	}
	if _, err := s.toScanConfig(ModeHTTP, t.TempDir()); err != nil {
		t.Fatal("irrelevant SNI must not block clean IP")
	}
}

func speedAppForServer(t *testing.T, srv *httptest.Server) *App {
	t.Helper()
	host, rawPort, _ := net.SplitHostPort(srv.Listener.Addr().String())
	port, _ := strconv.Atoi(rawPort)
	a := &App{state: "STOPPED", settings: defaultSettings(), results: newStore(), run: RunInfo{Mode: ModeHTTP, Dir: "selected-run"}}
	a.results.addRow(Row{Label: host, IP: host, URL: srv.URL, Port: port, Status: 200, Category: TabOK})
	return a
}

func TestSpeedUsesSelectedIPAndRejectsStaleOrDNSRows(t *testing.T) {
	seen := make(chan string, 2)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen <- r.Host
		_, _ = w.Write([]byte(strings.Repeat("x", 128<<10)))
	}))
	defer srv.Close()
	a := speedAppForServer(t, srv)
	req := SpeedRequest{Seq: 1, RunDir: "selected-run", DownloadURL: "http://origin.invalid/download", DurationSecs: 2, MaxSizeMB: 1}
	result, err := a.TestSpeed(req)
	if err != nil || result.Bytes != 128<<10 || result.DownloadMbps <= 0 {
		t.Fatalf("speed result: %+v %v", result, err)
	}
	if host := <-seen; host != "origin.invalid" {
		t.Fatalf("lost origin Host: %q", host)
	}
	req.RunDir = "another-run"
	if _, err := a.TestSpeed(req); err == nil {
		t.Fatal("stale result selection accepted")
	}
	req.RunDir = "selected-run"
	a.results.rows[0].Protocol = "UDP/53"
	if _, err := a.TestSpeed(req); err == nil {
		t.Fatal("DNS result must not be used for download test")
	}
}

func TestSpeedCancellationAndConcurrentTestGuard(t *testing.T) {
	reached := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.(http.Flusher).Flush()
		close(reached)
		<-r.Context().Done()
	}))
	defer srv.Close()
	a := speedAppForServer(t, srv)
	req := SpeedRequest{Seq: 1, RunDir: "selected-run", DownloadURL: srv.URL, DurationSecs: 20, MaxSizeMB: 1}
	done := make(chan error, 1)
	go func() { _, err := a.TestSpeed(req); done <- err }()
	select {
	case <-reached:
	case <-time.After(3 * time.Second):
		t.Fatal("test did not reach download")
	}
	if _, err := a.TestSpeed(req); err == nil || !strings.Contains(err.Error(), "already running") {
		t.Fatalf("concurrent test guard: %v", err)
	}
	a.CancelSpeedTest()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("cancelled test reported success")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("speed test cancellation stalled")
	}
}
