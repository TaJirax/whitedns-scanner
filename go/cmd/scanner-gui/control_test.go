package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestStopSavesStoppedRunEvenWhenEveryJobReportsCancellation(t *testing.T) {
	entered := make(chan struct{}, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) { entered <- struct{}{}; <-r.Context().Done() }))
	defer srv.Close()
	t.Setenv("WHITEDNS_CONFIG_DIR", t.TempDir())
	a := &App{state: "IDLE", results: newStore()}
	settings := defaultSettings()
	settings.OutputDir = t.TempDir()
	settings.AutoConcurrency = false
	settings.MaxConcurrent = 1
	settings.StreamingAuto = false
	settings.TimeoutSecs = 3
	settings.RetryCount = 0
	settings.Targets[ModeHTTP] = ModeTargets{TargetsText: srv.URL}
	if err := a.StartScan(ModeHTTP, settings); err != nil {
		t.Fatal(err)
	}
	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		t.Fatal("scan did not reach local endpoint")
	}
	a.PauseScan()
	if a.GetStats().State != "PAUSED" {
		t.Fatal("pause failed")
	}
	a.ResumeScan()
	if a.GetStats().State != "RUNNING" {
		t.Fatal("resume failed")
	}
	a.StopScan()
	waitStopped(t, a)
	runs := a.ListRuns()
	if len(runs) != 1 || runs[0].State != "stopped" {
		t.Fatalf("user-stopped scan recorded as completed: %+v", runs)
	}
	if _, err := a.LoadRun(runs[0].Dir); err != nil {
		t.Fatal(err)
	}
}

func TestImmediateStopAfterStart(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) { <-r.Context().Done() }))
	defer srv.Close()
	t.Setenv("WHITEDNS_CONFIG_DIR", t.TempDir())
	for i := 0; i < 8; i++ {
		a := &App{state: "IDLE", results: newStore()}
		s := defaultSettings()
		s.OutputDir = t.TempDir()
		s.AutoConcurrency = false
		s.MaxConcurrent = 1
		s.StreamingAuto = false
		s.TimeoutSecs = 2
		s.RetryCount = 0
		s.Targets[ModeHTTP] = ModeTargets{TargetsText: srv.URL}
		if err := a.StartScan(ModeHTTP, s); err != nil {
			t.Fatal(err)
		}
		a.StopScan()
		waitStopped(t, a)
		if a.ListRuns()[0].State != "stopped" {
			t.Fatal("immediate Stop was lost")
		}
	}
}

func TestCompletionDoesNotHideFatalError(t *testing.T) {
	a := &App{state: "IDLE", results: newStore(), run: RunInfo{Dir: t.TempDir(), Mode: ModeHTTP}}
	h := &guiHandler{app: a}
	h.OnStateChange("FATAL: cannot read targets")
	h.OnComplete(0, 0, 0)
	a.finishRun()
	if a.run.State != "failed" || !strings.Contains(a.GetStats().Message, "cannot read targets") {
		t.Fatalf("failure became success: %+v", a.run)
	}
}

func TestFailedCSVWriteIsNotReportedAsCompleted(t *testing.T) {
	entered, release := make(chan struct{}, 1), make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		entered <- struct{}{}
		select {
		case <-release:
			w.WriteHeader(204)
		case <-r.Context().Done():
		}
	}))
	defer srv.Close()
	t.Setenv("WHITEDNS_CONFIG_DIR", t.TempDir())
	a := &App{state: "IDLE", results: newStore()}
	s := defaultSettings()
	s.OutputDir = t.TempDir()
	s.AutoConcurrency = false
	s.MaxConcurrent = 1
	s.StreamingAuto = false
	s.RetryCount = 0
	s.Targets[ModeHTTP] = ModeTargets{TargetsText: srv.URL}
	if err := a.StartScan(ModeHTTP, s); err != nil {
		t.Fatal(err)
	}
	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		t.Fatal("request did not start")
	}
	if err := os.Mkdir(filepath.Join(a.GetStats().RunDir, "results.csv"), 0700); err != nil {
		t.Fatal(err)
	}
	close(release)
	waitStopped(t, a)
	runs := a.ListRuns()
	if len(runs) != 1 || runs[0].State != "failed" || runs[0].HasResult {
		t.Fatalf("failed report was advertised as available: %+v", runs)
	}
}
