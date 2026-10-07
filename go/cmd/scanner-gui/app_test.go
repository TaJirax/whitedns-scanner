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

func waitStopped(t *testing.T, a *App) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for {
		a.mu.Lock()
		busy := a.busy
		a.mu.Unlock()
		if !busy {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("scan did not finish: %+v", a.GetStats())
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// End to end through the methods the window calls: a custom-ports scan of a
// local TLS server plus a closed port lands in its own sorted run folder with
// every report and a results.csv that reloads into Results.
func TestScanThroughApp(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(204) }))
	defer srv.Close()
	_, port, _ := net.SplitHostPort(srv.Listener.Addr().String())
	closed, _ := net.Listen("tcp", "127.0.0.1:0")
	_, closedPort, _ := net.SplitHostPort(closed.Addr().String())
	closed.Close() // nothing listens here any more

	t.Setenv("WHITEDNS_CONFIG_DIR", t.TempDir()) // keep settings.json out of the real profile
	a := &App{state: "IDLE", results: newStore()}
	s := defaultSettings()
	s.OutputDir = t.TempDir()
	s.Targets[ModeCustom] = ModeTargets{TargetsText: "127.0.0.1", CustomPorts: port + "," + closedPort}
	s.TimeoutSecs, s.RetryCount = 3, 0
	s.AutoConcurrency, s.MaxConcurrent, s.StreamingAuto = false, 4, false

	if err := a.StartScan(ModeCustom, s); err != nil {
		t.Fatal(err)
	}
	if a.StartScan(ModeCustom, s) == nil {
		t.Fatal("a second scan must be refused while one runs")
	}
	waitStopped(t, a)

	st := a.GetStats()
	if st.Counts[TabAll] != 2 || st.Counts[TabOK] != 1 || st.Counts[TabDead] != 1 {
		t.Fatalf("counts = %v, want 1 reachable + 1 failed", st.Counts)
	}
	ok := a.QueryResults(Query{Tab: TabOK, Limit: 10})
	if ok.Total != 1 || ok.Rows[0].Status != 204 || strconv.Itoa(ok.Rows[0].Port) != port {
		t.Fatalf("reachable page = %+v", ok)
	}

	// Sorted output: <out>/Custom ports/<date time>/ with the reports.
	if filepath.Dir(st.RunDir) != filepath.Join(s.OutputDir, "Custom ports") {
		t.Fatalf("run dir %s not under the mode folder", st.RunDir)
	}
	runs := a.ListRuns()
	if len(runs) != 1 || runs[0].State != "completed" || !runs[0].HasResult {
		t.Fatalf("runs = %+v", runs)
	}
	kinds := map[string]bool{}
	for _, f := range runs[0].Files {
		kinds[f.Kind] = true
	}
	for _, want := range []string{"Reachable", "Full log", "Raw IP dump", "All results (CSV)", "Targets scanned"} {
		if !kinds[want] {
			t.Fatalf("run folder lacks %q: %+v", want, runs[0].Files)
		}
	}
	if _, err := os.Stat(filepath.Join(s.OutputDir, "Custom ports", "last_passed.txt")); err != nil {
		t.Fatalf("mode cache missing: %v", err)
	}

	// A past run reloads into Results exactly.
	a.results.reset()
	view, err := a.LoadRun(runs[0].Dir)
	if err != nil || view.Counts[TabOK] != 1 || view.Counts[TabDead] != 1 || view.Mode != ModeCustom {
		t.Fatalf("LoadRun = %+v, %v", view, err)
	}
	if txt, err := a.ReadReport(runs[0].Files[0].Path); err != nil || !strings.Contains(txt, "127.0.0.1") {
		t.Fatalf("ReadReport = %q, %v", txt, err)
	}
	if _, err := a.ReadReport(filepath.Join(os.TempDir(), "x.txt")); err == nil {
		t.Fatal("reading outside the output folder must be refused")
	}
}

func TestScanSetupErrorLeavesNoFolder(t *testing.T) {
	t.Setenv("WHITEDNS_CONFIG_DIR", t.TempDir())
	a := &App{state: "IDLE", results: newStore()}
	s := defaultSettings()
	s.OutputDir = t.TempDir()
	if err := a.StartScan(ModeHTTP, s); err == nil {
		t.Fatal("a scan without targets must be refused")
	}
	if runs := a.ListRuns(); len(runs) != 0 {
		t.Fatalf("refused scan left runs: %+v", runs)
	}
	if err := a.StartScan(ModeHTTP, s); err == nil || strings.Contains(err.Error(), "already running") {
		t.Fatalf("refusal must not leave the app busy: %v", err)
	}
}

func TestParsePorts(t *testing.T) {
	got, err := parsePorts("443, 80,8000-8002,443")
	if err != nil || len(got) != 5 {
		t.Fatalf("got %v, %v", got, err)
	}
	for _, bad := range []string{"0", "70000", "a", "1-x"} {
		if _, err := parsePorts(bad); err == nil {
			t.Fatalf("%q should be rejected", bad)
		}
	}
}

func TestSettingsLoadIgnoresBOM(t *testing.T) {
	t.Setenv("WHITEDNS_CONFIG_DIR", t.TempDir())
	want := defaultSettings()
	want.Theme = "light"
	if err := saveSettings(want); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(settingsPath())
	if err := os.WriteFile(settingsPath(), append([]byte("\xef\xbb\xbf"), raw...), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := loadSettings(); got.Theme != "light" {
		t.Fatalf("BOM-prefixed settings not loaded: theme=%s", got.Theme)
	}
}
