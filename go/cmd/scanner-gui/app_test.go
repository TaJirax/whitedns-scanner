package main

import (
	"net"
	"os"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"
)

// End to end through the methods the window calls: start an HTTP scan of a
// local TLS server plus a closed port, wait for it to finish, page the results.
func TestScanThroughApp(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(204) }))
	defer srv.Close()
	_, port, _ := net.SplitHostPort(srv.Listener.Addr().String())
	closed, _ := net.Listen("tcp", "127.0.0.1:0")
	_, closedPort, _ := net.SplitHostPort(closed.Addr().String())
	closed.Close() // nothing listens here any more

	a := &App{state: "IDLE", results: newStore()}
	s := defaultSettings()
	s.OutputDir = t.TempDir()
	s.Mode = ModeCustom
	s.CustomPorts = port + "," + closedPort
	s.TargetsText = "127.0.0.1"
	s.TimeoutSecs = 3
	s.RetryCount = 0
	s.AutoConcurrency = false
	s.MaxConcurrent = 4
	s.StreamingAuto = false
	t.Setenv("APPDATA", t.TempDir()) // keep settings.json out of the real profile

	if err := a.StartScan(s); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(30 * time.Second)
	for a.GetStats().State != "STOPPED" {
		if time.Now().After(deadline) {
			t.Fatalf("scan did not finish: %+v", a.GetStats())
		}
		time.Sleep(100 * time.Millisecond)
	}

	st := a.GetStats()
	if st.Counts[TabAll] != 2 || st.Counts[TabOK] != 1 || st.Counts[TabDead] != 1 {
		t.Fatalf("counts = %v, want 1 reachable + 1 failed", st.Counts)
	}
	ok := a.QueryResults(Query{Tab: TabOK, Limit: 10})
	if ok.Total != 1 || ok.Rows[0].Status != 204 || strconv.Itoa(ok.Rows[0].Port) != port {
		t.Fatalf("reachable page = %+v", ok)
	}
	if found := a.QueryResults(Query{Tab: TabAll, Search: closedPort, Limit: 10}); found.Total != 1 || found.Rows[0].Error == "" {
		t.Fatalf("search for the closed port = %+v", found)
	}
	if a.StartScan(s) != nil {
		t.Fatal("a finished scan must allow a new one")
	}
	a.StopScan()
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
	t.Setenv("APPDATA", t.TempDir())
	want := defaultSettings()
	want.Mode, want.Theme = ModeDNS, "light"
	if err := saveSettings(want); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(settingsPath())
	if err := os.WriteFile(settingsPath(), append([]byte("\xef\xbb\xbf"), raw...), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := loadSettings(); got.Mode != ModeDNS || got.Theme != "light" {
		t.Fatalf("BOM-prefixed settings not loaded: mode=%s theme=%s", got.Mode, got.Theme)
	}
}
