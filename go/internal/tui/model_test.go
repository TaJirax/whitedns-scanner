package tui

import (
	tea "github.com/charmbracelet/bubbletea"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reachability-scanner/engine"
	"strings"
	"testing"
	"time"
)

type quietHandler struct{}

func (quietHandler) OnResult(*engine.ScanResult) {}
func (quietHandler) OnProgress(int, int)         {}
func (quietHandler) OnStateChange(string)        {}
func (quietHandler) OnComplete(int, int, int)    {}

func TestTUIControlsAndPersianShortcuts(t *testing.T) {
	entered := make(chan struct{}, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) { entered <- struct{}{}; <-r.Context().Done() }))
	defer srv.Close()
	cfg := engine.DefaultConfig()
	cfg.OutputDir = t.TempDir()
	cfg.InputFile = filepath.Join(cfg.OutputDir, "targets.txt")
	cfg.AutoConcurrency = false
	cfg.MaxConcurrent = 1
	cfg.StreamingAuto = false
	cfg.RetryCount = 0
	cfg.TimeoutSecs = 2
	if err := os.WriteFile(cfg.InputFile, []byte(srv.URL+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	m := NewModel(cfg)
	m.engine = engine.NewEngine(cfg, quietHandler{})
	done := make(chan struct{})
	go func() { m.engine.Start(); close(done) }()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("scan did not start")
	}
	press := func(value string) {
		_, cmd := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(value)})
		if cmd != nil {
			cmd()
		}
	}
	for _, keys := range [][2]string{{"p", "r"}, {"ح", "ق"}} {
		press(keys[0])
		if m.engine.State() != "PAUSED" {
			t.Fatal("pause failed")
		}
		press(keys[1])
		if m.engine.State() != "RUNNING" {
			t.Fatal("resume failed")
		}
	}
	press("؟")
	if !m.help {
		t.Fatal("Persian help failed")
	}
	press("h")
	if m.help {
		t.Fatal("help toggle failed")
	}
	m.engine.Stop()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("stop did not finish")
	}
}

func TestTUIResultClassificationAndViews(t *testing.T) {
	for _, kind := range []string{"http", "dns", "txt"} {
		cfg := engine.DefaultConfig()
		cfg.DnsDiscoveryMode = kind == "dns"
		cfg.DnsTxtMode = kind == "txt"
		m := NewModel(cfg)
		rows := []*engine.ScanResult{{Label: "8.8.8.8", Status: 200, DnsProtocol: "UDP/53", DnsAnswer: "answer", ResolvedIP: "8.8.8.8"}, {Label: "bad", Status: 200, Error: "failed", DnsProtocol: "TCP/53"}}
		for _, row := range rows {
			m.Update(resultMsg{row})
		}
		if m.openCount != 1 || m.deadCount != 1 {
			t.Fatalf("%s counts open=%d dead=%d", kind, m.openCount, m.deadCount)
		}
		for _, size := range []tea.WindowSizeMsg{{Width: 40, Height: 14}, {Width: 90, Height: 30}, {Width: 140, Height: 50}} {
			m.Update(size)
			if m.View() == "" {
				t.Fatal("empty view")
			}
		}
		m.Update(progressMsg{1, 2})
		m.Update(stateMsg{"FATAL: test failure"})
		m.Update(completeMsg{1, 1, 2})
		if !strings.Contains(m.View(), "test failure") {
			t.Fatal("failure was hidden by completion")
		}
	}
}
