package engine

import (
	"context"
	"encoding/base64"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

type lifecycleHandler struct {
	states    chan string
	completed atomic.Int32
}

func (*lifecycleHandler) OnResult(*ScanResult) {}
func (*lifecycleHandler) OnProgress(int, int)  {}
func (h *lifecycleHandler) OnStateChange(state string) {
	if h.states != nil {
		h.states <- state
	}
}
func (h *lifecycleHandler) OnComplete(int, int, int) { h.completed.Add(1) }

func TestEngineCompletesEmptyAndInvalidInputs(t *testing.T) {
	for _, variant := range []string{"empty", "missing", "invalid-type"} {
		t.Run(variant, func(t *testing.T) {
			cfg := DefaultConfig()
			cfg.OutputDir = t.TempDir()
			cfg.InputFile = filepath.Join(cfg.OutputDir, "targets.txt")
			if variant != "missing" {
				text := "# empty\n"
				if variant == "invalid-type" {
					text = "example.test\n"
					cfg.TargetType = TargetIP
				}
				if err := os.WriteFile(cfg.InputFile, []byte(text), 0600); err != nil {
					t.Fatal(err)
				}
			}
			h := &lifecycleHandler{}
			engine := NewEngine(cfg, h)
			engine.Start()
			if engine.State() != "STOPPED" || h.completed.Load() != 1 {
				t.Fatalf("early exit left state=%s, completions=%d", engine.State(), h.completed.Load())
			}
		})
	}
}

func TestStopFromRunningNotificationAndPausedRestartGuard(t *testing.T) {
	for _, variant := range []string{"stop-immediately", "paused-restart"} {
		t.Run(variant, func(t *testing.T) {
			entered := make(chan struct{}, 2)
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { entered <- struct{}{}; <-r.Context().Done() }))
			defer srv.Close()
			cfg := DefaultConfig()
			cfg.OutputDir = t.TempDir()
			cfg.InputFile = filepath.Join(cfg.OutputDir, "targets.txt")
			cfg.StreamingAuto = false
			cfg.AutoConcurrency = false
			cfg.MaxConcurrent = 1
			cfg.RetryCount = 0
			cfg.TimeoutSecs = 3
			if err := os.WriteFile(cfg.InputFile, []byte(srv.URL+"\n"), 0600); err != nil {
				t.Fatal(err)
			}
			h := &lifecycleHandler{states: make(chan string, 16)}
			scanner := NewEngine(cfg, h)
			done := make(chan struct{})
			go func() { scanner.Start(); close(done) }()
			select {
			case state := <-h.states:
				if state != "RUNNING" {
					t.Fatal(state)
				}
			case <-time.After(time.Second):
				t.Fatal("missing running event")
			}
			if variant == "paused-restart" {
				select {
				case <-entered:
				case <-time.After(2 * time.Second):
					t.Fatal("request did not reach server")
				}
				scanner.Pause()
				restarted := make(chan struct{})
				go func() { scanner.Start(); close(restarted) }()
				select {
				case <-restarted:
				case <-time.After(time.Second):
					t.Fatal("a paused engine started a second concurrent run")
				}
				if scanner.State() != "PAUSED" {
					t.Fatal("second Start changed paused state")
				}
				scanner.Resume()
				if scanner.State() != "RUNNING" {
					t.Fatal("resume failed")
				}
			}
			scanner.Stop()
			select {
			case <-done:
			case <-time.After(time.Second):
				t.Fatal("Stop did not complete")
			}
			if h.completed.Load() != 1 {
				t.Fatalf("completion events=%d", h.completed.Load())
			}
		})
	}
}

func TestStopCancelsTruthTableSetup(t *testing.T) {
	entered := make(chan struct{}, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) { entered <- struct{}{}; <-r.Context().Done() }))
	defer srv.Close()
	old := trustedProviders
	trustedProviders = []trustedDoHProvider{{Name: "blocked", URL: srv.URL + "?name=%s"}}
	defer func() { trustedProviders = old }()
	cfg := DefaultConfig()
	cfg.OutputDir = t.TempDir()
	cfg.InputFile = filepath.Join(cfg.OutputDir, "targets.txt")
	cfg.DnsDiscoveryMode = true
	cfg.DnsUdpTcpOnly = true
	cfg.AutoConcurrency = false
	cfg.MaxConcurrent = 1
	cfg.StreamingAuto = false
	cfg.TargetDomain = "example.test"
	if err := os.WriteFile(cfg.InputFile, []byte("127.0.0.1:53535\n"), 0600); err != nil {
		t.Fatal(err)
	}
	h := &lifecycleHandler{states: make(chan string, 16)}
	scanner := NewEngine(cfg, h)
	done := make(chan struct{})
	go func() { scanner.Start(); close(done) }()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("truth request did not start")
	}
	scanner.Stop()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Stop waited for the truth provider timeout")
	}
}

func TestDoHIPv6AndQueryEncoding(t *testing.T) {
	for _, host := range []string{"127.0.0.1", "::1"} {
		t.Run(host, func(t *testing.T) {
			listener, err := net.Listen("tcp", net.JoinHostPort(host, "0"))
			if err != nil {
				t.Skipf("loopback unavailable: %v", err)
			}
			srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Host != listener.Addr().String() {
					t.Errorf("invalid resolver Host: %q", r.Host)
				}
				// RFC 8484: the query travels as base64url wire format.
				query, err := base64.RawURLEncoding.DecodeString(r.URL.Query().Get("dns"))
				if err != nil || r.Header.Get("Accept") != "application/dns-message" {
					t.Errorf("not an RFC 8484 request: %q %q", r.URL.RawQuery, r.Header.Get("Accept"))
				}
				var msg dnsmessage.Message
				if err := msg.Unpack(query); err != nil || len(msg.Questions) != 1 || msg.Header.ID != 0 {
					t.Errorf("bad wire query: %v %+v", err, msg.Header)
				} else if msg.Questions[0].Name.String() != "example.test&extra=1." {
					t.Errorf("query name was changed: %q", msg.Questions[0].Name.String())
				}
				w.Header().Set("Content-Type", "application/dns-message")
				_, _ = w.Write(dnsAnswer(query, "8.8.8.8", false))
			}))
			srv.Listener.Close()
			srv.Listener = listener
			srv.StartTLS()
			defer srv.Close()
			_, portText, _ := net.SplitHostPort(listener.Addr().String())
			var port int
			for _, digit := range portText {
				port = port*10 + int(digit-'0')
			}
			for _, txt := range []bool{false, true} {
				var result DnsProbeResult
				if txt {
					result = DnsProbeTXTDoHWithClient(context.Background(), host, "example.test&extra=1", time.Second, srv.Client(), port)
				} else {
					result = DnsProbeDoHWithClient(context.Background(), host, "example.test&extra=1", fixtureTruth(), time.Second, srv.Client(), port)
				}
				if !result.Responded || result.IsPoisoned || !result.Header.RA || !result.EDNS {
					t.Fatalf("DoH txt=%v: %+v", txt, result)
				}
				if txt && !strings.Contains(strings.Join(result.AnswerTXT, ""), "hello") {
					t.Fatal(result.AnswerTXT)
				}
			}
		})
	}
}
