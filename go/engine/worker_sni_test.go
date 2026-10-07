package engine

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

type sniResultHandler struct{ rows []ScanResult }

func (h *sniResultHandler) OnResult(r *ScanResult) { h.rows = append(h.rows, *r) }
func (*sniResultHandler) OnProgress(int, int)      {}
func (*sniResultHandler) OnStateChange(string)     {}
func (*sniResultHandler) OnComplete(int, int, int) {}

// Both the preflight and the real HTTPS request must carry the forged SNI.
// A server that refuses any other ClientHello catches the old IP-dial bug.
func TestHTTPScanPreservesForgedSNI(t *testing.T) {
	for _, variant := range []string{"shared", "streaming", "worker-fallback", "ipv6"} {
		t.Run(variant, func(t *testing.T) {
			const forged = "forged.example"
			names := make(chan string, 16)
			hosts := make(chan string, 16)
			srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				hosts <- r.Host
				w.WriteHeader(http.StatusNoContent)
			}))
			if variant == "ipv6" {
				listener, err := net.Listen("tcp", "[::1]:0")
				if err != nil {
					srv.Close()
					t.Skipf("IPv6 loopback unavailable: %v", err)
				}
				srv.Listener.Close()
				srv.Listener = listener
			}
			srv.TLS = &tls.Config{GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
				names <- hello.ServerName
				if hello.ServerName != forged {
					return nil, fmt.Errorf("unexpected SNI %q", hello.ServerName)
				}
				return nil, nil
			}}
			srv.StartTLS()
			defer srv.Close()
			host, portText, err := net.SplitHostPort(srv.Listener.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			port, _ := strconv.Atoi(portText)
			if variant == "ipv6" {
				c, err := net.DialTimeout("tcp", net.JoinHostPort(host, portText), time.Second)
				if err != nil {
					t.Skipf("IPv6 loopback cannot be dialed: %v", err)
				}
				c.Close()
			}
			cfg := DefaultConfig()
			cfg.OutputDir = t.TempDir()
			cfg.InputFile = filepath.Join(cfg.OutputDir, "targets.txt")
			cfg.SpoofedSNI = forged
			cfg.SNIScan = true
			cfg.CustomPorts = []int{port}
			cfg.AutoConcurrency, cfg.StreamingAuto = false, false
			cfg.Streaming = variant == "streaming"
			cfg.MaxConcurrent, cfg.RetryCount, cfg.TimeoutSecs = 1, 0, 3
			if err := os.WriteFile(cfg.InputFile, []byte(host+"\n"), 0600); err != nil {
				t.Fatal(err)
			}
			handler := &sniResultHandler{}
			eng := NewEngine(cfg, handler)
			if variant == "worker-fallback" || variant == "ipv6" {
				eng.state = "RUNNING"
				jobs := make(chan Target, 1)
				results := make(chan ScanResult, 1)
				jobs <- Target{Label: host, Host: host, URL: "https://" + host, Scheme: "https", Port: port}
				close(jobs)
				eng.wg.Add(1)
				eng.scanWorker(context.Background(), jobs, results)
				handler.rows = append(handler.rows, <-results)
			} else {
				eng.Start()
			}
			if len(handler.rows) != 1 || handler.rows[0].Error != "" || handler.rows[0].Status != http.StatusNoContent {
				t.Fatalf("forged SNI HTTPS scan: %+v", handler.rows)
			}
			if len(names) != 1 {
				t.Fatalf("want one handshake carrying TLS and the request, got %d", len(names))
			}
			for len(names) > 0 {
				if got := <-names; got != forged {
					t.Fatalf("SNI = %q, want %q", got, forged)
				}
			}
			if len(hosts) != 1 {
				t.Fatalf("HTTP requests = %d, want 1", len(hosts))
			}
			if got := <-hosts; got != host {
				t.Fatalf("Host = %q, want original target %q", got, host)
			}
		})
	}
}
