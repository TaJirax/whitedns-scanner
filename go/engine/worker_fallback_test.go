package engine

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
)

// Plain HTTP on a port whose scheme was only guessed is a real answer; on an
// HTTPS port it only proves TCP is open, so the TLS failure must stand.
func TestHTTPFallbackOnlyWhenTheSchemeWasGuessed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNoContent) }))
	defer srv.Close()
	host, rawPort, _ := net.SplitHostPort(srv.Listener.Addr().String())
	port, _ := strconv.Atoi(rawPort)
	if knownCFPort(port) {
		t.Skipf("test port %d is a Cloudflare port", port)
	}
	for _, c := range []struct {
		name     string
		explicit bool
		ok       bool
	}{{"guessed scheme falls back", false, true}, {"explicit https stays failed", true, false}} {
		t.Run(c.name, func(t *testing.T) {
			cfg := DefaultConfig()
			cfg.TimeoutSecs, cfg.RetryCount = 2, 0
			eng := NewEngine(cfg, &sniResultHandler{})
			eng.state = "RUNNING"
			jobs, rows := make(chan Target, 1), make(chan ScanResult, 1)
			jobs <- Target{Host: host, Label: host, Port: port, Scheme: "https", URL: "https://" + host, ExplicitScheme: c.explicit}
			close(jobs)
			eng.wg.Add(1)
			eng.scanWorker(context.Background(), jobs, rows)
			row := <-rows
			if c.ok && (row.Error != "" || row.Status != http.StatusNoContent || !strings.HasPrefix(row.URL, "http://")) {
				t.Fatalf("fallback: %+v", row)
			}
			if !c.ok && !strings.HasPrefix(row.Error, "TLS_FAILED") {
				t.Fatalf("explicit https must not fall back: %+v", row)
			}
		})
	}
	if !knownCFPort(443) || !knownCFPort(8080) || knownCFPort(8000) {
		t.Fatal("Cloudflare port lists")
	}
}

// Through a fronting domain, a 5xx means the domain is not served via this IP.
func TestQuickFrontingRejectsServerErrors(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusInternalServerError) }))
	defer srv.Close()
	host, rawPort, _ := net.SplitHostPort(srv.Listener.Addr().String())
	port, _ := strconv.Atoi(rawPort)
	for fronting, wantErr := range map[string]string{"my-worker.me.workers.dev": "FRONTING_FAILED: HTTP 500", "": ""} {
		cfg := DefaultConfig()
		cfg.TimeoutSecs, cfg.RetryCount, cfg.FrontingHost = 2, 0, fronting
		eng := NewEngine(cfg, &sniResultHandler{})
		eng.state = "RUNNING"
		jobs, rows := make(chan Target, 1), make(chan ScanResult, 1)
		jobs <- Target{Host: host, Label: host, Port: port, Scheme: "https", URL: "https://" + host}
		close(jobs)
		eng.wg.Add(1)
		eng.scanWorker(context.Background(), jobs, rows)
		if row := <-rows; !strings.HasPrefix(row.Error, wantErr) || (wantErr == "") != (row.Error == "") {
			t.Fatalf("fronting %q: %+v", fronting, row)
		}
	}
}
