package engine

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func testHTTPForwarder(t *testing.T) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	forwarded := &atomic.Int32{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		forwarded.Add(1)
		if r.Method == http.MethodConnect {
			upstream, err := net.DialTimeout("tcp", r.Host, time.Second)
			if err != nil {
				http.Error(w, err.Error(), 502)
				return
			}
			conn, _, err := w.(http.Hijacker).Hijack()
			if err != nil {
				upstream.Close()
				return
			}
			_, _ = conn.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n"))
			go func() { defer upstream.Close(); defer conn.Close(); _, _ = io.Copy(upstream, conn) }()
			_, _ = io.Copy(conn, upstream)
			return
		}
		if !r.URL.IsAbs() {
			http.Error(w, "absolute URL required", 400)
			return
		}
		req := r.Clone(r.Context())
		req.RequestURI = ""
		resp, err := http.DefaultTransport.RoundTrip(req)
		if err != nil {
			http.Error(w, err.Error(), 502)
			return
		}
		defer resp.Body.Close()
		for key, values := range resp.Header {
			for _, v := range values {
				w.Header().Add(key, v)
			}
		}
		w.WriteHeader(resp.StatusCode)
		_, _ = io.Copy(w, resp.Body)
	}))
	t.Cleanup(srv.Close)
	return srv, forwarded
}

func testSOCKSForwarder(t *testing.T, user, password string) (string, *atomic.Int32) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	forwarded := &atomic.Int32{}
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
				h := make([]byte, 2)
				if _, err := io.ReadFull(conn, h); err != nil {
					return
				}
				methods := make([]byte, int(h[1]))
				if _, err := io.ReadFull(conn, methods); err != nil {
					return
				}
				method := byte(0)
				if user != "" {
					method = 2
				}
				_, _ = conn.Write([]byte{5, method})
				if method == 2 {
					if _, err := io.ReadFull(conn, h); err != nil {
						return
					}
					u := make([]byte, int(h[1]))
					_, _ = io.ReadFull(conn, u)
					_, _ = io.ReadFull(conn, h[:1])
					p := make([]byte, int(h[0]))
					_, _ = io.ReadFull(conn, p)
					status := byte(0)
					if string(u) != user || string(p) != password {
						status = 1
					}
					_, _ = conn.Write([]byte{1, status})
					if status != 0 {
						return
					}
				}
				request := make([]byte, 4)
				if _, err := io.ReadFull(conn, request); err != nil {
					return
				}
				var host string
				switch request[3] {
				case 1:
					ip := make([]byte, 4)
					_, _ = io.ReadFull(conn, ip)
					host = net.IP(ip).String()
				case 4:
					ip := make([]byte, 16)
					_, _ = io.ReadFull(conn, ip)
					host = net.IP(ip).String()
				case 3:
					_, _ = io.ReadFull(conn, h[:1])
					name := make([]byte, int(h[0]))
					_, _ = io.ReadFull(conn, name)
					host = string(name)
				default:
					return
				}
				if _, err := io.ReadFull(conn, h); err != nil {
					return
				}
				port := binary.BigEndian.Uint16(h)
				upstream, err := net.DialTimeout("tcp", net.JoinHostPort(host, strconv.Itoa(int(port))), time.Second)
				if err != nil {
					_, _ = conn.Write([]byte{5, 1, 0, 1, 0, 0, 0, 0, 0, 0})
					return
				}
				defer upstream.Close()
				forwarded.Add(1)
				_, _ = conn.Write([]byte{5, 0, 0, 1, 127, 0, 0, 1, 0, 0})
				go func() { _, _ = io.Copy(upstream, conn); upstream.Close() }()
				_, _ = io.Copy(conn, upstream)
			}()
		}
	}()
	return listener.Addr().String(), forwarded
}

func runProxyWorker(t *testing.T, raw, kind, testURL string) ScanResult {
	t.Helper()
	parsed, err := parseBaseTargetsFromLine(raw)
	if err != nil {
		t.Fatal(err)
	}
	cfg := DefaultConfig()
	cfg.ProxyMode = kind
	cfg.ProxyTestURL = testURL
	cfg.RetryCount = 0
	cfg.TimeoutSecs = 2
	cfg.SpoofedSNI = "must-not-leak.example"
	eng := NewEngine(cfg, &sniResultHandler{})
	eng.state = "RUNNING"
	jobs := make(chan Target, 1)
	rows := make(chan ScanResult, 1)
	jobs <- parsed[0]
	close(jobs)
	eng.wg.Add(1)
	eng.scanWorker(context.Background(), jobs, rows)
	return <-rows
}

func TestProxyModesAndSpeedUseSelectedForwarder(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		_, _ = io.WriteString(w, strings.Repeat("payload", 4096))
	}))
	defer origin.Close()
	httpProxy, httpCount := testHTTPForwarder(t)
	socksAddress, socksCount := testSOCKSForwarder(t, "user", "pass")
	for _, tc := range []struct {
		kind, endpoint string
		counter        *atomic.Int32
	}{
		{"http", strings.TrimPrefix(httpProxy.URL, "http://"), httpCount},
		{"socks5", "socks5://user:pass@" + socksAddress, socksCount},
	} {
		t.Run(tc.kind, func(t *testing.T) {
			row := runProxyWorker(t, tc.endpoint, tc.kind, origin.URL)
			if row.Error != "" || row.Status != 200 || tc.counter.Load() < 1 {
				t.Fatalf("forwarding failed: %+v", row)
			}
			parsed, _ := parseBaseTargetsFromLine(tc.endpoint)
			before := tc.counter.Load()
			result, err := MeasureDownload(context.Background(), parsed[0], tc.kind, "must-not-leak.example", origin.URL, 2, 1<<20)
			if err != nil || result.Bytes != 7*4096 || result.DownloadMbps <= 0 || tc.counter.Load() <= before {
				t.Fatalf("speed result = %+v, %v", result, err)
			}
		})
	}
	if row := runProxyWorker(t, "socks5://wrong:password@"+socksAddress, "socks5", origin.URL); row.Error == "" {
		t.Fatal("wrong SOCKS credentials must fail")
	}
	if row := runProxyWorker(t, "127.0.0.1:1", "http", origin.URL); row.Error == "" {
		t.Fatal("closed proxy port must fail")
	}
}

func TestHTTPProxyCONNECTUsesOrdinaryTLS(t *testing.T) {
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(204) }))
	defer origin.Close()
	httpProxy, count := testHTTPForwarder(t)
	parsed, _ := parseBaseTargetsFromLine(httpProxy.URL)
	transport, err := EndpointTransport(parsed[0], "http", "must-not-leak.example", time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if transport.TLSClientConfig != nil && transport.TLSClientConfig.ServerName != "" {
		t.Fatal("forged SNI leaked into proxy transport")
	}
	transport.TLSClientConfig = origin.Client().Transport.(*http.Transport).TLSClientConfig.Clone()
	defer transport.CloseIdleConnections()
	resp, err := (&http.Client{Transport: transport, Timeout: 2 * time.Second}).Get(origin.URL)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 204 || count.Load() != 1 {
		t.Fatalf("CONNECT status %d, calls %d", resp.StatusCode, count.Load())
	}
}

func TestCleanIPDoesNotUseForgedSNI(t *testing.T) {
	names := make(chan string, 8)
	origin := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { names <- "Host " + r.Host; w.WriteHeader(204) }))
	origin.TLS = &tls.Config{GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) { names <- hello.ServerName; return nil, nil }}
	origin.StartTLS()
	defer origin.Close()
	host, rawPort, _ := net.SplitHostPort(origin.Listener.Addr().String())
	port, _ := strconv.Atoi(rawPort)
	// A bare IP fronts through the user's domain (SNI and Host), never the forged SNI.
	for fronting, want := range map[string]string{"": ipProbeHost, "my-worker.me.workers.dev": "my-worker.me.workers.dev"} {
		cfg := DefaultConfig()
		cfg.SpoofedSNI = "must-not-leak.example"
		cfg.FrontingHost = fronting
		cfg.TimeoutSecs = 2
		cfg.RetryCount = 0
		eng := NewEngine(cfg, &sniResultHandler{})
		eng.state = "RUNNING"
		jobs := make(chan Target, 1)
		rows := make(chan ScanResult, 1)
		jobs <- Target{Host: host, Label: host, Port: port, Scheme: "https"}
		close(jobs)
		eng.wg.Add(1)
		eng.scanWorker(context.Background(), jobs, rows)
		if row := <-rows; row.Error != "" || row.Status != 204 {
			t.Fatalf("clean IP failed: %+v", row)
		}
		if len(names) != 2 {
			t.Fatalf("want one handshake carrying TLS and the request, got %d events", len(names))
		}
		if sni, hostHeader := <-names, <-names; sni != want || hostHeader != "Host "+want {
			t.Fatalf("fronting %q: SNI %q, %s; want %q for both", fronting, sni, hostHeader, want)
		}
	}
}

func TestEndpointPortsAgreeAcrossInputPaths(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "targets.txt")
	inputs := "host.example:8080\n127.0.0.1:3128\n[::1]:1080\nhttps://example.com:8443/path\n127.0.0.1:8080\n"
	if err := os.WriteFile(file, []byte(inputs), 0600); err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseTargets(file, false, []int{80, 443}, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(parsed) != 5 {
		t.Fatalf("explicit endpoint ports were expanded or dropped: %+v", parsed)
	}
	stream, total, err := StreamTargets(file, false, []int{80, 443}, true, false)
	if err != nil {
		t.Fatal(err)
	}
	var streamed []Target
	for target := range stream {
		streamed = append(streamed, target)
	}
	if total != len(parsed) || !reflect.DeepEqual(parsed, streamed) {
		t.Fatalf("parsing/streaming mismatch: %d %+v", total, streamed)
	}
	if parsed[2].Host != "::1" || parsed[2].Port != 1080 {
		t.Fatal("IPv6 endpoint not preserved")
	}
	txt, err := loadTxtResolverTargets("", "1.1.1.1:1053, [::1]:2053, 192.0.2.0/31")
	if err != nil || len(txt) != 4 || txt[0].Port != 1053 || !txt[0].ExplicitPort {
		t.Fatalf("TXT custom endpoints: %+v %v", txt, err)
	}
	for _, input := range []string{"http://proxy.example", "https://proxy.example", "socks5://proxy.example", "udp://127.0.0.1:1053"} {
		endpoints, err := parseBaseTargetsFromLine(input)
		if err != nil || !endpoints[0].ExplicitPort {
			t.Fatalf("explicit URL %q: %+v %v", input, endpoints, err)
		}
	}
	cfg := DefaultConfig()
	cfg.DnsDiscoveryMode = true
	eng := NewEngine(cfg, &sniResultHandler{})
	a := Target{Port: 1053, ExplicitPort: true}
	b := Target{}
	if eng.dnsTotalForTargets([]Target{a, b}) != 6 {
		t.Fatal("mixed DNS progress must account for per-endpoint ports")
	}
	for _, bad := range []string{"https://example.com:99999", "example.com:0", "ftp://example.com", "example.com:"} {
		if _, err := parseBaseTargetsFromLine(bad); err == nil {
			t.Fatalf("accepted %q", bad)
		}
	}
	for _, bad := range []string{"https://example.com", "1.1.1.1", "a b.example"} {
		if ValidateSNI(bad) == nil {
			t.Fatalf("accepted SNI %q", bad)
		}
	}
}

func TestProxyCacheDoesNotDuplicateExplicitEndpoints(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "ok") }))
	defer origin.Close()
	address, _ := testSOCKSForwarder(t, "", "")
	for _, streaming := range []bool{false, true} {
		t.Run(strconv.FormatBool(streaming), func(t *testing.T) {
			cfg := DefaultConfig()
			cfg.OutputDir = t.TempDir()
			cfg.InputFile = filepath.Join(cfg.OutputDir, "targets.txt")
			cfg.ProxyMode = "socks5"
			cfg.ProxyTestURL = origin.URL
			cfg.CustomPorts = []int{1080}
			cfg.Streaming = streaming
			cfg.StreamingAuto = false
			cfg.AutoConcurrency = false
			cfg.MaxConcurrent = 1
			cfg.TimeoutSecs = 2
			cfg.RetryCount = 0
			if err := os.WriteFile(cfg.InputFile, []byte(address+"\n"), 0600); err != nil {
				t.Fatal(err)
			}
			for run := 0; run < 2; run++ {
				handler := &sniResultHandler{}
				NewEngine(cfg, handler).Start()
				if len(handler.rows) != 1 || handler.rows[0].Error != "" {
					t.Fatalf("run %d duplicate/failed proxy probes: %+v", run, handler.rows)
				}
			}
		})
	}
}

func TestCancelledInputStreamClosesWithoutConsumer(t *testing.T) {
	file := filepath.Join(t.TempDir(), "targets.txt")
	if err := os.WriteFile(file, []byte(strings.Repeat("127.0.0.1\n", 10000)), 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	stream, _, err := streamTargetsContext(ctx, file, false, nil, false, false)
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(10 * time.Millisecond)
	cancel()
	closed := make(chan struct{})
	go func() {
		for range stream {
		}
		close(closed)
	}()
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("cancelled producer did not close")
	}
}
