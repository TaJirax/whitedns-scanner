package engine

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"golang.org/x/net/proxy"
)

func ValidateSNI(name string) error {
	name = strings.TrimSuffix(strings.TrimSpace(name), ".")
	if name == "" || len(name) > 253 || net.ParseIP(name) != nil || strings.ContainsAny(name, ":/ \\@") {
		return fmt.Errorf("enter an SNI hostname, without a URL, port or IP address")
	}
	for _, label := range strings.Split(name, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return fmt.Errorf("invalid SNI hostname %q", name)
		}
		for _, c := range label {
			if c != '-' && !(c >= 'a' && c <= 'z') && !(c >= 'A' && c <= 'Z') && !(c >= '0' && c <= '9') {
				return fmt.Errorf("invalid SNI hostname %q", name)
			}
		}
	}
	return nil
}

func ParseProbeURL(raw string) (*url.URL, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Hostname() == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return nil, fmt.Errorf("enter a complete http:// or https:// test URL")
	}
	return u, nil
}

// EndpointTransport routes every request through the selected endpoint.
// Proxy TLS always uses ordinary TLS; forged SNI belongs only to SNI scan.
func EndpointTransport(endpoint Target, kind, forged string, timeout time.Duration) (*http.Transport, error) {
	return EndpointTransportWithDPI(endpoint, kind, forged, timeout, nil)
}
func EndpointTransportWithDPI(endpoint Target, kind, forged string, timeout time.Duration, cfg *ScanConfig) (*http.Transport, error) {
	dialer := &net.Dialer{Timeout: timeout, KeepAlive: 30 * time.Second}
	transport := &http.Transport{DialContext: dialer.DialContext, TLSHandshakeTimeout: timeout, ResponseHeaderTimeout: timeout, MaxIdleConns: 4, IdleConnTimeout: 15 * time.Second}
	address := net.JoinHostPort(endpoint.Host, strconv.Itoa(endpoint.Port))
	switch kind {
	case "http", "http-proxy":
		scheme := "http"
		if endpoint.Scheme == "https" && endpoint.ExplicitScheme {
			scheme = "https"
		}
		p := &url.URL{Scheme: scheme, Host: address}
		if endpoint.Username != "" {
			p.User = url.UserPassword(endpoint.Username, endpoint.Password)
		}
		transport.Proxy = http.ProxyURL(p)
	case "socks5", "socks-proxy":
		var auth *proxy.Auth
		if endpoint.Username != "" {
			auth = &proxy.Auth{User: endpoint.Username, Password: endpoint.Password}
		}
		d, err := proxy.SOCKS5("tcp", address, auth, dialer)
		if err != nil {
			return nil, err
		}
		contextual, ok := d.(proxy.ContextDialer)
		if !ok {
			return nil, fmt.Errorf("SOCKS dialer does not support cancellation")
		}
		transport.DialContext = contextual.DialContext
	case "", "sni":
		transport.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
			return dialer.DialContext(ctx, network, address)
		}
		if kind == "sni" {
			transport.TLSClientConfig = &tls.Config{ServerName: forged, InsecureSkipVerify: true}
		}
	default:
		return nil, fmt.Errorf("unknown endpoint type %q", kind)
	}
	transport.DialContext = antiDPIDial(transport.DialContext, cfg)
	return transport, nil
}

func (e *Engine) proxyWorker(ctx context.Context, jobs <-chan Target, results chan<- ScanResult) {
	timeout := time.Duration(e.config.TimeoutSecs) * time.Second
	testURL := strings.TrimSpace(e.config.ProxyTestURL)
	if testURL == "" {
		testURL = "https://example.com/"
	}
	for target := range jobs {
		func() {
			if !e.acquireProbe(ctx) {
				results <- ScanResult{Label: target.Label, URL: target.URL, Error: "ABORTED"}
				return
			}
			defer e.releaseProbe()
			started := time.Now()
			scheme := "http"
			if e.config.ProxyMode == "socks5" {
				scheme = "socks5"
			} else if target.Scheme == "https" && target.ExplicitScheme {
				scheme = "https"
			}
			endpoint := &url.URL{Scheme: scheme, Host: net.JoinHostPort(target.Host, strconv.Itoa(target.Port))}
			if target.Username != "" {
				endpoint.User = url.UserPassword(target.Username, target.Password)
			}
			row := ScanResult{Label: target.Label, URL: endpoint.String(), ResolvedIP: target.Host, Port: target.Port, Kind: e.config.ModeID()}
			if !e.checkStateOrWait(ctx) {
				row.Error = "ABORTED"
				results <- row
				return
			}
			transport, err := EndpointTransportWithDPI(target, e.config.ProxyMode, "", timeout, e.config)
			if err != nil {
				e.reportResourceError(err)
				row.Error = err.Error()
				results <- row
				return
			}
			client := &http.Client{Transport: transport, Timeout: timeout}
			for attempt := 0; attempt <= e.config.RetryCount; attempt++ {
				if !e.checkStateOrWait(ctx) {
					row.Error = "ABORTED"
					break
				}
				req, err := http.NewRequestWithContext(ctx, http.MethodGet, testURL, nil)
				if err != nil {
					e.reportResourceError(err)
					row.Error = err.Error()
					break
				}
				req.Header.Set("User-Agent", e.config.UserAgent)
				resp, err := client.Do(req)
				if err != nil {
					e.reportResourceError(err)
					row.Error = err.Error()
					if ctx.Err() != nil {
						row.Error = "ABORTED"
						break
					}
					continue
				}
				row.Status = resp.StatusCode
				_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
				resp.Body.Close()
				if resp.StatusCode >= 200 && resp.StatusCode < 400 {
					row.Error = ""
				} else {
					row.Error = fmt.Sprintf("proxy test returned HTTP %d", resp.StatusCode)
				}
				break
			}
			transport.CloseIdleConnections()
			row.LatencyMs = int(time.Since(started).Milliseconds())
			results <- row
		}()
	}
}

type SpeedResult struct {
	DownloadMbps float64 `json:"downloadMbps"`
	Bytes        int64   `json:"bytes"`
	ElapsedS     float64 `json:"elapsedS"`
	LatencyMs    int64   `json:"latencyMs"`
	Endpoint     string  `json:"endpoint"`
	URL          string  `json:"url"`
}

// MeasureDownload never falls back to the system connection or a different IP.
func MeasureDownload(ctx context.Context, endpoint Target, kind, forged, rawURL string, seconds int, byteLimit int64) (SpeedResult, error) {
	return MeasureDownloadWithDPI(ctx, endpoint, kind, forged, rawURL, seconds, byteLimit, nil)
}
func MeasureDownloadWithDPI(ctx context.Context, endpoint Target, kind, forged, rawURL string, seconds int, byteLimit int64, cfg *ScanConfig) (SpeedResult, error) {
	u, err := ParseProbeURL(rawURL)
	if err != nil {
		return SpeedResult{}, err
	}
	if seconds < 1 || seconds > 60 || byteLimit < 1 || byteLimit > 1024<<20 {
		return SpeedResult{}, fmt.Errorf("use 1-60 seconds and at most 1024 MB")
	}
	ctx, cancel := context.WithTimeout(ctx, time.Duration(seconds)*time.Second)
	defer cancel()
	transport, err := EndpointTransportWithDPI(endpoint, kind, forged, time.Duration(seconds)*time.Second, cfg)
	if err != nil {
		return SpeedResult{}, err
	}
	defer transport.CloseIdleConnections()
	// A redirect could test a different origin; ask for a direct download URL.
	client := &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return SpeedResult{}, err
	}
	req.Header.Set("Accept-Encoding", "identity")
	req.Header.Set("Cache-Control", "no-cache")
	started := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		return SpeedResult{}, err
	}
	defer resp.Body.Close()
	latency := time.Since(started).Milliseconds()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return SpeedResult{}, fmt.Errorf("download URL returned HTTP %d; use a direct download URL", resp.StatusCode)
	}
	n, readErr := io.Copy(io.Discard, io.LimitReader(resp.Body, byteLimit))
	elapsed := time.Since(started).Seconds()
	if ctx.Err() == context.Canceled {
		return SpeedResult{}, fmt.Errorf("speed test cancelled")
	}
	if readErr != nil && ctx.Err() != context.DeadlineExceeded {
		return SpeedResult{}, readErr
	}
	if n == 0 {
		return SpeedResult{}, fmt.Errorf("download returned no data")
	}
	return SpeedResult{DownloadMbps: float64(n) * 8 / elapsed / 1e6, Bytes: n, ElapsedS: elapsed, LatencyMs: latency, Endpoint: net.JoinHostPort(endpoint.Host, strconv.Itoa(endpoint.Port)), URL: u.String()}, nil
}

func normalizeProxyTarget(t Target, kind string) Target {
	scheme := "http"
	if kind == "socks5" {
		scheme = "socks5"
	} else if t.Scheme == "https" && t.ExplicitScheme {
		scheme = "https"
	}
	endpoint := &url.URL{Scheme: scheme, Host: net.JoinHostPort(t.Host, strconv.Itoa(t.Port))}
	if t.Username != "" {
		endpoint.User = url.UserPassword(t.Username, t.Password)
	}
	t.Scheme, t.URL = scheme, endpoint.String()
	return t
}

func normalizeProxyStream(ctx context.Context, source <-chan Target, kind string) <-chan Target {
	out := make(chan Target, 1024)
	go func() {
		defer close(out)
		for t := range source {
			select {
			case out <- normalizeProxyTarget(t, kind):
			case <-ctx.Done():
				return
			}
		}
	}()
	return out
}
