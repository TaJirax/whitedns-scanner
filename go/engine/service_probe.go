package engine

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

type serviceRouteKey struct{}
type serviceOutcome struct {
	domain  string
	status  int
	passed  bool
	error   string
	latency int
}

func (e *Engine) serviceWorker(ctx context.Context, jobs <-chan Target, results chan<- ScanResult) {
	for target := range jobs {
		row := ScanResult{Label: target.Label, URL: target.URL, ResolvedIP: target.Host, Port: target.Port, ServiceTotal: len(e.config.ProbeDomains)}
		if !e.checkStateOrWait(ctx) {
			row.Error = "ABORTED"
			results <- row
			continue
		}
		start := time.Now()
		host := target.Host
		if net.ParseIP(host) == nil {
			lookup, cancel := context.WithTimeout(ctx, time.Duration(e.config.TimeoutSecs)*time.Second)
			ips, err := net.DefaultResolver.LookupHost(lookup, host)
			cancel()
			if err != nil || len(ips) == 0 {
				row.Error = "DNS_FAILED"
				results <- row
				continue
			}
			host = ips[0]
		}
		row.ResolvedIP = host
		address := net.JoinHostPort(host, strconv.Itoa(target.Port))
		// One TCP connect first, like the plain worker's pre-flight: a port that
		// refuses or ignores connections fails every service domain the same
		// way, so a dead endpoint costs one connect timeout instead of every
		// domain's timeouts and retries.
		if !e.acquireProbe(ctx) {
			row.Error = "ABORTED"
			results <- row
			continue
		}
		conn, err := (&net.Dialer{Timeout: max(time.Duration(e.config.TimeoutSecs)*time.Second/2, 3*time.Second)}).DialContext(ctx, "tcp", address)
		e.releaseProbe()
		if err != nil {
			e.reportResourceError(err)
			row.Error, row.LatencyMs = "TCP_FAILED", int(time.Since(start).Milliseconds())
			if ctx.Err() != nil {
				row.Error = "ABORTED"
			}
			results <- row
			continue
		}
		conn.Close()
		outcomes := make([]serviceOutcome, len(e.config.ProbeDomains))
		// All domains at once: a reachable IP whose blocked domains each time
		// out then costs one timeout, not one per batch. serviceSlots and the
		// probe limiter still bound the total.
		var wg sync.WaitGroup
		for i, domain := range e.config.ProbeDomains {
			wg.Add(1)
			go func(i int, domain string) {
				defer wg.Done()
				select {
				case e.serviceSlots <- struct{}{}:
				case <-ctx.Done():
					return
				}
				defer func() { <-e.serviceSlots }()
				if !e.acquireProbe(ctx) {
					return
				}
				defer e.releaseProbe()
				outcomes[i] = e.checkService(ctx, address, target.Scheme, domain)
			}(i, domain)
		}
		wg.Wait()
		if ctx.Err() != nil {
			row.Error = "ABORTED"
			results <- row
			continue
		}
		required := len(e.config.RequiredProbeDomains) == 0
		var passed, summary []string
		for _, outcome := range outcomes {
			if outcome.passed {
				row.ServicePassed++
				passed = append(passed, outcome.domain)
				if row.Status == 0 {
					row.Status = outcome.status
					row.URL = target.Scheme + "://" + net.JoinHostPort(target.Host, strconv.Itoa(target.Port))
				}
				for _, domain := range e.config.RequiredProbeDomains {
					if strings.EqualFold(domain, outcome.domain) {
						required = true
					}
				}
			}
			verdict := "failed: " + outcome.error
			if outcome.passed {
				verdict = fmt.Sprintf("passed (HTTP %d)", outcome.status)
			}
			summary = append(summary, outcome.domain+": "+verdict)
		}
		row.PassedDomains = strings.Join(passed, ",")
		row.ServiceSummary = strings.Join(summary, "\n")
		row.LatencyMs = int(time.Since(start).Milliseconds())
		if row.ServicePassed == 0 {
			row.Error = "no service domain passed"
		} else if !required {
			row.Error = "no fronting domain answered through this IP"
		}
		results <- row
	}
}

func (e *Engine) checkService(ctx context.Context, address, scheme, domain string) serviceOutcome {
	out := serviceOutcome{domain: domain}
	// A pool belongs to this candidate, port and original hostname only. Reuse
	// across retries cannot credit another candidate with an existing socket.
	client := *e.serviceClient
	if base, ok := client.Transport.(*http.Transport); ok {
		transport := base.Clone()
		transport.DisableKeepAlives = false
		transport.MaxIdleConns, transport.MaxIdleConnsPerHost = 1, 1
		transport.DialContext = antiDPIDial(func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{Timeout: time.Duration(e.config.TimeoutSecs) * time.Second}).DialContext(ctx, network, address)
		}, e.config)
		transport.TLSClientConfig = base.TLSClientConfig.Clone()
		transport.TLSClientConfig.ServerName = domain
		client.Transport = transport
		defer transport.CloseIdleConnections()
	}
	for attempt := 0; attempt <= e.config.RetryCount; attempt++ {
		if !e.checkStateOrWait(ctx) {
			out.error = "ABORTED"
			return out
		}
		probeCtx, cancel := context.WithTimeout(context.WithValue(ctx, serviceRouteKey{}, address), time.Duration(e.config.TimeoutSecs)*time.Second)
		req, err := http.NewRequestWithContext(probeCtx, http.MethodGet, scheme+"://"+domain+"/", nil)
		if err != nil {
			e.reportResourceError(err)
			cancel()
			out.error = err.Error()
			return out
		}
		req.Host = domain
		req.Header.Set("User-Agent", e.config.UserAgent)
		req.Header.Set("Accept-Encoding", "identity")
		started := time.Now()
		resp, err := client.Do(req)
		if err != nil {
			e.reportResourceError(err)
			cancel()
			out.error = err.Error()
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				return out // the TCP check passed, so a timeout is this domain being filtered: retrying waits again for nothing
			}
			continue
		}
		body, readErr := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
		resp.Body.Close()
		cancel()
		out.status = resp.StatusCode
		out.latency = int(time.Since(started).Milliseconds())
		if readErr != nil {
			out.error = readErr.Error()
			continue
		}
		certMatch := resp.TLS != nil && len(resp.TLS.PeerCertificates) > 0 && resp.TLS.PeerCertificates[0].VerifyHostname(domain) == nil
		lower := strings.ToLower(string(body))
		hardReject := false
		for _, pattern := range []string{"edge ip restricted", "direct ip access not allowed", "peyvandha.ir", "internet.ir", "no such application", "fastly error: unknown domain", "unavailable in your region"} {
			if strings.Contains(lower, pattern) {
				hardReject = true
			}
		}
		namedAnswer := strings.Contains(lower, strings.ToLower(domain))
		out.passed = (resp.StatusCode >= 200 && resp.StatusCode < 500) && (certMatch || namedAnswer && !hardReject)
		if out.passed {
			return out
		}
		out.error = fmt.Sprintf("HTTP %d without evidence for %s", resp.StatusCode, domain)
		return out
	}
	return out
}

func (e *Engine) initServiceClient() {
	dialer := &net.Dialer{Timeout: time.Duration(e.config.TimeoutSecs) * time.Second}
	transport := &http.Transport{DisableKeepAlives: true, TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, TLSHandshakeTimeout: time.Duration(e.config.TimeoutSecs) * time.Second}
	transport.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
		address, ok := ctx.Value(serviceRouteKey{}).(string)
		if !ok {
			return nil, fmt.Errorf("missing selected service endpoint")
		}
		return dialer.DialContext(ctx, network, address)
	}
	e.serviceClient = &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	slots := e.config.MaxConcurrent
	if slots < 1 {
		slots = 1
	}
	e.serviceSlots = make(chan struct{}, slots)
}

// SortedPassedDomains is used by reports without changing probe ordering.
func SortedPassedDomains(raw string) []string {
	domains := strings.FieldsFunc(raw, func(r rune) bool { return r == ',' })
	sort.Strings(domains)
	return domains
}
