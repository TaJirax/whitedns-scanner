package engine

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"
)

// scanWorker processes targets from the jobs channel.
func (e *Engine) scanWorker(ctx context.Context, jobs <-chan Target, results chan<- ScanResult) {
	defer e.wg.Done()
	if len(e.config.ProbeDomains) > 0 && !e.config.SNIScan && e.config.ProxyMode == "" {
		e.serviceWorker(ctx, jobs, results)
		return
	}
	if e.config.ProxyMode != "" {
		e.proxyWorker(ctx, jobs, results)
		return
	}

	timeout := time.Duration(e.config.TimeoutSecs) * time.Second
	layerTimeout := max(timeout/2, 3*time.Second)

	for target := range jobs {
		func() {
			if !e.acquireProbe(ctx) {
				results <- ScanResult{Label: target.Label, URL: target.URL, Error: "ABORTED"}
				return
			}
			defer e.releaseProbe()
			// Respect PAUSED or STOPPED
			if !e.checkStateOrWait(ctx) {
				results <- ScanResult{Label: target.Label, URL: target.URL, Error: "ABORTED"}
				return
			}

			start := time.Now()
			scheme := target.Scheme
			if e.config.SNIScan {
				scheme = "https"
			}
			var status int
			var resolvedIP, errText string
			for attempt := 0; attempt <= e.config.RetryCount; attempt++ {
				if !e.checkStateOrWait(ctx) {
					errText = "ABORTED"
					break
				}
				status, resolvedIP, scheme, errText = e.probeEndpoint(ctx, target, scheme, layerTimeout, timeout)
				retry := errText == "HTTP_TIMEOUT" || e.config.LimitedNetwork && errText == "TLS_FAILED: timeout"
				if !retry { // a refused or filtered handshake fails the same way again
					break
				}
				time.Sleep(300 * time.Millisecond)
			}
			if errText == "FATAL_ERR" {
				time.Sleep(500 * time.Millisecond) // let the OS reclaim sockets
			}
			row := ScanResult{Label: target.Label, URL: target.URL, ResolvedIP: resolvedIP, Port: target.Port, Status: status, LatencyMs: int(time.Since(start).Milliseconds()), Error: errText}
			if errText == "" {
				row.URL = scheme + "://" + net.JoinHostPort(target.Host, strconv.Itoa(target.Port))
			}
			results <- row
		}()
	}
}

// ipProbeHost is the TLS name and HTTP Host for bare-IP targets outside SNI
// scan when no fronting domain is set. Real clients always send SNI and
// filtering networks silently drop ClientHellos without one, so an SNI-less
// handshake fails on every Cloudflare IP there. This is Cloudflare's own speed
// test host (the app's speed test default).
const ipProbeHost = "speed.cloudflare.com"

// endpointNames picks the TLS SNI and HTTP Host for a target: the forged SNI
// with the original target as Host in SNI scan, otherwise the domain itself,
// or for a bare IP the fronting domain (ipProbeHost when none is set), so a
// pass means that domain is reachable through the IP.
func (e *Engine) endpointNames(host string) (sni, hostHeader string) {
	switch {
	case e.config.SNIScan:
		return e.config.SpoofedSNI, host
	case net.ParseIP(host) == nil:
		return host, host
	case e.config.FrontingHost != "":
		return e.config.FrontingHost, e.config.FrontingHost
	default:
		return ipProbeHost, ipProbeHost
	}
}

// probeEndpoint runs DNS, TCP, TLS and one HTTP GET over a single connection
// and returns the HTTP status, the IP used, the scheme that answered and an
// error code ("" on success).
func (e *Engine) probeEndpoint(ctx context.Context, target Target, scheme string, layerTimeout, timeout time.Duration) (int, string, string, string) {
	sni, hostHeader := e.endpointNames(target.Host)
	probe, conn := preFlightConn(ctx, target.Host, target.Port, scheme, layerTimeout, sni, e.config)
	if probe.Status == "TLS_FAILED" && !e.config.SNIScan && !target.ExplicitScheme && !knownCFPort(target.Port) {
		// The scheme of this port was only a guess, so the other one may be right.
		if fallback, fallbackConn := preFlightConn(ctx, target.Host, target.Port, "http", layerTimeout, sni, e.config); fallback.Status == "PASSED" {
			probe, conn, scheme = fallback, fallbackConn, "http"
		}
	}
	if probe.ResourceLimited && e.networkLimiter != nil {
		e.networkLimiter.resourcePressure()
	}
	if probe.Status != "PASSED" {
		if probe.Status == "TLS_FAILED" && probe.Detail != "" {
			return 0, probe.ResolvedIP, scheme, "TLS_FAILED: " + probe.Detail
		}
		return 0, probe.ResolvedIP, scheme, probe.Status
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	_ = conn.SetDeadline(time.Now().Add(timeout))

	req, err := http.NewRequestWithContext(ctx, "GET", "http://"+bracketIPv6(hostHeader)+"/", nil)
	if err != nil {
		return 0, probe.ResolvedIP, scheme, "HTTP_REQ_ERR"
	}
	req.Host = hostHeader
	req.Close = true
	req.Header.Set("User-Agent", e.config.UserAgent)
	req.Header.Set("Accept", "text/html,application/xhtml+xml,*/*;q=0.9")
	req.Header.Set("Accept-Language", "en-US,en;q=0.5")
	if err := req.Write(conn); err != nil {
		return 0, probe.ResolvedIP, scheme, e.httpFailure(ctx, err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), req)
	if err != nil {
		return 0, probe.ResolvedIP, scheme, e.httpFailure(ctx, err)
	}
	resp.Body.Close()
	if e.config.FrontingHost != "" && hostHeader == e.config.FrontingHost && resp.StatusCode >= 500 {
		// The fronting domain is not served through this IP (a Worker error,
		// or an edge that does not carry it), as the full check also judges.
		return resp.StatusCode, probe.ResolvedIP, scheme, fmt.Sprintf("FRONTING_FAILED: HTTP %d from %s", resp.StatusCode, hostHeader)
	}
	return resp.StatusCode, probe.ResolvedIP, scheme, ""
}

func (e *Engine) httpFailure(ctx context.Context, err error) string {
	var ne net.Error
	switch {
	case ctx.Err() != nil:
		return "ABORTED"
	case isSocketExhaustion(err):
		e.reportResourceError(err)
		return "FATAL_ERR"
	case errors.As(err, &ne) && ne.Timeout():
		return "HTTP_TIMEOUT"
	}
	return "HTTP_ERR: " + truncErr(err)
}

// knownCFPort reports whether the scheme of port is known (Cloudflare's HTTPS
// and HTTP port lists). Falling back to plain HTTP on a known HTTPS port only
// proves TCP is open (Cloudflare answers "400 plain HTTP sent to HTTPS port"),
// so a blocked TLS handshake must stay a failure there.
func knownCFPort(port int) bool {
	return slices.Contains(CFHTTPSPorts, port) || slices.Contains(CFHTTPPorts, port)
}

// checkStateOrWait blocks if PAUSED, returns false if STOPPED/Context Done, true if RUNNING.
func (e *Engine) checkStateOrWait(ctx context.Context) bool {
	for {
		e.mu.Lock()
		state := e.state
		e.mu.Unlock()

		if state == "STOPPED" {
			return false
		}
		if state == "RUNNING" {
			return true
		}

		// PAUSED - Wait for signal or context cancellation
		select {
		case <-ctx.Done():
			return false
		case <-e.resumeChan:
			// Woke up, loop again to check state
		}
	}
}

// ════════════════════════════════════════════════════════════════════════════════
// DNS DISCOVERY WORKER
//
// Processes resolver IPs from the jobs channel, probes each across all 4
// DNS protocols (UDP/TCP/DoT/DoH), and emits one ScanResult per protocol.
// ════════════════════════════════════════════════════════════════════════════════

// classifyTunnel decides whether a resolver probe is suitable for DNS tunneling
// per the criteria: open recursion (RA=1) + EDNS0 large-payload support + TXT
// passthrough. Poisoning is intentionally NOT a disqualifier — a poisoning
// resolver can still carry a tunnel — it is reported separately. The returned
// reason lists what is missing so the report explains each verdict.
func classifyTunnel(pr DnsProbeResult, txtPassthrough bool) (bool, string) {
	if !pr.Responded {
		return false, "no-response"
	}
	var missing []string
	if pr.HeaderOK && !pr.Header.RA {
		missing = append(missing, "no-recursion(RA=0)")
	}
	if !pr.EDNS {
		missing = append(missing, "no-edns0")
	}
	if !txtPassthrough {
		missing = append(missing, "no-txt-passthrough")
	}
	if len(missing) == 0 {
		return true, "open-recursor+edns0+txt-passthrough"
	}
	return false, strings.Join(missing, ",")
}

// txtPassthrough checks, for each protocol that answered, whether the
// resolver also returns TXT rdata over that same protocol and port: the
// channel classic tunnels ride on, and dnstt runs over DoT and DoH as well as
// UDP. It queries a domain known to carry TXT records: the configured TXT base
// domain when set (which the operator may control), else the integrity
// TargetDomain.
func (e *Engine) txtPassthrough(ctx context.Context, resolverIP string, timeout time.Duration, probes []DnsProbeResult) []bool {
	ok := make([]bool, len(probes))
	txtDomain := strings.TrimSpace(e.config.DnsTxtDomain)
	if txtDomain == "" {
		txtDomain = e.config.TargetDomain
	}
	if txtDomain == "" {
		return ok
	}
	var checks []func() DnsProbeResult
	var rows []int
	for i, pr := range probes {
		if !pr.Responded {
			continue
		}
		port := dnsProtocolPort(pr.Protocol)
		var check func() DnsProbeResult
		switch {
		case strings.HasPrefix(pr.Protocol, "UDP"):
			check = func() DnsProbeResult {
				return DnsProbeTXTUDPWithDialer(ctx, resolverIP, txtDomain, timeout, e.configuredDialer(), port)
			}
		case strings.HasPrefix(pr.Protocol, "TCP"):
			check = func() DnsProbeResult {
				return DnsProbeTXTTCPWithDialer(ctx, resolverIP, txtDomain, timeout, e.configuredDialer(), port)
			}
		case strings.HasPrefix(pr.Protocol, "DoT"):
			check = func() DnsProbeResult {
				return DnsProbeTXTDoTWithDialer(ctx, resolverIP, txtDomain, timeout, e.configuredDialer(), port)
			}
		case strings.HasPrefix(pr.Protocol, "DoH"):
			check = func() DnsProbeResult {
				return DnsProbeTXTDoHWithClient(ctx, resolverIP, txtDomain, timeout, e.configuredDoHClient(), port)
			}
		default:
			continue
		}
		checks = append(checks, check)
		rows = append(rows, i)
	}
	for j, r := range runProbesConcurrently(checks) {
		ok[rows[j]] = r.Responded && len(r.AnswerTXT) > 0
	}
	return ok
}

// dnsProtocolPort maps DNS protocol names to their canonical port numbers.
func dnsProtocolPort(proto string) int {
	if idx := strings.LastIndex(proto, "/"); idx != -1 && idx < len(proto)-1 {
		if port, err := strconv.Atoi(proto[idx+1:]); err == nil && port > 0 {
			return port
		}
	}
	switch proto {
	case "UDP":
		return 53
	case "TCP":
		return 53
	case "DoT":
		return 853
	case "DoH":
		return 443
	default:
		return 0
	}
}

// dnsWorker processes resolver IP targets from the jobs channel.
// For each resolver, it runs all 4 protocol probes and emits results.
func (e *Engine) dnsWorker(ctx context.Context, jobs <-chan Target, results chan<- ScanResult, truth *TruthTable) {
	defer e.wg.Done()

	timeout := time.Duration(e.config.TimeoutSecs) * time.Second
	if e.config.DnsMaxPingMs > 0 {
		timeout = time.Duration(e.config.DnsMaxPingMs) * time.Millisecond
	}
	domain := e.config.TargetDomain

	for target := range jobs {
		func() {
			if !e.acquireProbe(ctx) {
				results <- ScanResult{Label: target.Label, URL: target.URL, Error: "ABORTED"}
				return
			}
			defer e.releaseProbe()
			// Respect PAUSED or STOPPED
			if !e.checkStateOrWait(ctx) {
				results <- ScanResult{Label: target.Label, URL: target.URL, Error: "ABORTED"}
				return
			}

			resolverIP := target.Host
			answerDomain := e.config.TargetDomain
			if e.config.DnsTxtMode {
				answerDomain = e.config.DnsTxtDomain
			}

			// Determine ports to probe: default to standard DNS behavior
			// (UDP/TCP on 53 + DoT 853 + DoH 443). Custom ports override only
			// when explicitly provided by the user.
			probePorts := e.config.CustomPorts
			if target.ExplicitPort {
				probePorts = []int{target.Port}
			}
			if len(probePorts) == 0 {
				probePorts = nil
			}

			var probeResults []DnsProbeResult
			if e.config.DnsTxtMode {
				probeResults = DnsProbeTXT(ctx, resolverIP, answerDomain, timeout, e.configuredDialer(), e.configuredDoHClient(), probePorts)
			} else {
				// Run the layered DNS probe. Respect DnsUdpTcpOnly config flag to optionally
				// restrict probes to UDP/TCP only (no DoT/DoH).
				probeResults = DnsProbe(ctx, resolverIP, domain, truth, timeout, e.configuredDialer(), e.configuredDoHClient(), probePorts, e.config.DnsUdpTcpOnly)
			}

			// In A-record mode we don't yet know whether the resolver forwards TXT
			// rdata intact (the channel classic tunnels ride on), so each protocol
			// that answered gets one extra TXT query. In TXT mode each probe
			// already carries its own passthrough signal.
			var txtPassthrough []bool
			if !e.config.DnsTxtMode {
				txtPassthrough = e.txtPassthrough(ctx, resolverIP, timeout, probeResults)
			}

			// Emit one ScanResult per protocol probe
			for i, pr := range probeResults {
				e.reportResourceError(fmt.Errorf("%s", pr.Error))
				port := dnsProtocolPort(pr.Protocol)
				answerIP := ""
				answerText := ""
				if len(pr.AnswerTXT) > 0 {
					answerText = pr.AnswerTXT[0]
				}
				if len(pr.AnswerIPs) > 0 {
					answerIP = pr.AnswerIPs[0]
					if answerText == "" {
						answerText = answerIP
					}
				}

				status := 0
				errStr := pr.Error
				if pr.Responded {
					status = 1 // 1 = responded (non-HTTP, so we use 1 as "alive")
				}

				if pr.IsPoisoned {
					if errStr == "" {
						errStr = "POISONED"
					} else {
						errStr = fmt.Sprintf("%s; POISONED", errStr)
					}
				}

				// Tunnel suitability: TXT mode probes self-report passthrough; A-mode
				// probes use the same-protocol passthrough check above.
				txtOK := pr.Responded && len(pr.AnswerTXT) > 0
				if !e.config.DnsTxtMode {
					txtOK = txtPassthrough[i]
				}
				tunnelReady, tunnelReason := classifyTunnel(pr, txtOK)

				hdrDump := ""
				if pr.HeaderOK {
					hdrDump = pr.Header.String()
				}

				results <- ScanResult{
					Label:        target.Label,
					URL:          fmt.Sprintf("dns://%s:%d", resolverIP, port),
					ResolvedIP:   answerIP,
					DnsAnswer:    answerText,
					Port:         port,
					Status:       status,
					LatencyMs:    int(pr.TTFB.Milliseconds()),
					Error:        errStr,
					DnsProtocol:  pr.Protocol,
					IsPoisoned:   pr.IsPoisoned,
					HdrValid:     pr.HeaderOK,
					HdrDump:      hdrDump,
					RA:           pr.Header.RA,
					TC:           pr.Header.TC,
					Rcode:        int(pr.Header.Rcode),
					Edns:         pr.EDNS,
					TunnelReady:  tunnelReady,
					TunnelReason: tunnelReason,
				}
			}
		}()
	}
}
