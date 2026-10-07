package engine

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"syscall"
	"time"
)

// ProbeResult holds the outcome of the pre-flight layer checks.
type ProbeResult struct {
	Status          string // "PASSED", "DNS_FAILED", "TCP_FAILED", "TLS_FAILED", etc.
	ResolvedIP      string // The IP we actually connected to
	ResourceLimited bool   // scheduling signal; the result status is unchanged
	Detail          string // why TCP or TLS failed, for the report
}

// PreFlightLayerCheck performs DNS resolution, TCP SYN, and TLS checks.
// Critically: it resolves the domain to an IP first, then dials the *IP directly*,
// spoofing the SNI/ServerName to the chosen clean domain. This is the core DPI bypass mechanism.
func PreFlightLayerCheck(ctx context.Context, host string, port int, scheme string, timeout time.Duration, spoofedSNI string) ProbeResult {
	result, conn := preFlightConn(ctx, host, port, scheme, timeout, spoofedSNI, nil)
	if conn != nil {
		conn.Close()
	}
	return result
}

// preFlightConn resolves host, connects to the resolved IP and, for https,
// completes TLS with the given SNI. On PASSED it returns the open connection
// (TLS when https) for the caller's request, so a target costs one handshake.
func preFlightConn(ctx context.Context, host string, port int, scheme string, timeout time.Duration, sni string, cfg *ScanConfig) (ProbeResult, net.Conn) {
	if host == "" {
		return ProbeResult{Status: "PARSE_ERR"}, nil
	}

	// 1. DNS resolution (IP targets skip it)
	var resolvedIP string
	if ip := net.ParseIP(host); ip != nil {
		resolvedIP = ip.String()
	} else {
		dnsCtx, dnsCancel := context.WithTimeout(ctx, timeout)
		ips, err := net.DefaultResolver.LookupHost(dnsCtx, host)
		dnsCancel()
		if err != nil || len(ips) == 0 {
			return ProbeResult{Status: "DNS_FAILED"}, nil
		}
		resolvedIP = ips[0]
	}

	// 2. TCP to the resolved IP, not the name
	conn, err := (&net.Dialer{Timeout: timeout}).DialContext(ctx, "tcp", net.JoinHostPort(resolvedIP, fmt.Sprint(port)))
	if err != nil {
		return ProbeResult{Status: "TCP_FAILED", ResolvedIP: resolvedIP, ResourceLimited: isSocketExhaustion(err), Detail: truncErr(err)}, nil
	}
	if scheme != "https" {
		return ProbeResult{Status: "PASSED", ResolvedIP: resolvedIP}, conn
	}

	// 3. TLS on the same connection
	conn = wrapAntiDPI(ctx, conn, cfg)
	_ = conn.SetDeadline(time.Now().Add(timeout))
	tlsConn := tls.Client(conn, &tls.Config{ServerName: sni, InsecureSkipVerify: true})
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		conn.Close()
		if isSocketExhaustion(err) {
			return ProbeResult{Status: "FATAL_ERR", ResolvedIP: resolvedIP, ResourceLimited: true}, nil
		}
		return ProbeResult{Status: "TLS_FAILED", ResolvedIP: resolvedIP, Detail: tlsFailure(err)}, nil
	}
	_ = conn.SetDeadline(time.Time{})
	return ProbeResult{Status: "PASSED", ResolvedIP: resolvedIP}, tlsConn
}

// tlsFailure names how a handshake failed: a timeout or reset usually means
// the ClientHello was filtered; an alert means the server itself refused it.
func tlsFailure(err error) string {
	var ne net.Error
	switch {
	case errors.As(err, &ne) && ne.Timeout():
		return "timeout"
	case errors.Is(err, io.EOF), errors.Is(err, syscall.ECONNRESET), strings.Contains(err.Error(), "forcibly closed"), strings.Contains(err.Error(), "connection reset"):
		return "reset"
	}
	return truncErr(err)
}

// isSocketExhaustion checks if an error is caused by OS resource limits (EMFILE, ENFILE, etc.)
func isSocketExhaustion(err error) bool {
	if err == nil {
		return false
	}
	errStr := err.Error()
	// Common OS-level socket exhaustion messages across platforms
	for _, pattern := range []string{
		"too many open files",
		"socket: too many open files",
		"resource temporarily unavailable",
		"EMFILE",
		"ENFILE",
		"wsaemfile",
		"An operation on a socket could not be performed",
	} {
		if contains(errStr, pattern) {
			return true
		}
	}
	return false
}

// contains is a case-insensitive substring check.
func contains(s, substr string) bool {
	return len(s) >= len(substr) && searchInsensitive(s, substr)
}

func searchInsensitive(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		match := true
		for j := 0; j < len(substr); j++ {
			sc := s[i+j]
			pc := substr[j]
			if sc >= 'A' && sc <= 'Z' {
				sc += 32
			}
			if pc >= 'A' && pc <= 'Z' {
				pc += 32
			}
			if sc != pc {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}

// ════════════════════════════════════════════════════════════════════════════════
// DNS PROBE — Layered Multi-Protocol Check
//
// Runs all 4 protocol probes (UDP → TCP → DoT → DoH) independently against
// a single resolver IP. Returns all results so the TUI can display the full
// protocol compatibility map for each resolver.
// ════════════════════════════════════════════════════════════════════════════════

// DnsProbe executes a layered DNS probe across all 4 protocols.
// Each protocol is tested independently — no short-circuiting.
func DnsProbe(ctx context.Context, resolverIP string, domain string, truth *TruthTable, timeout time.Duration, dialer *net.Dialer, dohClient *http.Client, customPorts []int, dnsUdpTcpOnly bool) []DnsProbeResult {
	var probes []func() DnsProbeResult
	add := func(p func() DnsProbeResult) { probes = append(probes, p) }

	if len(customPorts) > 0 {
		for _, p := range customPorts {
			add(func() DnsProbeResult {
				return DnsProbeUDPWithDialer(ctx, resolverIP, domain, truth, timeout, dialer, p)
			})
			add(func() DnsProbeResult {
				return DnsProbeTCPWithDialer(ctx, resolverIP, domain, truth, timeout, dialer, p)
			})
			if !dnsUdpTcpOnly {
				if p == 853 {
					add(func() DnsProbeResult {
						return DnsProbeDoTWithDialer(ctx, resolverIP, domain, truth, timeout, dialer, p)
					})
				}
				if p == 443 {
					add(func() DnsProbeResult {
						return DnsProbeDoHWithClient(ctx, resolverIP, domain, truth, timeout, dohClient, p)
					})
				}
			}
		}
		return runProbesConcurrently(probes)
	}

	// Default behaviour
	add(func() DnsProbeResult {
		return DnsProbeUDPWithDialer(ctx, resolverIP, domain, truth, timeout, dialer, 53)
	})
	add(func() DnsProbeResult {
		return DnsProbeTCPWithDialer(ctx, resolverIP, domain, truth, timeout, dialer, 53)
	})
	if !dnsUdpTcpOnly {
		add(func() DnsProbeResult {
			return DnsProbeDoTWithDialer(ctx, resolverIP, domain, truth, timeout, dialer, 853)
		})
		add(func() DnsProbeResult {
			return DnsProbeDoHWithClient(ctx, resolverIP, domain, truth, timeout, dohClient, 443)
		})
	}
	return runProbesConcurrently(probes)
}

// runProbesConcurrently runs one resolver's protocol probes at the same time
// and returns their results in order. A dead resolver then costs one timeout
// instead of one per protocol.
func runProbesConcurrently(probes []func() DnsProbeResult) []DnsProbeResult {
	results := make([]DnsProbeResult, len(probes))
	var wg sync.WaitGroup
	for i, probe := range probes {
		wg.Add(1)
		go func() {
			defer wg.Done()
			results[i] = probe()
		}()
	}
	wg.Wait()
	return results
}
