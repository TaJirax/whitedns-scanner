package engine

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"net"
	"net/http"
	"time"
)

// DnsProbeTXT executes TXT lookups against a resolver across the configured
// protocols. It mirrors the A-record path but does not compare answers against
// the truth table.
func DnsProbeTXT(ctx context.Context, resolverIP string, domain string, timeout time.Duration, dialer *net.Dialer, dohClient *http.Client, customPorts []int) []DnsProbeResult {
	var probes []func() DnsProbeResult
	add := func(p func() DnsProbeResult) { probes = append(probes, p) }
	queryName := buildTxtQueryName(domain)

	if len(customPorts) > 0 {
		for _, port := range customPorts {
			add(func() DnsProbeResult {
				return DnsProbeTXTUDPWithDialer(ctx, resolverIP, queryName, timeout, dialer, port)
			})
			add(func() DnsProbeResult {
				return DnsProbeTXTTCPWithDialer(ctx, resolverIP, queryName, timeout, dialer, port)
			})
			if port == 853 {
				add(func() DnsProbeResult {
					return DnsProbeTXTDoTWithDialer(ctx, resolverIP, queryName, timeout, dialer, port)
				})
			}
			if port == 443 {
				add(func() DnsProbeResult {
					return DnsProbeTXTDoHWithClient(ctx, resolverIP, queryName, timeout, dohClient, port)
				})
			}
		}
		return runProbesConcurrently(probes)
	}

	add(func() DnsProbeResult {
		return DnsProbeTXTUDPWithDialer(ctx, resolverIP, queryName, timeout, dialer, 53)
	})
	add(func() DnsProbeResult {
		return DnsProbeTXTTCPWithDialer(ctx, resolverIP, queryName, timeout, dialer, 53)
	})
	add(func() DnsProbeResult {
		return DnsProbeTXTDoTWithDialer(ctx, resolverIP, queryName, timeout, dialer, 853)
	})
	add(func() DnsProbeResult {
		return DnsProbeTXTDoHWithClient(ctx, resolverIP, queryName, timeout, dohClient, 443)
	})
	return runProbesConcurrently(probes)
}

// DnsProbeTXTUDPWithDialer sends a TXT query over UDP.
func DnsProbeTXTUDPWithDialer(ctx context.Context, resolverIP string, queryName string, timeout time.Duration, dialer *net.Dialer, port int) DnsProbeResult {
	result := DnsProbeResult{Protocol: fmt.Sprintf("UDP/%d", port)}

	hdr, txts, edns, ttfb, err := probeUDPWithFallback(ctx, resolverIP, queryName, 16, timeout, dialer, port)
	result.TTFB = ttfb
	if err != nil {
		result.Error = "UDP: " + err.Error()
		result.Header, result.HeaderOK = hdr, hdr.QR
		return result
	}

	result.Responded = true
	result.AnswerTXT = txts
	result.Header, result.HeaderOK, result.EDNS = hdr, true, edns
	return result
}

// DnsProbeTXTTCPWithDialer sends a TXT query over TCP.
func DnsProbeTXTTCPWithDialer(ctx context.Context, resolverIP string, queryName string, timeout time.Duration, dialer *net.Dialer, port int) DnsProbeResult {
	result := DnsProbeResult{Protocol: fmt.Sprintf("TCP/%d", port)}

	if !waitDNSQuery(ctx, resolverIP) {
		result.Error = "CANCELED"
		return result
	}
	query, txid := buildDnsQuery(queryName, 16, true)

	addr := net.JoinHostPort(resolverIP, fmt.Sprintf("%d", port))
	conn, err := probeDialer(dialer, timeout).DialContext(ctx, "tcp", addr)
	if err != nil {
		result.Error = "TCP_DIAL: " + truncErr(err)
		return result
	}
	defer conn.Close()
	stopCancel := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stopCancel()

	conn.SetDeadline(time.Now().Add(timeout))
	tcpMsg := make([]byte, 2+len(query))
	binary.BigEndian.PutUint16(tcpMsg[:2], uint16(len(query)))
	copy(tcpMsg[2:], query)

	if _, err := conn.Write(tcpMsg); err != nil {
		result.Error = "TCP_WRITE: " + truncErr(err)
		return result
	}

	start := time.Now()
	respBuf, err := readTCPResponse(conn)
	result.TTFB = time.Since(start)
	if err != nil {
		result.Error = "TCP_READ: " + truncErr(err)
		return result
	}

	hdr, txts, edns, err := parseDnsMessage(respBuf, 16, txid, true)
	if err != nil {
		result.Error = "TCP_PARSE: " + err.Error()
		result.Header, result.HeaderOK = hdr, hdr.QR
		return result
	}

	result.Responded = true
	result.AnswerTXT = txts
	result.Header, result.HeaderOK, result.EDNS = hdr, true, edns
	return result
}

// DnsProbeTXTDoTWithDialer sends a TXT query over DNS-over-TLS.
func DnsProbeTXTDoTWithDialer(ctx context.Context, resolverIP string, queryName string, timeout time.Duration, dialer *net.Dialer, port int) DnsProbeResult {
	result := DnsProbeResult{Protocol: fmt.Sprintf("DoT/%d", port)}

	if !waitDNSQuery(ctx, resolverIP) {
		result.Error = "CANCELED"
		return result
	}
	query, txid := buildDnsQuery(queryName, 16, true)

	addr := net.JoinHostPort(resolverIP, fmt.Sprintf("%d", port))
	tlsDialer := &tls.Dialer{NetDialer: probeDialer(dialer, timeout), Config: &tls.Config{InsecureSkipVerify: true}}
	tlsConn, err := tlsDialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		result.Error = "DoT_TLS: " + truncErr(err)
		return result
	}
	defer tlsConn.Close()
	stopCancel := context.AfterFunc(ctx, func() { _ = tlsConn.Close() })
	defer stopCancel()

	tlsConn.SetDeadline(time.Now().Add(timeout))
	tcpMsg := make([]byte, 2+len(query))
	binary.BigEndian.PutUint16(tcpMsg[:2], uint16(len(query)))
	copy(tcpMsg[2:], query)

	if _, err := tlsConn.Write(tcpMsg); err != nil {
		result.Error = "DoT_WRITE: " + truncErr(err)
		return result
	}

	start := time.Now()
	respBuf, err := readTCPResponse(tlsConn)
	result.TTFB = time.Since(start)
	if err != nil {
		result.Error = "DoT_READ: " + truncErr(err)
		return result
	}

	hdr, txts, edns, err := parseDnsMessage(respBuf, 16, txid, true)
	if err != nil {
		result.Error = "DoT_PARSE: " + err.Error()
		result.Header, result.HeaderOK = hdr, hdr.QR
		return result
	}

	result.Responded = true
	result.AnswerTXT = txts
	result.Header, result.HeaderOK, result.EDNS = hdr, true, edns
	return result
}

// DnsProbeTXTDoHWithClient sends a TXT query over DNS-over-HTTPS.
func DnsProbeTXTDoHWithClient(ctx context.Context, resolverIP string, queryName string, timeout time.Duration, client *http.Client, port int) DnsProbeResult {
	result := DnsProbeResult{Protocol: fmt.Sprintf("DoH/%d", port)}

	if !waitDNSQuery(ctx, resolverIP) {
		result.Error = "CANCELED"
		return result
	}
	hdr, txts, edns, ttfb, err := dohExchange(ctx, client, resolverIP, port, queryName, 16, timeout)
	result.TTFB = ttfb
	if err != nil {
		result.Error = "DoH_" + err.Error()
		result.Header, result.HeaderOK = hdr, hdr.QR
		return result
	}
	result.Responded = true
	result.AnswerTXT = txts
	result.Header, result.HeaderOK, result.EDNS = hdr, true, edns
	return result
}
