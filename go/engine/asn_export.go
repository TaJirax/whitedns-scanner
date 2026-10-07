package engine

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"strings"
	"time"
)

// WriteASNExport is the cleanip-finder TUI's "Export ASN IPs"
// (asnexport.ExportTargetsToTXT): a short header, then every IP of every range,
// one per line, with no cap. Improvements over the TUI:
//   - overlapping and duplicate ranges (common across neighbouring ASNs) are
//     merged first, so each IP is written once, in ascending order;
//   - IPv4 is written from integers into one reusable buffer, with no
//     per-address allocation;
//   - an IPv6 prefix wider than /120 lists the scanner's samples, because a /32
//     alone holds 2^96 addresses and the TUI's full sweep never finishes there.
//
// It returns how many IPs were written.
func WriteASNExport(w io.Writer, asnCount int, ranges []string) (int, error) {
	if len(ranges) == 0 {
		return 0, fmt.Errorf("no ASN targets selected")
	}
	var v4 []ipv4Span
	var v6 []string
	seenV6 := map[string]bool{}
	addV6 := func(s string) {
		if !seenV6[s] {
			seenV6[s] = true
			v6 = append(v6, s)
		}
	}
	for _, r := range ranges {
		r = strings.TrimSpace(r)
		if r == "" {
			continue
		}
		if !strings.Contains(r, "/") {
			ip := net.ParseIP(r)
			if ip == nil {
				return 0, fmt.Errorf("invalid range %q", r)
			}
			if ip.To4() != nil {
				r += "/32"
			} else {
				r += "/128"
			}
		}
		_, ipnet, err := net.ParseCIDR(r)
		if err != nil {
			return 0, fmt.Errorf("invalid range %q: %w", r, err)
		}
		if ipnet.IP.To4() != nil {
			first, last := ipv4Bounds(ipnet)
			v4 = append(v4, ipv4Span{first, last})
			continue
		}
		if ipv6Sampled(ipnet) {
			for _, h := range sampleIPv6CIDR(ipnet, maxIPv6PerCIDR) {
				addV6(h)
			}
			continue
		}
		for cur := ipnet.IP.Mask(ipnet.Mask); ipnet.Contains(cur); incIP(cur) {
			addV6(cur.String())
		}
	}
	merged := mergeIPv4Spans(v4)

	bw := bufio.NewWriterSize(w, 1<<20)
	fmt.Fprintln(bw, "# ASN IP export")
	fmt.Fprintln(bw, "# Generated:", time.Now().Format(time.RFC3339))
	fmt.Fprintln(bw, "# Source ASNs:", asnCount)
	fmt.Fprintln(bw)
	n := 0
	buf := make([]byte, 0, 16)
	for _, s := range merged {
		for u := s.first; u <= s.last; u++ {
			buf = append(appendIPv4(buf[:0], uint32(u)), '\n')
			if _, err := bw.Write(buf); err != nil {
				return n, err
			}
			n++
		}
	}
	for _, h := range v6 {
		if _, err := bw.WriteString(h + "\n"); err != nil {
			return n, err
		}
		n++
	}
	return n, bw.Flush()
}
