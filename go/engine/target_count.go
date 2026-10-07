package engine

import (
	"bufio"
	"net"
	"os"
	"sort"
	"strings"
)

// countStreamTargets is the progress total of a streaming run (targets, or
// probes in DNS modes as units reports them), worked out before scanning so
// progress has a total from the start. It dedupes by endpoint exactly as the stream
// does: IPv4 IPs and ranges as merged integer spans (overlapping ASN ranges
// count once, with no per-address memory), everything else in a set, and
// the cache seed, which is scanned first, is not counted again.
func countStreamTargets(path string, seed []Target, scanAllPorts bool, customPorts []int, dnsMode bool, units func(Target) int) (int, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	expand := func(t Target) []Target { return expandForMode(t, scanAllPorts, customPorts, dnsMode) }
	var spans []ipv4Span
	other := map[string]Target{} // by endpoint, as the stream dedupes
	addOther := func(t Target) {
		for _, x := range expand(t) {
			if _, ok := other[x.Key()]; !ok {
				other[x.Key()] = x
			}
		}
	}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		value := line
		if _, right, ok := strings.Cut(value, "|"); ok {
			value = strings.TrimSpace(right)
		}
		value = strings.Trim(value, "'\"")
		if strings.Contains(value, "/") && !strings.Contains(value, "://") {
			ip, ipnet, err := net.ParseCIDR(value)
			if err != nil {
				continue // the stream skips it too
			}
			if prefix, bits := ipnet.Mask.Size(); bits == 32 {
				first, last := ipv4Bounds(ipnet)
				if prefix < 31 {
					first, last = first+1, last-1 // as buildCIDRTargetsFromNet
				}
				spans = append(spans, ipv4Span{first, last})
				continue
			}
			for _, t := range buildCIDRTargetsFromNet("", ip, ipnet) { // IPv6: at most 256 samples
				addOther(t)
			}
			continue
		}
		if v, ok := ipv4Value(value); ok {
			spans = append(spans, ipv4Span{v, v}) // same target as that address inside a range
			continue
		}
		if parsed, err := parseBaseTargetsFromLine(line); err == nil {
			for _, base := range parsed {
				addOther(base)
			}
		}
	}
	if err := sc.Err(); err != nil {
		return 0, err
	}
	merged := mergeIPv4Spans(spans)
	// spanUnits reports whether the spans queue this endpoint, and its units there.
	spanUnits := func(t Target) (int, bool) {
		if v, ok := ipv4Value(t.Host); ok && inIPv4Spans(merged, v) {
			for _, x := range expand(addressTarget(t.Host)) {
				if x.Key() == t.Key() {
					return units(x), true
				}
			}
		}
		return 0, false
	}
	total := 0
	if len(merged) > 0 {
		perAddress := 0
		for _, x := range expand(addressTarget("192.0.2.1")) {
			perAddress += units(x)
		}
		for _, s := range merged {
			total += int(s.last-s.first+1) * perAddress
		}
	}
	for _, t := range other {
		if _, dup := spanUnits(t); !dup {
			total += units(t)
		}
	}
	seen := make(map[string]bool, len(seed))
	for _, t := range seed {
		if seen[t.Key()] {
			continue
		}
		seen[t.Key()] = true
		total += units(t)
		if n, dup := spanUnits(t); dup {
			total -= n // the input lists it too; the stream skips it
		} else if x, dup := other[t.Key()]; dup {
			total -= units(x)
		}
	}
	return total, nil
}

// addressTarget is the target buildCIDRTargetsFromNet makes for one address.
func addressTarget(host string) Target {
	return Target{Label: host, URL: "https://" + bracketIPv6(host), Host: host, Port: 443, Scheme: "https"}
}

func ipv4Value(s string) (uint64, bool) {
	ip := net.ParseIP(s)
	if ip == nil || !strings.Contains(s, ".") {
		return 0, false
	}
	v4 := ip.To4()
	if v4 == nil {
		return 0, false
	}
	return uint64(v4[0])<<24 | uint64(v4[1])<<16 | uint64(v4[2])<<8 | uint64(v4[3]), true
}

func inIPv4Spans(merged []ipv4Span, v uint64) bool {
	i := sort.Search(len(merged), func(i int) bool { return merged[i].last >= v })
	return i < len(merged) && merged[i].first <= v
}
