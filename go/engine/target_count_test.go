package engine

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The upfront total must equal what the stream actually queues: overlapping
// ranges, bare IPs inside ranges and cached passes are each scanned once.
func TestCountStreamTargetsMatchesStream(t *testing.T) {
	path := filepath.Join(t.TempDir(), "targets.txt")
	input := "# ASN ranges overlap\n10.0.0.0/22\n10.0.1.0/24\n10.0.3.255\nedge | 10.0.2.7\n10.0.4.0/31\n10.0.4.1\n192.0.2.9/32\n2001:db8::/32\n2001:db8::/126\nhttps://example.com:8443\nhttp://198.51.100.1\nnot a target\n"
	if err := os.WriteFile(path, []byte(input), 0o644); err != nil {
		t.Fatal(err)
	}
	cached, _ := parseBaseTargetsFromLine("x | https://10.0.0.9:443") // the cache stores the port
	seed := []Target{addressTarget("10.0.1.5"), addressTarget("10.0.1.5"), addressTarget("203.0.113.1"), cached[0]}
	units := func(t Target) int { // DNS-style weights: explicit ports probe fewer protocols
		if t.ExplicitPort {
			return 2
		}
		return 3
	}
	for _, c := range []struct {
		name   string
		all    bool
		custom []int
		dns    bool
	}{{"default ports", false, nil, false}, {"all ports", true, nil, false}, {"custom ports", false, []int{443, 2053, 8080}, false}, {"dns", false, []int{53}, true}} {
		for _, weight := range []func(Target) int{func(Target) int { return 1 }, units} {
			stream, _, err := streamTargetsContext(context.Background(), path, c.all, c.custom, false, c.dns)
			if err != nil {
				t.Fatal(err)
			}
			want := 0
			for target := range prependAndFilterStreamContext(context.Background(), seed, stream) {
				want += weight(target)
			}
			got, err := countStreamTargets(path, seed, c.all, c.custom, c.dns, weight)
			if err != nil || got != want {
				t.Fatalf("%s: counted %d (%v), the stream queues %d", c.name, got, err, want)
			}
		}
	}
}

// A pass cached as "https://IP:443" is the same target as "https://IP" in the
// input, so a rescan probes it once, not twice.
func TestCachedPassIsNotScannedTwice(t *testing.T) {
	cached, _ := parseBaseTargetsFromLine("162.159.36.1 | https://162.159.36.1:443")
	input, _ := parseBaseTargetsFromLine("162.159.36.1")
	if got := DeduplicateTargets(cached, input); len(got) != 1 || !got[0].ExplicitPort {
		t.Fatalf("cached pass and input target were not merged: %+v", got)
	}
}

// Default Ports scans HTTPS 443 and plain HTTP 80; explicit ports, custom
// ports and DNS resolvers keep their own.
func TestDefaultPortsAreHTTPSAndHTTP(t *testing.T) {
	base, _ := parseBaseTargetsFromLine("104.16.0.1")
	var got []string
	for _, x := range expandForMode(base[0], false, nil, false) {
		got = append(got, x.URL)
	}
	if strings.Join(got, " ") != "https://104.16.0.1:443 http://104.16.0.1:80" || expansionFactor(false, nil, false) != 2 {
		t.Fatalf("default ports: %v", got)
	}
	explicit, _ := parseBaseTargetsFromLine("104.16.0.1:8443")
	if n := len(expandForMode(explicit[0], false, nil, false)); n != 1 {
		t.Fatalf("an explicit port was expanded into %d targets", n)
	}
	if n := len(expandForMode(base[0], false, []int{2053}, false)); n != 1 {
		t.Fatalf("custom ports: %d targets", n)
	}
	if n := len(expandForMode(base[0], false, nil, true)); n != 1 || expansionFactor(false, nil, true) != 1 {
		t.Fatalf("a DNS resolver was expanded into %d targets", n)
	}
}
