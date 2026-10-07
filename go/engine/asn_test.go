package engine

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestASNTablesMatchTheAndroidSet(t *testing.T) {
	all, err := SearchASNs("", "")
	if err != nil {
		t.Fatal(err)
	}
	v4, _ := SearchASNs("", "ipv4")
	v6, _ := SearchASNs("", "ipv6")
	// cleanip-finder's bundled tables: 1,716 ASNs with IPv4, 292 with IPv6, 1,782 in all.
	if len(all) != 1782 || len(v4) != 1716 || len(v6) != 292 {
		t.Fatalf("ASN counts all=%d v4=%d v6=%d", len(all), len(v4), len(v6))
	}
	hit, _ := SearchASNs("58224", "")
	if len(hit) == 0 || hit[0].ASN != "AS58224" || hit[0].IPv4 == 0 {
		t.Fatalf("exact ASN must come first: %+v", hit[:min(len(hit), 1)])
	}
	if strings.Contains(hit[0].Type, `"`) {
		t.Fatalf("type kept a stray quote: %q", hit[0].Type)
	}
	ranges, err := ASNRanges([]string{"as58224"}, "ipv4")
	if err != nil || len(ranges) != hit[0].IPv4 {
		t.Fatalf("ranges: %d %v", len(ranges), err)
	}
	for _, r := range ranges {
		if ip, _, err := net.ParseCIDR(r); err != nil || ip.To4() == nil {
			t.Fatalf("not an IPv4 CIDR: %q", r)
		}
	}
	if _, err := ASNRanges([]string{"AS0"}, ""); err == nil {
		t.Fatal("unknown ASN accepted")
	}
}

func TestIPv6PrefixesAreSampledNotEnumerated(t *testing.T) {
	_, wide, _ := net.ParseCIDR("2001:db8::/32")
	targets := buildCIDRTargetsFromNet("", wide.IP, wide)
	if len(targets) != maxIPv6PerCIDR || countCIDRTargets(wide) != maxIPv6PerCIDR {
		t.Fatalf("a /32 must yield %d samples, got %d (count %d)", maxIPv6PerCIDR, len(targets), countCIDRTargets(wide))
	}
	if targets[0].URL != "https://[2001:db8::1]" || !wide.Contains(net.ParseIP(targets[len(targets)-1].Host)) {
		t.Fatalf("bad samples: %+v … %+v", targets[0], targets[len(targets)-1])
	}
	_, narrow, _ := net.ParseCIDR("2001:db8::/124")
	if got := buildCIDRTargetsFromNet("", narrow.IP, narrow); len(got) != 16 {
		t.Fatalf("a /124 is small enough to enumerate, got %d", len(got))
	}
}

func TestFilterTargetFamilyKeepsHostnames(t *testing.T) {
	dir := t.TempDir()
	src, dst := filepath.Join(dir, "in.txt"), filepath.Join(dir, "out.txt")
	os.WriteFile(src, []byte("1.1.1.1\n2606:4700::1111\n[2606:4700::1]:443\n104.16.0.0/24\n2001:db8::/48\nlabel | 8.8.8.8\nexample.com\nhttps://[2001:db8::2]/x\n# note\n"), 0o600)
	kept, dropped, err := filterTargetFamily(src, dst, "ipv6")
	if err != nil {
		t.Fatal(err)
	}
	out, _ := os.ReadFile(dst)
	want := "2606:4700::1111\n[2606:4700::1]:443\n2001:db8::/48\nexample.com\nhttps://[2001:db8::2]/x\n# note\n"
	if string(out) != want || kept != 5 || dropped != 3 {
		t.Fatalf("kept=%d dropped=%d out=%q", kept, dropped, out)
	}
}

func TestFastIPv4ExpansionMatchesNetIP(t *testing.T) {
	for _, v := range []uint32{0, 1, 255, 256, 0x0A000001, 0xC0A80101, 0xFFFFFFFF} {
		want := net.IPv4(byte(v>>24), byte(v>>16), byte(v>>8), byte(v)).String()
		if got := string(appendIPv4(nil, v)); got != want {
			t.Fatalf("appendIPv4(%d)=%q want %q", v, got, want)
		}
	}
	for cidr, want := range map[string][3]string{
		"10.0.0.0/24": {"254", "10.0.0.1", "10.0.0.254"}, // network and broadcast skipped
		"10.0.0.8/31": {"2", "10.0.0.8", "10.0.0.9"},
		"10.0.0.7/32": {"1", "10.0.0.7", "10.0.0.7"},
		"10.0.0.9/24": {"254", "10.0.0.1", "10.0.0.254"}, // host bits ignored
	} {
		ip, n, _ := net.ParseCIDR(cidr)
		got := buildCIDRTargetsFromNet("edge", ip, n)
		if fmt.Sprint(len(got)) != want[0] || got[0].Host != want[1] || got[len(got)-1].Host != want[2] {
			t.Fatalf("%s: %d targets %s..%s", cidr, len(got), got[0].Host, got[len(got)-1].Host)
		}
		if got[0].URL != "https://"+want[1] || got[0].Label != "edge "+want[1] || got[0].Port != 443 {
			t.Fatalf("%s: %+v", cidr, got[0])
		}
	}
}

func TestASNExportMergesOverlapsLikeAUniqueSet(t *testing.T) {
	var b strings.Builder
	n, err := WriteASNExport(&b, 2, []string{"10.0.0.0/30", "10.0.0.2/31", "10.0.0.4/32", "9.255.255.255", "2001:db8::/126", "2001:db8::/127"})
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(b.String()), "\n")
	if !strings.HasPrefix(lines[0], "# ASN IP export") || lines[2] != "# Source ASNs: 2" || lines[3] != "" {
		t.Fatalf("header: %q", lines[:4])
	}
	got := strings.Join(lines[4:], ",")
	want := "9.255.255.255,10.0.0.0,10.0.0.1,10.0.0.2,10.0.0.3,10.0.0.4,2001:db8::,2001:db8::1,2001:db8::2,2001:db8::3"
	if got != want || n != 10 {
		t.Fatalf("n=%d got %s", n, got)
	}
}
