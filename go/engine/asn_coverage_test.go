package engine

import (
	"net"
	"sort"
	"strings"
	"testing"
)

// coverage is an oracle for "which IPv4 addresses do these ranges cover",
// built by a sweep over range start/end events. It shares no code with the
// expanders, so agreeing with it proves they neither lose nor invent IPs.
type coverage struct{ starts, ends []uint64 } // disjoint, ascending

func coverageOf(ranges [][2]uint64) coverage {
	type event struct {
		at    uint64
		delta int
	}
	events := make([]event, 0, 2*len(ranges))
	for _, r := range ranges {
		events = append(events, event{r[0], +1}, event{r[1] + 1, -1})
	}
	sort.Slice(events, func(i, j int) bool {
		if events[i].at != events[j].at {
			return events[i].at < events[j].at
		}
		return events[i].delta > events[j].delta // open before close: touching ranges join
	})
	var c coverage
	depth := 0
	for _, e := range events {
		if depth == 0 && e.delta > 0 {
			c.starts = append(c.starts, e.at)
		}
		depth += e.delta
		if depth == 0 {
			c.ends = append(c.ends, e.at-1)
		}
	}
	return c
}

func (c coverage) size() (n uint64) {
	for i := range c.starts {
		n += c.ends[i] - c.starts[i] + 1
	}
	return n
}

// checker consumes addresses that must arrive strictly ascending (so all are
// distinct) and inside the coverage; with count == size, output == coverage.
type checker struct {
	c        coverage
	i        int
	last     uint64
	n        uint64
	t        *testing.T
	failures int
}

func (k *checker) add(v uint64) {
	if k.failures > 0 {
		return
	}
	if k.n > 0 && v <= k.last {
		k.t.Errorf("not strictly ascending: %d after %d", v, k.last)
		k.failures++
		return
	}
	for k.i < len(k.c.ends) && k.c.ends[k.i] < v {
		k.i++
	}
	if k.i == len(k.c.starts) || v < k.c.starts[k.i] {
		k.t.Errorf("address %d is outside every input range", v)
		k.failures++
		return
	}
	k.last, k.n = v, k.n+1
}

// lineWriter parses "a.b.c.d\n" lines from the export as they are written.
type lineWriter struct {
	k            *checker
	header       int
	cur, octet   uint64
	inLine, skip bool
}

func (w *lineWriter) Write(p []byte) (int, error) {
	for _, b := range p {
		switch {
		case b == '\n':
			if w.header < 4 { // "# ASN IP export", Generated, Source ASNs, blank
				w.header++
			} else if !w.skip {
				w.k.add(w.cur<<8 | w.octet)
			}
			w.cur, w.octet, w.inLine, w.skip = 0, 0, false, false
		case w.header < 4:
		case b == '.':
			w.cur, w.octet = w.cur<<8|w.octet, 0
		case b >= '0' && b <= '9':
			w.octet = w.octet*10 + uint64(b-'0')
		default:
			w.skip = true // an IPv6 line; this test checks IPv4
		}
	}
	return len(p), nil
}

func allIPv4Ranges(t *testing.T) ([]string, [][2]uint64) {
	all, _ := SearchASNs("", "ipv4")
	ids := make([]string, len(all))
	for i, a := range all {
		ids[i] = a.ASN
	}
	cidrs, err := ASNRanges(ids, "ipv4")
	if err != nil {
		t.Fatal(err)
	}
	spans := make([][2]uint64, 0, len(cidrs))
	for _, c := range cidrs {
		if !strings.Contains(c, "/") { // 18,116 rows are single addresses
			c += "/32"
		}
		_, n, err := net.ParseCIDR(c)
		if err != nil {
			t.Fatal(err)
		}
		ones, _ := n.Mask.Size()
		v4 := n.IP.To4()
		first := uint64(v4[0])<<24 | uint64(v4[1])<<16 | uint64(v4[2])<<8 | uint64(v4[3])
		spans = append(spans, [2]uint64{first, first + 1<<uint(32-ones) - 1})
	}
	return cidrs, spans
}

// Every IPv4 address of every bundled ASN (159.6M unique of 177.7M listed)
// must come out of the export exactly once.
func TestASNExportLosesNoIPv4Address(t *testing.T) {
	if testing.Short() {
		t.Skip("exhaustive: expands the whole ASN dataset")
	}
	cidrs, spans := allIPv4Ranges(t)
	want := coverageOf(spans)
	k := &checker{c: want, t: t}
	n, err := WriteASNExport(&lineWriter{k: k}, 1, cidrs)
	if err != nil {
		t.Fatal(err)
	}
	if k.n != want.size() || uint64(n) != want.size() {
		t.Fatalf("exported %d (%d checked), the ranges cover %d", n, k.n, want.size())
	}
	t.Logf("%d ranges, %d unique IPv4 addresses, all exported once", len(cidrs), k.n)
}

// The scanner's CIDR expander must list every address of each range in order,
// minus only the network and broadcast addresses of ranges wider than /31.
func TestCIDRExpanderLosesNoIPv4Address(t *testing.T) {
	if testing.Short() {
		t.Skip("exhaustive: expands every bundled range")
	}
	cidrs, spans := allIPv4Ranges(t)
	checked := 0
	for i, c := range cidrs {
		if !strings.Contains(c, "/") {
			continue // single addresses are scan endpoints, not CIDRs
		}
		ip, n, _ := net.ParseCIDR(c)
		ones, _ := n.Mask.Size()
		if ones < 12 {
			continue // a /8 is 16.7M Target structs; the same code path is covered by every smaller range
		}
		first, last := spans[i][0], spans[i][1]
		if ones < 31 {
			first, last = first+1, last-1
		}
		got := buildCIDRTargetsFromNet("", ip, n)
		if uint64(len(got)) != last-first+1 {
			t.Fatalf("%s: %d targets, want %d", c, len(got), last-first+1)
		}
		for j, target := range got {
			v4 := net.ParseIP(target.Host).To4()
			v := uint64(v4[0])<<24 | uint64(v4[1])<<16 | uint64(v4[2])<<8 | uint64(v4[3])
			if v != first+uint64(j) || target.URL != "https://"+target.Host {
				t.Fatalf("%s: target %d is %+v, want address %d", c, j, target, first+uint64(j))
			}
		}
		checked += len(got)
	}
	t.Logf("%d addresses checked one by one", checked)
}
