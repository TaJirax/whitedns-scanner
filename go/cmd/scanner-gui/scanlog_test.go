package main

import "testing"

func TestScanLogText(t *testing.T) {
	for n, want := range map[int]string{0: "0", 999: "999", 1000: "1,000", 2495462: "2,495,462", -1234: "-1,234"} {
		if got := group(n); got != want {
			t.Fatalf("group(%d) = %q, want %q", n, got, want)
		}
	}
	if got := groupNumbers("2495462 targets, 1500 to 5000 workers, port 443"); got != "2,495,462 targets, 1,500 to 5,000 workers, port 443" {
		t.Fatal(got)
	}
	if level, text := resultLog(Row{IP: "2.144.5.29", Port: 443, Category: "dead", Error: "TCP_FAILED"}); level != "fail" || text != "Failed 2.144.5.29:443 · TCP_FAILED" {
		t.Fatal(level, text)
	}
	if level, text := resultLog(Row{IP: "2001:db8::1", Port: 443, Category: "ok", ServicePassed: 3, ServiceTotal: 9, LatencyMs: 312}); level != "ok" || text != "Passed [2001:db8::1]:443 · 3/9 service domains · 312 ms" {
		t.Fatal(level, text)
	}
}
