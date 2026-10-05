package engine

import (
	"context"
	"encoding/binary"
	"net"
	"testing"
	"time"
)

func TestDNSRateLimiterSpacing(t *testing.T) {
	if newDNSRateLimiter(0, 0, 1, 0) != nil {
		t.Fatal("no positive scope must disable the limiter")
	}
	now := time.Now()
	ms := time.Millisecond
	g := newDNSRateLimiter(5, 0, 1, 0)
	for i, want := range []time.Duration{0, 200 * ms, 400 * ms} {
		if got := g.schedule(now, "1.1.1.1"); got != want {
			t.Fatalf("slot %d: %v, want %v", i, got, want)
		}
	}
	r := newDNSRateLimiter(0, 5, 1, 0)
	r.schedule(now, "1.1.1.1")
	if got := r.schedule(now, "8.8.8.8"); got != 0 {
		t.Fatalf("other resolver delayed %v", got)
	}
	j := newDNSRateLimiter(5, 0, 1, 0.5)
	prev := time.Duration(0)
	for i := 0; i < 30; i++ {
		got := j.schedule(now, "")
		if gap := got - prev; i > 0 && (gap < 200*ms || gap > 300*ms) {
			t.Fatalf("jittered gap %v outside [200ms, 300ms]", gap)
		}
		prev = got
	}
}

// The wait must come before a probe's deadline: with 200ms between queries and
// a 50ms probe timeout, every probe still has to succeed.
func TestRateLimitWaitDoesNotEatProbeTimeout(t *testing.T) {
	pc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	go func() {
		buf := make([]byte, 1500)
		for {
			n, from, err := pc.ReadFromUDP(buf)
			if err != nil {
				return
			}
			if n < 12 {
				continue
			}
			// Header + question (OPT dropped) + one TXT answer "ok".
			q := 12
			for q < n && buf[q] != 0 {
				q += int(buf[q]) + 1
			}
			q += 5 // root label + QTYPE + QCLASS
			resp := append([]byte(nil), buf[:q]...)
			binary.BigEndian.PutUint16(resp[2:4], 0x8180) // QR RD RA, NOERROR
			binary.BigEndian.PutUint16(resp[6:8], 1)      // ANCOUNT
			binary.BigEndian.PutUint16(resp[10:12], 0)    // ARCOUNT
			resp = append(resp, 0xC0, 0x0C, 0, 16, 0, 1, 0, 0, 0, 60, 0, 3, 2, 'o', 'k')
			_, _ = pc.WriteToUDP(resp, from)
		}
	}()
	port := pc.LocalAddr().(*net.UDPAddr).Port

	activeDNSRateLimiter.Store(newDNSRateLimiter(5, 0, 1, 0))
	defer activeDNSRateLimiter.Store(nil)

	start := time.Now()
	for i := 0; i < 4; i++ {
		res := DnsProbeTXTUDPWithDialer(context.Background(), "127.0.0.1", "x.example.com", 50*time.Millisecond, nil, port)
		if !res.Responded {
			t.Fatalf("probe %d failed under rate limit: %s", i, res.Error)
		}
	}
	if elapsed := time.Since(start); elapsed < 550*time.Millisecond {
		t.Fatalf("4 queries at 5/s took %v, want >= 600ms", elapsed)
	}
}
