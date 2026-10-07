package engine

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestProbeLimiterManualAndResourceRecovery(t *testing.T) {
	manual := newProbeLimiter(8, 2, false)
	manual.resourcePressure()
	if manual.limit != 8 {
		t.Fatal("manual concurrency changed")
	}
	auto := newProbeLimiter(8, 2, true)
	e := &Engine{networkLimiter: auto}
	e.reportResourceError(errors.New("remote request timeout"))
	if auto.limit != 8 {
		t.Fatal("remote timeout changed admission")
	}
	e.reportResourceError(errors.New("socket: too many open files"))
	if auto.limit != 6 {
		t.Fatalf("pressure limit %d", auto.limit)
	}
	for i := 0; i < 20; i++ {
		auto.resourcePressure()
	}
	if auto.limit != 2 {
		t.Fatalf("minimum not respected: %d", auto.limit)
	}
	auto.pressure = time.Now().Add(-3 * time.Second)
	if !auto.acquire(context.Background()) {
		t.Fatal("cannot acquire")
	}
	auto.release()
	if auto.limit != 3 {
		t.Fatal("automatic admission did not recover")
	}
}

func TestProbeLimiterBoundAndCancellation(t *testing.T) {
	p := newProbeLimiter(1, 1, false)
	if !p.acquire(context.Background()) {
		t.Fatal("first slot")
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan bool, 1)
	go func() { done <- p.acquire(ctx) }()
	select {
	case <-done:
		t.Fatal("exceeded limit")
	case <-time.After(20 * time.Millisecond):
	}
	cancel()
	select {
	case acquired := <-done:
		if acquired {
			t.Fatal("acquired after cancellation")
		}
	case <-time.After(time.Second):
		t.Fatal("cancellation blocked")
	}
	p.release()
	if p.acquire(ctx) {
		t.Fatal("cancelled context admitted")
	}
}

func TestStreamingProgressDoesNotPublishPartialTotal(t *testing.T) {
	for _, dns := range []bool{false, true} {
		cfg := DefaultConfig()
		cfg.DnsDiscoveryMode, cfg.DnsUdpTcpOnly = dns, dns
		e := NewEngine(cfg, nil)
		e.streamingRun = true
		in := make(chan Target)
		ctx, cancel := context.WithCancel(context.Background())
		out := e.trackTargets(ctx, in)
		in <- Target{Host: "127.0.0.1", Port: 53, ExplicitPort: true}
		<-out
		if e.progressTotal() != 0 {
			t.Fatal("partial total treated as exact")
		}
		close(in)
		for range out {
		}
		e.streamWG.Wait()
		want := 1
		if dns {
			want = 2
		}
		if e.progressTotal() != want {
			t.Fatalf("total=%d want %d", e.progressTotal(), want)
		}
		cancel()
	}
}
