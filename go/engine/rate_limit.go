package engine

// rate_limit.go — optional cap on outgoing DNS probe queries, for networks
// that drop or block DNS above a fixed rate (Iran: about 6 queries/second).
// Without it a resolver scan sends thousands of queries at once, the firewall
// drops nearly all of them, and working resolvers are reported as dead.
//
// Same scheme as the CottenDNS client: each enabled scope (total, per resolver)
// spaces queries evenly; a probe waits for its slot, nothing is dropped. The
// wait happens before a probe's timeout starts, so waiting never counts
// against the resolver. Burst lets that many queries go back-to-back; jitter
// randomly lengthens each gap (never shortens it) so probes have no fixed rhythm.

import (
	"context"
	"math/rand/v2"
	"sync"
	"sync/atomic"
	"time"
)

type dnsRateLimiter struct {
	global, resolver time.Duration // gap per scope; 0 = scope off
	burst            int
	jitter           float64

	mu  sync.Mutex
	tat map[string]time.Time // theoretical arrival time per scope key
}

// activeDNSRateLimiter is set when a scan starts; nil = unlimited.
var activeDNSRateLimiter atomic.Pointer[dnsRateLimiter]

// configureDNSRateLimit applies the config's limits for the scan about to start.
func configureDNSRateLimit(cfg *ScanConfig) {
	activeDNSRateLimiter.Store(newDNSRateLimiter(
		cfg.DnsRateLimitPerSecond, cfg.DnsRateLimitPerResolverPerSecond,
		cfg.DnsRateLimitBurst, cfg.DnsTimingJitter))
}

func newDNSRateLimiter(perSecond, perResolverPerSecond float64, burst int, jitter float64) *dnsRateLimiter {
	if perSecond <= 0 && perResolverPerSecond <= 0 {
		return nil
	}
	return &dnsRateLimiter{
		global:   rateGap(perSecond),
		resolver: rateGap(perResolverPerSecond),
		burst:    max(burst, 1),
		jitter:   min(max(jitter, 0), 1),
		tat:      make(map[string]time.Time),
	}
}

func rateGap(perSecond float64) time.Duration {
	if perSecond <= 0 {
		return 0
	}
	return time.Duration(float64(time.Second) / perSecond)
}

// schedule claims the next slot for a query to resolverIP and returns how long
// to wait for it.
func (l *dnsRateLimiter) schedule(now time.Time, resolverIP string) time.Duration {
	scopes := [2]struct {
		key string
		gap time.Duration
	}{{"*", l.global}, {"r:" + resolverIP, l.resolver}}

	l.mu.Lock()
	defer l.mu.Unlock()
	sendAt := now
	for _, s := range scopes {
		if s.gap == 0 {
			continue
		}
		if allow := l.tat[s.key].Add(-time.Duration(l.burst-1) * s.gap); allow.After(sendAt) {
			sendAt = allow
		}
	}
	stretch := 1.0
	if l.jitter > 0 {
		stretch += rand.Float64() * l.jitter
	}
	for _, s := range scopes {
		if s.gap == 0 {
			continue
		}
		tat := l.tat[s.key]
		if tat.Before(sendAt) {
			tat = sendAt
		}
		l.tat[s.key] = tat.Add(time.Duration(float64(s.gap) * stretch))
	}
	return sendAt.Sub(now)
}

// waitDNSQuery blocks until one query to resolverIP may be sent. Call it right
// before a probe sets its deadline or dials. False if the scan was stopped.
func waitDNSQuery(ctx context.Context, resolverIP string) bool {
	l := activeDNSRateLimiter.Load()
	if l == nil {
		return true // unlimited: behave exactly as before
	}
	d := l.schedule(time.Now(), resolverIP)
	if d <= 0 {
		return ctx.Err() == nil
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return true
	case <-ctx.Done():
		return false
	}
}
