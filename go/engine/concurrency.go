package engine

import (
	"context"
	"sync"
	"time"
)

// Admission changes never shorten active probes or change their retry rules.
type probeLimiter struct {
	mu                              sync.Mutex
	changed                         chan struct{}
	active, limit, minimum, maximum int
	automatic                       bool
	pressure, lastIncrease          time.Time
}

func newProbeLimiter(maximum, minimum int, automatic bool) *probeLimiter {
	if maximum < 1 {
		maximum = 1
	}
	if minimum < 1 {
		minimum = 1
	}
	if minimum > maximum {
		minimum = maximum
	}
	return &probeLimiter{changed: make(chan struct{}), limit: maximum, minimum: minimum, maximum: maximum, automatic: automatic}
}
func (p *probeLimiter) acquire(ctx context.Context) bool {
	for {
		if ctx.Err() != nil {
			return false
		}
		p.mu.Lock()
		if p.active < p.limit {
			p.active++
			p.mu.Unlock()
			return true
		}
		changed := p.changed
		p.mu.Unlock()
		select {
		case <-changed:
		case <-ctx.Done():
			return false
		}
	}
}
func (p *probeLimiter) signal() { close(p.changed); p.changed = make(chan struct{}) }
func (p *probeLimiter) release() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.active--
	now := time.Now()
	if p.automatic && p.limit < p.maximum && now.Sub(p.pressure) > 2*time.Second && now.Sub(p.lastIncrease) > time.Second {
		p.limit = min(p.maximum, p.limit+max(1, p.limit/8))
		p.lastIncrease = now
	}
	p.signal()
}
func (p *probeLimiter) resourcePressure() {
	if !p.automatic {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.pressure = time.Now()
	p.limit = max(p.minimum, p.limit*3/4)
	p.signal()
}
func (e *Engine) acquireProbe(ctx context.Context) bool {
	if e.networkLimiter == nil {
		return ctx.Err() == nil
	}
	return e.networkLimiter.acquire(ctx)
}
func (e *Engine) releaseProbe() {
	if e.networkLimiter != nil {
		e.networkLimiter.release()
	}
}
func (e *Engine) reportResourceError(err error) {
	if err != nil && e.networkLimiter != nil && isSocketExhaustion(err) {
		e.networkLimiter.resourcePressure()
	}
}
