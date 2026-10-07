package engine

import "context"

// targetStream uses the same normalization and deduplication for counting and
// scanning, so background progress cannot count a different set of endpoints.
func (e *Engine) targetStream(ctx context.Context, path string, seed []Target) (<-chan Target, error) {
	stream, _, err := streamTargetsContext(ctx, path, e.config.ScanAllPorts, e.config.CustomPorts, false, e.config.DnsDiscoveryMode)
	if err != nil {
		return nil, err
	}
	if e.config.ProxyMode != "" {
		stream = normalizeProxyStream(ctx, stream, e.config.ProxyMode)
	}
	return prependAndFilterStreamContext(ctx, seed, stream), nil
}

func (e *Engine) progressUnits(target Target) int {
	if e.config.DnsDiscoveryMode || e.config.DnsTxtMode {
		return e.dnsUnits(target)
	}
	return 1
}

func (e *Engine) countTargetsInBackground(ctx context.Context, stream <-chan Target) {
	e.countWG.Add(1)
	go func() {
		defer e.countWG.Done()
		total := 0
		for target := range stream {
			if ctx.Err() != nil {
				return
			}
			total += e.progressUnits(target)
		}
		if ctx.Err() == nil {
			e.knownTotal.Store(int64(total))
		}
	}()
}

// Tracking does not expose a growing partial total as if it were final.
func (e *Engine) trackTargets(ctx context.Context, stream <-chan Target) <-chan Target {
	out := make(chan Target, 1024)
	e.streamWG.Add(1)
	go func() {
		defer e.streamWG.Done()
		defer close(out)
		for target := range stream {
			select {
			case out <- target:
				e.discoveredTotal.Add(int64(e.progressUnits(target)))
			case <-ctx.Done():
				return
			}
		}
		if ctx.Err() == nil {
			e.knownTotal.Store(e.discoveredTotal.Load())
			e.logf("All %d %s queued", e.discoveredTotal.Load(), e.progressNoun())
		}
	}()
	return out
}

func (e *Engine) progressTotal() int {
	if !e.streamingRun {
		return e.totalCount
	}
	return int(e.knownTotal.Load())
}
