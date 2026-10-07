package engine

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"sync/atomic"
	"time"
)

// Engine is the core scanner orchestrator.
type Engine struct {
	config  *ScanConfig
	handler ResultHandler

	state          string // RUNNING, PAUSED, STOPPED
	mu             sync.Mutex
	resumeChan     chan struct{}
	resumeOpen     bool
	activeRun      bool
	completionSent bool

	cancel          context.CancelFunc
	wg              sync.WaitGroup
	countWG         sync.WaitGroup
	streamWG        sync.WaitGroup
	knownTotal      atomic.Int64
	discoveredTotal atomic.Int64
	streamingRun    bool
	networkLimiter  *probeLimiter

	totalCount    int
	serviceClient *http.Client
	serviceSlots  chan struct{}
	dnsDialer     *net.Dialer
	dohClient     *http.Client
}

// NewEngine creates a new scanner engine instance.
func NewEngine(config *ScanConfig, handler ResultHandler) *Engine {
	return &Engine{
		config:     config,
		handler:    handler,
		state:      "STOPPED",
		resumeChan: make(chan struct{}),
		resumeOpen: true,
	}
}

// Start begins the scanning process.
// Blocks until all scans are finished or stopped.
func (e *Engine) Start() {
	e.mu.Lock()
	// Prevent concurrent starts
	if e.activeRun {
		e.mu.Unlock()
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	e.cancel = cancel
	e.state, e.activeRun, e.completionSent, e.totalCount = "RUNNING", true, false, 0
	e.mu.Unlock()
	e.handler.OnStateChange("RUNNING")
	e.knownTotal.Store(0)
	e.discoveredTotal.Store(0)
	e.streamingRun = false

	defer func() {
		cancel()
		e.countWG.Wait()
		e.streamWG.Wait()
		e.mu.Lock()
		missingCompletion := !e.completionSent
		e.state, e.activeRun, e.completionSent = "STOPPED", false, true
		e.mu.Unlock()
		if missingCompletion {
			e.handler.OnStateChange("STOPPED")
			e.handler.OnComplete(0, 0, e.totalCount)
		}
	}()
	configureDNSRateLimit(e.config)
	if err := e.config.ValidateAntiDPI(); err != nil {
		e.handler.OnStateChange("FATAL: " + err.Error())
		return
	}

	cachePath := resolvePath(e.config.OutputDir, e.config.CacheFile)
	inputPath := resolvePath(e.config.OutputDir, e.config.InputFile)
	if err := ValidateTargetFile(inputPath, e.config.TargetType); err != nil {
		e.handler.OnStateChange(fmt.Sprintf("FATAL: %v", err))
		return
	}
	if family := e.config.IPFamily; family == "ipv4" || family == "ipv6" {
		// Every scan path reads inputPath, so one filtered copy covers them all.
		filtered := filepath.Join(e.config.OutputDir, "targets_"+family+".txt")
		kept, dropped, err := filterTargetFamily(inputPath, filtered, family)
		if err != nil {
			e.handler.OnStateChange(fmt.Sprintf("FATAL: IP family filter: %v", err))
			return
		}
		if kept == 0 {
			e.handler.OnStateChange(fmt.Sprintf("FATAL: no %s targets in the input (%d of the other family were skipped)", map[string]string{"ipv4": "IPv4", "ipv6": "IPv6"}[family], dropped))
			return
		}
		inputPath = filtered
		e.logf("IP version %s: kept %d target lines, skipped %d", map[string]string{"ipv4": "IPv4", "ipv6": "IPv6"}[family], kept, dropped)
	} else if family != "" && family != "both" {
		e.handler.OnStateChange("FATAL: IP family must be ipv4, ipv6 or both")
		return
	}
	if e.config.DnsTxtMode {
		txtTargets, err := loadTxtResolverTargets(inputPath, e.config.DnsTxtResolversRaw)
		if err != nil {
			e.handler.OnStateChange(fmt.Sprintf("FATAL: TXT Resolver Parse Err: %v", err))
			return
		}
		if len(txtTargets) == 0 {
			e.handler.OnStateChange("FATAL: TXT Resolver list is empty")
			return
		}
		e.totalCount = e.dnsTotalForTargets(txtTargets)
		workers := e.resolveWorkerCount(len(txtTargets))
		e.networkLimiter = newProbeLimiter(workers, e.config.MinConcurrent, e.config.AutoConcurrency)
		e.startDnsTxtMode(ctx, txtTargets)
		return
	}
	var prioritized []Target
	// DNS reports cache protocol rows, not resolver targets; current inputs define probes.
	if !e.config.DnsDiscoveryMode {
		prioritized, _ = LoadCache(cachePath, false)
	}
	if e.config.TargetType != "" || e.config.IPFamily != "" {
		matching := prioritized[:0]
		for _, target := range prioritized {
			if e.config.TargetType != "" {
				if kind, err := TargetKind(target.URL); err != nil || kind != e.config.TargetType {
					continue
				}
			}
			if targetFamilyAllows(target.Host, e.config.IPFamily) {
				matching = append(matching, target)
			}
		}
		prioritized = matching
	}
	if len(prioritized) > 0 {
		e.logf("%d earlier passes from the cache are scanned first", len(prioritized))
	}
	if e.config.ProxyMode != "" {
		for i := range prioritized {
			prioritized[i] = normalizeProxyTarget(prioritized[i], e.config.ProxyMode)
		}
	}

	streamingEnabled := e.config.Streaming
	if e.config.StreamingAuto {
		large, _, err := IsLargeInput(inputPath, e.config.ScanAllPorts, e.config.CustomPorts, e.config.DnsDiscoveryMode, e.config.StreamingThreshold, e.config.StreamingSizeMB)
		if err == nil && large {
			streamingEnabled = true
		}
	}

	var targets []Target
	if !streamingEnabled {
		mainTargets, err := ParseTargets(
			inputPath,
			e.config.ScanAllPorts,
			e.config.CustomPorts,
			e.config.DnsDiscoveryMode,
		)
		if err != nil {
			e.handler.OnStateChange(fmt.Sprintf("FATAL: Target Parse Err: %v", err))
			return
		}

		if e.config.ProxyMode != "" {
			for i := range mainTargets {
				mainTargets[i] = normalizeProxyTarget(mainTargets[i], e.config.ProxyMode)
			}
		}
		targets = DeduplicateTargets(prioritized, mainTargets)
		e.totalCount = len(targets)
		if e.totalCount == 0 {
			e.handler.OnStateChange("FATAL: no valid targets were found in the input or cache")
			return
		}
		e.logf("Loaded %d targets (duplicates removed)", e.totalCount)
	}

	// Initialize shared high-capacity HTTP transport & client to support large concurrency
	// Tuned for many concurrent TCP connections across many hosts. We avoid per-worker
	// transports because that exhausts OS resources when scaled to thousands of goroutines.
	timeout := time.Duration(e.config.TimeoutSecs) * time.Second
	maxConns := e.resolveWorkerCount(e.totalCount)
	e.config.MaxConcurrent = maxConns
	e.networkLimiter = newProbeLimiter(maxConns, e.config.MinConcurrent, e.config.AutoConcurrency)
	if len(e.config.ProbeDomains) > 0 {
		e.initServiceClient()
		defer e.serviceClient.CloseIdleConnections()
	}
	if e.config.AutoConcurrency {
		e.logf("Automatic concurrency: up to %d workers", maxConns)
	} else {
		e.logf("Concurrency: %d workers", maxConns)
	}
	if len(e.config.ProbeDomains) > 0 && !e.config.SNIScan && e.config.ProxyMode == "" {
		e.logf("Each reachable endpoint is checked against %d service domains", len(e.config.ProbeDomains))
	}
	if maxConns < 100 {
		maxConns = 100
	}

	// Determine reasonable connection pool sizes derived from desired concurrency.
	// Keep caps to avoid unbounded allocations on small machines.
	maxIdle := maxConns * 4
	if maxIdle < 1000 {
		maxIdle = 1000
	}
	if maxIdle > 20000 {
		maxIdle = 20000
	}

	// Shared DNS dialer for UDP/TCP/DoT connections — used both by DNS probes
	// and by the HTTP transport's DialContext to ensure consistent socket options.
	sharedDialer := &net.Dialer{Timeout: timeout, KeepAlive: 30 * time.Second}
	e.dnsDialer = sharedDialer

	// Shared DoH client tuned for high concurrency — reuse same dialer
	dohTransport := &http.Transport{
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
		DisableKeepAlives:   false,
		MaxIdleConns:        maxIdle,
		MaxConnsPerHost:     maxConns,
		MaxIdleConnsPerHost: maxConns * 2,
		IdleConnTimeout:     90 * time.Second,
		TLSHandshakeTimeout: timeout / 2,
		ForceAttemptHTTP2:   false,
		DialContext:         sharedDialer.DialContext,
	}
	e.dohClient = &http.Client{Transport: dohTransport, Timeout: timeout}

	// If streaming ingestion is enabled, prefer streaming path to avoid
	// loading the entire target list in memory (helps with very large lists).
	if streamingEnabled {
		e.streamingRun = true
		e.logf("Large input: streaming targets from disk")
		if total, err := countStreamTargets(inputPath, prioritized, e.config.ScanAllPorts, e.config.CustomPorts, e.config.DnsDiscoveryMode, e.progressUnits); err == nil && total > 0 {
			e.knownTotal.Store(int64(total)) // the stream's exact count replaces it when queuing ends
			e.logf("%d %s to scan (overlapping ranges counted once)", total, e.progressNoun())
		}
		streamCh, err := e.targetStream(ctx, inputPath, prioritized)
		if err != nil {
			e.handler.OnStateChange(fmt.Sprintf("FATAL: Target Stream Err: %v", err))
			return
		}
		streamCh = e.trackTargets(ctx, streamCh)
		if e.config.CountTotal {
			countStream, countErr := e.targetStream(ctx, inputPath, prioritized)
			if countErr == nil {
				e.countTargetsInBackground(ctx, countStream)
			}
		}

		// ── DNS Discovery Mode (streaming) ──
		if e.config.DnsDiscoveryMode {
			e.startDnsDiscoveryStream(ctx, streamCh)
			return
		}

		// ── Standard HTTP Reachability Scan (streaming) ──
		e.startHttpScanStream(ctx, streamCh)
		return
	}

	// ── DNS Discovery Mode ──
	if e.config.DnsDiscoveryMode {
		e.totalCount = e.dnsTotalForTargets(targets)
		e.startDnsDiscovery(ctx, targets)
		return
	}

	// ── Standard HTTP Reachability Scan ──
	e.startHttpScan(ctx, targets)
}

// resolvePath joins a relative path onto dir; an absolute path is kept as is.
func resolvePath(dir, p string) string {
	if filepath.IsAbs(p) {
		return p
	}
	return filepath.Join(dir, p)
}

// configuredDialer returns the engine's shared DNS dialer or a default one.
func (e *Engine) configuredDialer() *net.Dialer {
	if e.dnsDialer != nil {
		return e.dnsDialer
	}
	return &net.Dialer{Timeout: time.Duration(e.config.TimeoutSecs) * time.Second}
}

// configuredDoHClient returns the engine's shared DoH HTTP client.
func (e *Engine) configuredDoHClient() *http.Client {
	if e.dohClient != nil {
		return e.dohClient
	}
	return &http.Client{Timeout: time.Duration(e.config.TimeoutSecs) * time.Second}
}

// startHttpScan runs the standard HTTP reachability scanning path.
func (e *Engine) startHttpScan(ctx context.Context, targets []Target) {
	// Use a bounded job buffer — avoid allocating a channel the size of all targets
	// when scanning millions of IPs across 13 ports.
	workers := e.resolveWorkerCount(len(targets))
	bufSize := workers * 8
	if bufSize > e.totalCount {
		bufSize = e.totalCount
	}
	if bufSize < 16 {
		bufSize = 16
	}
	jobs := make(chan Target, bufSize)
	results := make(chan ScanResult, bufSize*4)

	// Start workers
	for i := 0; i < workers; i++ {
		e.wg.Add(1)
		go e.scanWorker(ctx, jobs, results)
	}

	// Feed jobs in a separate goroutine so we don't block on a full channel
	go func() {
		defer close(jobs)
		for _, t := range targets {
			select {
			case jobs <- t:
			case <-ctx.Done():
				return
			}
		}
	}()

	// Collect results
	e.collectResults(ctx, results)
}

// startDnsDiscovery runs the DNS resolver discovery path.
// Each resolver IP is probed across 4 protocols, producing 4 results per target.
func (e *Engine) startDnsDiscovery(ctx context.Context, targets []Target) {
	// Initialize the Truth Table
	truth := NewTruthTable(e.config.TargetDomain)
	if err := truth.FetchTruthContext(ctx); err != nil {
		// Suppress raw stdout output to prevent UI tearing during engine start.
		// Integrity Verification falls back implicitly.
	}

	// In DNS mode, each resolver emits 2 or 4 results depending on the
	// configured protocol set.
	e.totalCount = e.dnsTotalForTargets(targets)

	workers := e.resolveWorkerCount(len(targets))
	bufSize := workers * 8
	if bufSize > len(targets) {
		bufSize = len(targets)
	}
	if bufSize < 16 {
		bufSize = 16
	}
	jobs := make(chan Target, bufSize)
	// Increase results buffer to handle multi-protocol bursts from each worker
	// Each worker can emit up to 4 results per job, so buffer should be at least 4x job buffer
	resultsBufSize := bufSize * 16
	if resultsBufSize < 256 {
		resultsBufSize = 256
	}
	results := make(chan ScanResult, resultsBufSize)

	// Start DNS workers
	for i := 0; i < workers; i++ {
		e.wg.Add(1)
		go e.dnsWorker(ctx, jobs, results, truth)
	}

	// Feed jobs
	go func() {
		defer close(jobs)
		for _, t := range targets {
			select {
			case jobs <- t:
			case <-ctx.Done():
				return
			}
		}
	}()

	// Collect results
	e.collectResults(ctx, results)
}

// startDnsTxtMode runs TXT resolver verification against the provided resolvers.
func (e *Engine) startDnsTxtMode(ctx context.Context, targets []Target) {
	e.totalCount = e.dnsTotalForTargets(targets)

	workers := e.resolveWorkerCount(len(targets))
	bufSize := workers * 8
	if bufSize > len(targets) {
		bufSize = len(targets)
	}
	if bufSize < 16 {
		bufSize = 16
	}
	jobs := make(chan Target, bufSize)
	resultsBufSize := bufSize * 16
	if resultsBufSize < 256 {
		resultsBufSize = 256
	}
	results := make(chan ScanResult, resultsBufSize)

	for i := 0; i < workers; i++ {
		e.wg.Add(1)
		go e.dnsWorker(ctx, jobs, results, nil)
	}

	go func() {
		defer close(jobs)
		for _, t := range targets {
			select {
			case jobs <- t:
			case <-ctx.Done():
				return
			}
		}
	}()

	e.collectResults(ctx, results)
}

// collectResults is the shared result collection loop used by both scan modes.
func (e *Engine) collectResults(ctx context.Context, results chan ScanResult) {
	var openResults []ScanResult
	var deadResults []ScanResult
	var poisonedResults []ScanResult
	doneCount := 0
	if total := e.progressTotal(); total > 0 {
		e.handler.OnProgress(0, total) // the total is shown before the first probe finishes
	}

	// Close results channel when all workers finish
	go func() {
		e.wg.Wait()
		close(results)
	}()

	for res := range results {
		if res.Error == "ABORTED" {
			continue
		}
		doneCount++

		e.handler.OnResult(&res)
		e.handler.OnProgress(doneCount, e.progressTotal())

		// Determine success based on the active scan mode:
		//   HTTP Reachability Mode: successful iff Error is empty.
		//   DNS Discovery Mode:     successful iff Error is empty AND the
		//                           resolver is NOT poisoned.
		//   TXT Resolver Mode:      successful iff Error is empty.
		// Poisoned DNS results are tracked separately so the summary/report counts
		// do not double count them as both dead and poisoned.
		isSuccess := res.Error == ""
		if e.config.DnsDiscoveryMode && !e.config.DnsTxtMode {
			isSuccess = isSuccess && !res.IsPoisoned
		}

		if isSuccess {
			openResults = append(openResults, res)
		} else {
			if e.config.DnsDiscoveryMode && !e.config.DnsTxtMode && res.IsPoisoned {
				poisonedResults = append(poisonedResults, res)
			} else {
				deadResults = append(deadResults, res)
			}
		}
	}
	e.countWG.Wait()
	if e.streamingRun {
		e.totalCount = e.progressTotal()
		if e.totalCount < doneCount {
			e.totalCount = doneCount
		}
		if e.totalCount == 0 {
			e.totalCount = int(e.discoveredTotal.Load())
		}
		e.handler.OnProgress(doneCount, e.totalCount)
	}

	e.mu.Lock()
	e.state = "STOPPED"
	e.mu.Unlock()
	e.handler.OnStateChange("STOPPED")

	timestamp := time.Now().Format("20060102_150405")
	openPath := fmt.Sprintf("reachable_%s.txt", timestamp)
	fullPath := fmt.Sprintf("full_log_%s.txt", timestamp)
	poisonedPath := fmt.Sprintf("poisoned_dns_%s.txt", timestamp)
	hijackedPath := fmt.Sprintf("hijacked_dns_%s.txt", timestamp)
	rawIPPath := fmt.Sprintf("raw_ip_dump_%s.txt", timestamp)
	tunnelPath := fmt.Sprintf("tunnel_ready_%s.txt", timestamp)
	headerPath := fmt.Sprintf("dns_headers_%s.txt", timestamp)
	debugPath := fmt.Sprintf("debug_count_%s.txt", timestamp)

	// Write debug counts
	debugFile := filepath.Join(e.config.OutputDir, debugPath)
	if f, err := os.Create(debugFile); err == nil {
		debugStr := fmt.Sprintf("Scan Results Debug Count\nGenerated: %s\n\n"+
			"Expected Total (totalCount): %d\n"+
			"Actually Collected: %d\n"+
			"  - Open Results: %d\n"+
			"  - Dead Results: %d\n"+
			"  - Poisoned Results: %d\n"+
			"  - Total Accounted: %d\n",
			time.Now().Format("2006-01-02 15:04:05"),
			e.totalCount,
			doneCount,
			len(openResults),
			len(deadResults),
			len(poisonedResults),
			len(openResults)+len(deadResults)+len(poisonedResults),
		)
		f.WriteString(debugStr)
		f.Close()
	}

	if err := WriteReports(e.config.OutputDir, openPath, fullPath, poisonedPath, hijackedPath, rawIPPath, tunnelPath, headerPath, e.config.CacheFile, openResults, deadResults, poisonedResults, e.totalCount); err != nil {
		e.handler.OnStateChange(fmt.Sprintf("ERROR: Report write failed: %v", err))
	}

	deadCount := len(deadResults)
	e.mu.Lock()
	e.completionSent = true
	e.mu.Unlock()
	e.handler.OnComplete(len(openResults), deadCount, e.totalCount)
}

// Pause puts the engine in a paused state.
func (e *Engine) Pause() {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.state == "RUNNING" {
		e.state = "PAUSED"
		e.handler.OnStateChange("PAUSED")
	}
}

// Resume wakes the engine from a paused state.
func (e *Engine) Resume() {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.state == "PAUSED" {
		e.state = "RUNNING"
		// close resume channel only if it's open
		if e.resumeOpen {
			close(e.resumeChan)
			e.resumeOpen = false
		}
		e.resumeChan = make(chan struct{})
		e.resumeOpen = true
		e.handler.OnStateChange("RUNNING")
	}
}

// Stop safely aborts all running workers and shuts down.
func (e *Engine) Stop() {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.state != "STOPPED" {
		e.state = "STOPPED"
		if e.cancel != nil {
			e.cancel()
		}
		if e.resumeOpen {
			close(e.resumeChan)
			e.resumeOpen = false
		}
		e.resumeChan = make(chan struct{})
		e.resumeOpen = true
		e.handler.OnStateChange("STOPPED")
	}
}

// startHttpScanStream runs the HTTP reachability scan using a streaming
// source of targets to avoid loading all targets in memory.
func (e *Engine) startHttpScanStream(ctx context.Context, stream <-chan Target) {
	// Use a bounded job buffer — avoid allocating a channel the size of all targets
	workers := e.resolveWorkerCount(0)
	bufSize := workers * 8
	if bufSize < 16 {
		bufSize = 16
	}
	jobs := make(chan Target, bufSize)
	results := make(chan ScanResult, bufSize*4)

	// Start workers
	for i := 0; i < workers; i++ {
		e.wg.Add(1)
		go e.scanWorker(ctx, jobs, results)
	}

	// Feed jobs from stream
	go func() {
		defer close(jobs)
		for t := range stream {
			select {
			case jobs <- t:
			case <-ctx.Done():
				return
			}
		}
	}()

	// Collect results
	e.collectResults(ctx, results)
}

// startDnsDiscoveryStream runs DNS discovery using a streaming source of targets.
func (e *Engine) startDnsDiscoveryStream(ctx context.Context, stream <-chan Target) {
	// Initialize the Truth Table
	truth := NewTruthTable(e.config.TargetDomain)
	if err := truth.FetchTruthContext(ctx); err != nil {
		// Suppress raw stdout output to prevent UI tearing during engine start.
		// Integrity Verification falls back implicitly.
	}

	workers := e.resolveWorkerCount(0)
	bufSize := workers * 8
	if bufSize < 16 {
		bufSize = 16
	}
	jobs := make(chan Target, bufSize)
	// Increase results buffer for multi-protocol DNS results
	resultsBufSize := bufSize * 16
	if resultsBufSize < 256 {
		resultsBufSize = 256
	}
	results := make(chan ScanResult, resultsBufSize)

	for i := 0; i < workers; i++ {
		e.wg.Add(1)
		go e.dnsWorker(ctx, jobs, results, truth)
	}

	go func() {
		defer close(jobs)
		for t := range stream {
			select {
			case jobs <- t:
			case <-ctx.Done():
				return
			}
		}
	}()

	e.collectResults(ctx, results)
}

// prependAndFilterStream emits prioritized targets first, and then
// streams remaining targets while skipping those already in the cache.
// It only tracks cache entries to avoid unbounded memory growth.
func prependAndFilterStream(prioritized []Target, stream <-chan Target) <-chan Target {
	return prependAndFilterStreamContext(context.Background(), prioritized, stream)
}

func prependAndFilterStreamContext(ctx context.Context, prioritized []Target, stream <-chan Target) <-chan Target {
	out := make(chan Target, 1024)
	go func() {
		defer close(out)
		seen := make(map[string]struct{}, len(prioritized))
		for _, t := range prioritized {
			if _, ok := seen[t.Key()]; ok {
				continue
			}
			seen[t.Key()] = struct{}{}
			select {
			case out <- t:
			case <-ctx.Done():
				return
			}
		}
		for t := range stream {
			if _, ok := seen[t.Key()]; ok {
				continue
			}
			seen[t.Key()] = struct{}{}
			select {
			case out <- t:
			case <-ctx.Done():
				return
			}
		}
	}()
	return out
}

// resolveWorkerCount picks a worker count based on config and target count.
func (e *Engine) resolveWorkerCount(targetCount int) int {
	maxW := e.config.MaxConcurrent
	if maxW <= 0 {
		maxW = 5000
	}
	minW := e.config.MinConcurrent
	if minW <= 0 {
		minW = 50
	}
	workers := maxW
	if e.config.AutoConcurrency {
		ideal := runtime.NumCPU() * 200
		if ideal < minW {
			ideal = minW
		}
		if ideal > maxW {
			ideal = maxW
		}
		workers = ideal
	}
	if targetCount > 0 && workers > targetCount {
		workers = targetCount
	}
	if workers < 1 {
		workers = 1
	}
	return workers
}

// dnsProgressUnitsPerResolver returns the number of progress events emitted
// per resolver in DNS discovery mode for the current configuration.
func dnsProgressUnitsPerResolver(cfg *ScanConfig) int {
	if cfg == nil {
		return 4
	}
	if len(cfg.CustomPorts) > 0 {
		units := len(cfg.CustomPorts) * 2
		if cfg.DnsTxtMode || !cfg.DnsUdpTcpOnly {
			for _, port := range cfg.CustomPorts {
				if port == 853 {
					units++
				}
				if port == 443 {
					units++
				}
			}
		}
		return units
	}
	if cfg.DnsTxtMode {
		return 4
	}
	if cfg.DnsUdpTcpOnly {
		return 2
	}
	return 4
}

// State returns the current engine state.
func (e *Engine) State() string {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.state
}

func (e *Engine) logf(format string, args ...any) {
	if l, ok := e.handler.(LogHandler); ok {
		l.OnLog(fmt.Sprintf(format, args...))
	}
}

func (e *Engine) progressNoun() string {
	if e.config.DnsDiscoveryMode || e.config.DnsTxtMode {
		return "probes"
	}
	return "targets"
}
