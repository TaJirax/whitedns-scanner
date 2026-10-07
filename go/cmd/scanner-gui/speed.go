package main

import (
	"context"
	"fmt"
	"net/url"
	"strings"

	"reachability-scanner/engine"
)

type SpeedRequest struct {
	RunDir       string `json:"runDir"`
	Seq          int    `json:"seq"`
	DownloadURL  string `json:"downloadUrl"`
	DurationSecs int    `json:"durationSecs"`
	MaxSizeMB    int    `json:"maxSizeMb"`
}

func (a *App) TestSpeed(request SpeedRequest) (engine.SpeedResult, error) {
	if request.DurationSecs < 1 || request.DurationSecs > 60 || request.MaxSizeMB < 1 || request.MaxSizeMB > 1024 {
		return engine.SpeedResult{}, fmt.Errorf("use 1-60 seconds and 1-1024 MB")
	}
	a.mu.Lock()
	if request.RunDir != a.run.Dir {
		a.mu.Unlock()
		return engine.SpeedResult{}, fmt.Errorf("the selected scan changed; select a result again")
	}
	if a.speedBusy {
		a.mu.Unlock()
		return engine.SpeedResult{}, fmt.Errorf("a speed test is already running")
	}
	a.results.mu.RLock()
	if request.Seq < 1 || request.Seq > len(a.results.rows) {
		a.results.mu.RUnlock()
		a.mu.Unlock()
		return engine.SpeedResult{}, fmt.Errorf("select a reachable result first")
	}
	row := a.results.rows[request.Seq-1]
	a.results.mu.RUnlock()
	if row.Error != "" || row.Protocol != "" {
		a.mu.Unlock()
		return engine.SpeedResult{}, fmt.Errorf("speed tests require a reachable IP or proxy result")
	}
	mode, settings := a.run.Mode, a.settings
	if a.run.TransportSaved {
		settings.AntiDPI, settings.DPIFragmentSize, settings.DPIFragmentDelayMs, settings.SpoofedSNI = a.run.AntiDPI, a.run.DPIFragmentSize, a.run.DPIFragmentDelayMs, a.run.SpoofedSNI
	}
	base := a.ctx
	if base == nil {
		base = context.Background()
	}
	ctx, cancel := context.WithCancel(base)
	a.speedCancel, a.speedBusy = cancel, true
	a.mu.Unlock()
	defer func() { cancel(); a.mu.Lock(); a.speedCancel = nil; a.speedBusy = false; a.mu.Unlock() }()
	host := row.IP
	if host == "" {
		host = row.Label
	}
	endpoint := engine.Target{Host: host, Port: row.Port}
	if u, err := url.Parse(row.URL); err == nil {
		endpoint.Scheme = u.Scheme
		// HTTPS proxy URLs represent TLS to the proxy; bare proxy inputs use HTTP.
		endpoint.ExplicitScheme = u.Scheme == "https" && row.Kind == ModeHTTPProxy
		if u.User != nil {
			endpoint.Username = u.User.Username()
			endpoint.Password, _ = u.User.Password()
		}
	}
	kind := row.Kind
	if kind == "" && (mode == ModeHTTPProxy || mode == ModeSOCKSProxy || mode == ModeSNI) {
		kind = mode
	}
	if strings.TrimSpace(request.DownloadURL) == "" {
		return engine.SpeedResult{}, fmt.Errorf("enter a download URL")
	}
	cfg := &engine.ScanConfig{AntiDPI: settings.AntiDPI, DPIFragmentSize: positive(settings.DPIFragmentSize, 64), DPIFragmentDelayMs: settings.DPIFragmentDelayMs, SNIScan: kind == ModeSNI}
	if err := cfg.ValidateAntiDPI(); err != nil {
		return engine.SpeedResult{}, err
	}
	return engine.MeasureDownloadWithDPI(ctx, endpoint, kind, settings.SpoofedSNI, request.DownloadURL, request.DurationSecs, int64(request.MaxSizeMB)<<20, cfg)
}

func (a *App) CancelSpeedTest() {
	a.mu.Lock()
	cancel := a.speedCancel
	a.mu.Unlock()
	if cancel != nil {
		cancel()
	}
}
