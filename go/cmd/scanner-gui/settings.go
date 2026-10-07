package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"reachability-scanner/engine"
)

// Scan modes, one page each, mirroring the CLI's menu.
const (
	ModeHTTP       = "http"       // default ports 443/80
	ModeHTTPAll    = "http-all"   // all 13 Cloudflare ports
	ModeCustom     = "custom"     // HTTP on custom ports
	ModeDNS        = "dns"        // resolver discovery over UDP/TCP/DoT/DoH
	ModeDNSUDPTCP  = "dns-udptcp" // resolver discovery, UDP/TCP only
	ModeSNI        = "sni"
	ModeHTTPProxy  = "http-proxy"
	ModeSOCKSProxy = "socks-proxy"
	ModeTXT        = "txt" // TXT lookups against a user domain
)

// modeFolders names each mode's folder under the output dir, so runs are
// sorted by mode and then by date.
var modeFolders = map[string]string{
	ModeHTTP:       "Default ports",
	ModeHTTPAll:    "All Cloudflare ports",
	ModeCustom:     "Custom ports",
	ModeDNS:        "DNS resolvers",
	ModeDNSUDPTCP:  "DNS UDP-TCP",
	ModeTXT:        "TXT probe",
	ModeSNI:        "SNI scan",
	ModeHTTPProxy:  "HTTP proxy",
	ModeSOCKSProxy: "SOCKS proxy",
}

// ModeTargets are the inputs each mode page keeps for itself: a domain list
// and a resolver list are never mixed up between pages.
type TargetInput struct {
	ServiceChecks       bool      `json:"serviceChecks,omitempty"`
	PlatformDomainsText string    `json:"platformDomainsText,omitempty"`
	TimeoutSecs         int       `json:"timeoutSecs,omitempty"`
	RetryCount          *int      `json:"retryCount,omitempty"`
	UserAgent           string    `json:"userAgent,omitempty"`
	InputFile           string    `json:"inputFile"`
	TargetsText         string    `json:"targetsText"`
	CustomPorts         string    `json:"customPorts"`
	IPFamily            string    `json:"ipFamily,omitempty"` // "" (both), ipv4 or ipv6
	ASNs                []ASNPick `json:"asns,omitempty"`
}

// ASNPick is a network added from the ASN list. Its ranges are expanded only
// when the scan starts, so a large network (Cloudflare has 26,000 ranges)
// never sits in the page as text.
type ASNPick struct {
	ASN    string `json:"asn"`
	Name   string `json:"name,omitempty"`
	Family string `json:"family,omitempty"` // ipv4, ipv6 or both
	Ranges int    `json:"ranges,omitempty"`
}

type ModeTargets struct {
	EdgeProvider string                 `json:"edgeProvider,omitempty"`
	EdgeInputs   map[string]TargetInput `json:"edgeInputs,omitempty"`
	TargetType   string                 `json:"targetType,omitempty"`
	Inputs       map[string]TargetInput `json:"inputs,omitempty"`
	InputFile    string                 `json:"inputFile"`
	TargetsText  string                 `json:"targetsText"` // pasted; used instead of InputFile when set
	CustomPorts  string                 `json:"customPorts"` // "80,443,8000-8010"
	IPFamily     string                 `json:"ipFamily,omitempty"`
	ASNs         []ASNPick              `json:"asns,omitempty"`
}

// Settings is everything the GUI lets the user change, saved per user.
type Settings struct {
	AntiDPI            bool                   `json:"antiDpi"`
	DPIFragmentSize    int                    `json:"dpiFragmentSize"`
	DPIFragmentDelayMs int                    `json:"dpiFragmentDelayMs"`
	Accent             string                 `json:"accent"`
	SpeedTestURL       string                 `json:"speedTestUrl"`
	SpeedDurationSecs  int                    `json:"speedDurationSecs"`
	SpeedMaxSizeMB     int                    `json:"speedMaxSizeMb"`
	Theme              string                 `json:"theme"` // system | light | dark
	Targets            map[string]ModeTargets `json:"targets"`

	OutputDir string `json:"outputDir"`
	CacheFile string `json:"cacheFile"`

	TimeoutSecs    int    `json:"timeoutSecs"`
	RetryCount     int    `json:"retryCount"`
	LimitedNetwork bool   `json:"limitedNetwork"`
	UserAgent      string `json:"userAgent"`
	SpoofedSNI     string `json:"spoofedSni"`
	ProxyTestURL   string `json:"proxyTestUrl"`

	AutoConcurrency    bool `json:"autoConcurrency"`
	MaxConcurrent      int  `json:"maxConcurrent"`
	MinConcurrent      int  `json:"minConcurrent"`
	Streaming          bool `json:"streaming"`
	StreamingAuto      bool `json:"streamingAuto"`
	StreamingThreshold int  `json:"streamingThreshold"`
	StreamingSizeMB    int  `json:"streamingSizeMb"`
	CountTotal         bool `json:"countTotal"`

	TargetDomain string `json:"targetDomain"`
	DnsMaxPingMs int    `json:"dnsMaxPingMs"`
	DnsTxtDomain string `json:"dnsTxtDomain"`

	DnsRate            float64 `json:"dnsRate"`
	DnsRatePerResolver float64 `json:"dnsRatePerResolver"`
	DnsBurst           int     `json:"dnsBurst"`
	DnsJitter          float64 `json:"dnsJitter"`
}

func defaultSettings() Settings {
	d := engine.DefaultConfig()
	targets := make(map[string]ModeTargets, len(modeFolders))
	for mode := range modeFolders {
		targets[mode] = ModeTargets{}
	}
	return Settings{
		DPIFragmentSize:    d.DPIFragmentSize,
		DPIFragmentDelayMs: d.DPIFragmentDelayMs,
		Theme:              "system",
		Accent:             "purple",
		SpeedTestURL:       "https://speed.cloudflare.com/__down?bytes=25000000",
		SpeedDurationSecs:  10,
		SpeedMaxSizeMB:     25,
		Targets:            targets,
		OutputDir:          filepath.Join(userDocumentsDir(), "WhiteDNS Scanner"),
		CacheFile:          d.CacheFile,
		TimeoutSecs:        d.TimeoutSecs,
		RetryCount:         d.RetryCount,
		UserAgent:          d.UserAgent,
		SpoofedSNI:         d.SpoofedSNI,
		ProxyTestURL:       "https://example.com/",
		AutoConcurrency:    d.AutoConcurrency,
		MaxConcurrent:      d.MaxConcurrent,
		MinConcurrent:      d.MinConcurrent,
		Streaming:          d.Streaming,
		StreamingAuto:      d.StreamingAuto,
		StreamingThreshold: d.StreamingThreshold,
		StreamingSizeMB:    d.StreamingSizeMB,
		CountTotal:         d.CountTotal,
		TargetDomain:       d.TargetDomain,
		DnsMaxPingMs:       d.DnsMaxPingMs,
		DnsTxtDomain:       d.DnsTxtDomain,
		DnsBurst:           1,
	}
}

func userDocumentsDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return "."
	}
	return filepath.Join(home, "Documents")
}

func settingsPath() string {
	if root := os.Getenv("WHITEDNS_CONFIG_DIR"); root != "" {
		return filepath.Join(root, "WhiteDNS Scanner", "settings.json")
	}
	dir, err := os.UserConfigDir()
	if err != nil {
		dir = "."
	}
	return filepath.Join(dir, "WhiteDNS Scanner", "settings.json")
}

// loadSettings returns saved settings over the defaults, so a field added in a
// later version keeps its default for users with an older settings file.
func loadSettings() Settings {
	s := defaultSettings()
	if raw, err := os.ReadFile(settingsPath()); err == nil {
		// Editors such as Notepad and PowerShell may add a UTF-8 BOM.
		_ = json.Unmarshal(bytes.TrimPrefix(raw, []byte("\xef\xbb\xbf")), &s)
	}
	if s.Targets == nil {
		s.Targets = map[string]ModeTargets{}
	}
	return s
}

func saveSettings(s Settings) error {
	p := settingsPath()
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		return err
	}
	raw, err := json.MarshalIndent(withoutIPLists(s), "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(p, raw, 0o644)
}

// withoutIPLists drops pasted IP lists and added ASNs before settings reach
// disk: they are drafts for this session, so closing the app clears them.
// Edge domain lists, files and every other setting are kept.
func withoutIPLists(s Settings) Settings {
	targets := make(map[string]ModeTargets, len(s.Targets))
	for mode, t := range s.Targets {
		if t.TargetType != engine.TargetDomain {
			t.TargetsText, t.ASNs = "", nil
		}
		if ip, ok := t.Inputs[engine.TargetIP]; ok {
			t.Inputs = maps.Clone(t.Inputs)
			ip.TargetsText, ip.ASNs = "", nil
			t.Inputs[engine.TargetIP] = ip
		}
		targets[mode] = t
	}
	s.Targets = targets
	return s
}

// asnTargetLines expands added ASNs into one range per line.
func asnTargetLines(picks []ASNPick) ([]byte, error) {
	var out []byte
	for _, p := range picks {
		family := p.Family
		if family != "ipv4" && family != "ipv6" {
			family = "both"
		}
		ranges, err := engine.ASNRanges([]string{p.ASN}, family)
		if err != nil {
			return nil, err
		}
		for _, r := range ranges {
			out = append(append(out, r...), '\n')
		}
	}
	return out, nil
}

func isDNSMode(mode string) bool {
	return mode == ModeDNS || mode == ModeDNSUDPTCP || mode == ModeTXT
}

// newRunDir creates <output>/<mode folder>/<date time>/ for one scan.
func newRunDir(outputDir, mode string, now time.Time) (string, error) {
	base := filepath.Join(outputDir, modeFolders[mode], now.Format("2006-01-02 15-04-05"))
	dir := base
	for i := 2; ; i++ { // two runs in the same second
		if _, err := os.Stat(dir); os.IsNotExist(err) {
			break
		}
		dir = fmt.Sprintf("%s (%d)", base, i)
	}
	return dir, os.MkdirAll(dir, 0o755)
}

// toScanConfig validates the settings for one mode and builds the engine
// config. Reports go to runDir; each mode keeps its own cache of passed
// targets in its folder so modes never feed each other.
func (s Settings) toScanConfig(mode, runDir string) (*engine.ScanConfig, error) {
	if _, ok := modeFolders[mode]; !ok {
		return nil, fmt.Errorf("unknown scan mode %q", mode)
	}
	selection := s.Targets[mode]
	t := selection.selectedInput()

	cfg := engine.DefaultConfig()
	if isCleanMode(mode) {
		cfg.TargetType = selection.TargetType
		if cfg.TargetType != "" && cfg.TargetType != engine.TargetIP && cfg.TargetType != engine.TargetDomain {
			return nil, fmt.Errorf("choose IPs or Edge domains as the target type")
		}
	}
	if cfg.TargetType == engine.TargetDomain {
		providerID := selection.EdgeProvider
		if providerID != "" {
			provider, ok := engine.FindEdgeProvider(providerID)
			if !ok {
				return nil, fmt.Errorf("choose a supported CDN provider or Other / custom CDN")
			}
			supported := false
			for _, candidate := range provider.Modes {
				if candidate == mode {
					supported = true
				}
			}
			if !supported {
				return nil, fmt.Errorf("%s does not use the All Cloudflare Ports mode; choose Default Ports or Custom ports", provider.Name)
			}
			cfg.EdgeProvider = providerID
		}
	}
	switch t.IPFamily {
	case "", "both":
	case "ipv4", "ipv6":
		if cfg.TargetType != engine.TargetDomain { // domain targets resolve through the system resolver
			cfg.IPFamily = t.IPFamily
		}
	default:
		return nil, fmt.Errorf("choose IPv4, IPv6 or both")
	}
	cfg.OutputDir = runDir
	cacheName := defaultIfEmpty(s.CacheFile, cfg.CacheFile)
	if cfg.TargetType != "" {
		prefix := cfg.TargetType
		if cfg.EdgeProvider != "" {
			prefix += "-" + cfg.EdgeProvider
		}
		cacheName = filepath.Join(filepath.Dir(cacheName), prefix+"-"+filepath.Base(cacheName))
	}
	cfg.CacheFile = filepath.Join(filepath.Dir(runDir), cacheName)
	cfg.TimeoutSecs = positive(s.TimeoutSecs, cfg.TimeoutSecs)
	cfg.RetryCount = max(s.RetryCount, 0)
	cfg.LimitedNetwork = s.LimitedNetwork
	cfg.AntiDPI = s.AntiDPI && (isCleanMode(mode) || mode == ModeHTTPProxy || mode == ModeSOCKSProxy)
	cfg.DPIFragmentSize = positive(s.DPIFragmentSize, 64)
	cfg.DPIFragmentDelayMs = s.DPIFragmentDelayMs
	if err := cfg.ValidateAntiDPI(); err != nil {
		return nil, err
	}
	cfg.UserAgent = defaultIfEmpty(s.UserAgent, cfg.UserAgent)
	if cfg.TargetType == engine.TargetDomain {
		if t.TimeoutSecs > 0 {
			cfg.TimeoutSecs = t.TimeoutSecs
		}
		if t.RetryCount != nil {
			if *t.RetryCount < 0 {
				return nil, fmt.Errorf("retry count cannot be negative")
			}
			cfg.RetryCount = *t.RetryCount
		}
		if strings.TrimSpace(t.UserAgent) != "" {
			cfg.UserAgent = t.UserAgent
		}
	}
	cfg.SpoofedSNI = defaultIfEmpty(strings.TrimSpace(s.SpoofedSNI), cfg.SpoofedSNI)
	cfg.AutoConcurrency = s.AutoConcurrency
	cfg.MaxConcurrent = positive(s.MaxConcurrent, cfg.MaxConcurrent)
	cfg.MinConcurrent = positive(s.MinConcurrent, cfg.MinConcurrent)
	if cfg.AutoConcurrency && cfg.MinConcurrent > cfg.MaxConcurrent {
		return nil, fmt.Errorf("minimum workers must not exceed maximum workers in automatic mode")
	}
	cfg.Streaming = s.Streaming
	cfg.StreamingAuto = s.StreamingAuto
	cfg.StreamingThreshold = positive(s.StreamingThreshold, cfg.StreamingThreshold)
	cfg.StreamingSizeMB = positive(s.StreamingSizeMB, cfg.StreamingSizeMB)
	cfg.CountTotal = s.CountTotal
	cfg.TargetDomain = defaultIfEmpty(strings.TrimSpace(s.TargetDomain), cfg.TargetDomain)
	cfg.DnsMaxPingMs = positive(s.DnsMaxPingMs, cfg.DnsMaxPingMs)
	if isDNSMode(mode) {
		cfg.DnsRateLimitPerSecond = max(s.DnsRate, 0)
		cfg.DnsRateLimitPerResolverPerSecond = max(s.DnsRatePerResolver, 0)
		cfg.DnsRateLimitBurst = max(s.DnsBurst, 1)
		cfg.DnsTimingJitter = min(max(s.DnsJitter, 0), 1)
	}

	if isCleanMode(mode) {
		// Fronting domains: the Worker / Pages hostnames from the user's configs
		// (the platform's own domains by default), tested through each IP with
		// the domain as SNI and Host alongside the shared services. On a
		// filtering network an IP that any of them answers through is clean.
		platform := []string{"workers.dev", "pages.dev"}
		if cfg.EdgeProvider != "" {
			provider, _ := engine.FindEdgeProvider(cfg.EdgeProvider)
			platform = provider.PlatformDomains
		}
		if strings.TrimSpace(t.PlatformDomainsText) != "" {
			platform = strings.FieldsFunc(t.PlatformDomainsText, func(r rune) bool { return r == ',' || r == '\n' || r == '\r' || r == ' ' || r == '\t' })
		}
		for _, domain := range platform {
			if err := engine.ValidateSNI(domain); err != nil {
				return nil, fmt.Errorf("invalid fronting domain: %w", err)
			}
		}
		if t.ServiceChecks {
			cfg.ProbeDomains = engine.ProbeDomainsForPlatform(platform)
		} else if len(platform) > 0 {
			cfg.FrontingHost = platform[0] // the quick check fronts through the first one
		}
	}
	if strings.TrimSpace(t.CustomPorts) != "" {
		ports, err := parsePorts(t.CustomPorts)
		if err != nil {
			return nil, err
		}
		cfg.CustomPorts = ports
	}

	switch mode {
	case ModeSNI:
		cfg.SNIScan = true
		if len(cfg.CustomPorts) == 0 {
			cfg.CustomPorts = []int{443}
		}
		if err := engine.ValidateSNI(cfg.SpoofedSNI); err != nil {
			return nil, err
		}
	case ModeHTTPProxy, ModeSOCKSProxy:
		cfg.ProxyMode = "http"
		if mode == ModeSOCKSProxy {
			cfg.ProxyMode = "socks5"
		}
		cfg.ProxyTestURL = defaultIfEmpty(strings.TrimSpace(s.ProxyTestURL), "https://example.com/")
		if _, err := engine.ParseProbeURL(cfg.ProxyTestURL); err != nil {
			return nil, err
		}
		if len(cfg.CustomPorts) == 0 {
			if cfg.ProxyMode == "http" {
				cfg.CustomPorts = []int{8080, 3128, 80}
			} else {
				cfg.CustomPorts = []int{1080, 1081, 9050}
			}
		}
	case ModeHTTPAll:
		cfg.ScanAllPorts = true
	case ModeCustom:
		if len(cfg.CustomPorts) == 0 {
			return nil, fmt.Errorf("enter the ports to scan, e.g. 80,443,8000-8010")
		}
	case ModeDNS:
		cfg.DnsDiscoveryMode = true
	case ModeDNSUDPTCP:
		cfg.DnsDiscoveryMode = true
		cfg.DnsUdpTcpOnly = true
	case ModeTXT:
		cfg.DnsTxtMode = true
		cfg.DnsTxtDomain = strings.TrimSpace(s.DnsTxtDomain)
		if cfg.DnsTxtDomain == "" {
			return nil, fmt.Errorf("enter the TXT base domain to query")
		}
	}

	// Targets: pasted text wins over the file. Either way a copy lands in the
	// run folder, so every run records exactly what it scanned.
	// Added ASNs are expanded here and appended to either.
	pasted := strings.TrimSpace(t.TargetsText)
	in := filepath.Join(runDir, "targets.txt")
	var body []byte
	switch {
	case pasted != "":
		body = []byte(pasted + "\n")
	case strings.TrimSpace(t.InputFile) != "":
		raw, err := os.ReadFile(t.InputFile)
		if err != nil {
			return nil, fmt.Errorf("cannot read targets file: %v", err)
		}
		body = raw
	}
	if len(t.ASNs) > 0 {
		ranges, err := asnTargetLines(t.ASNs)
		if err != nil {
			return nil, err
		}
		if len(body) > 0 && body[len(body)-1] != '\n' {
			body = append(body, '\n')
		}
		body = append(body, ranges...)
	}
	if len(bytes.TrimSpace(body)) == 0 {
		if mode == ModeTXT {
			return nil, fmt.Errorf("choose a resolver file or paste resolvers first")
		}
		return nil, fmt.Errorf("choose a targets file, paste targets or add an ASN first")
	}
	if err := os.WriteFile(in, body, 0o644); err != nil {
		return nil, fmt.Errorf("cannot save targets: %v", err)
	}
	if err := engine.ValidateTargetFile(in, cfg.TargetType); err != nil {
		return nil, err
	}
	cfg.InputFile = in
	return cfg, nil
}

func defaultIfEmpty(v, def string) string {
	if strings.TrimSpace(v) == "" {
		return def
	}
	return v
}

func positive(v, def int) int {
	if v <= 0 {
		return def
	}
	return v
}

// parsePorts accepts "80,443,8000-8010" like the CLI's -ports flag.
func parsePorts(s string) ([]int, error) {
	seen := map[int]bool{}
	var out []int
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		lo, hi, isRange := strings.Cut(part, "-")
		a, err := strconv.Atoi(strings.TrimSpace(lo))
		if err != nil {
			return nil, fmt.Errorf("invalid port %q", part)
		}
		b := a
		if isRange {
			if b, err = strconv.Atoi(strings.TrimSpace(hi)); err != nil {
				return nil, fmt.Errorf("invalid port range %q", part)
			}
		}
		if a > b {
			a, b = b, a
		}
		if a < 1 || b > 65535 {
			return nil, fmt.Errorf("port out of range %q", part)
		}
		for p := a; p <= b; p++ {
			if !seen[p] {
				seen[p] = true
				out = append(out, p)
			}
		}
	}
	return out, nil
}

func isCleanMode(mode string) bool {
	return mode == ModeHTTP || mode == ModeHTTPAll || mode == ModeCustom
}

func (t ModeTargets) selectedInput() TargetInput {
	if t.TargetType == engine.TargetDomain && t.EdgeProvider != "" && t.EdgeInputs != nil {
		return t.EdgeInputs[t.EdgeProvider]
	}
	if t.TargetType != "" && t.Inputs != nil {
		return t.Inputs[t.TargetType]
	}
	return TargetInput{InputFile: t.InputFile, TargetsText: t.TargetsText, CustomPorts: t.CustomPorts, IPFamily: t.IPFamily, ASNs: t.ASNs}
}
