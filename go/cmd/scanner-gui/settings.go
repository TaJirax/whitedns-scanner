package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"reachability-scanner/engine"
)

// Scan modes, mirroring the CLI's interactive menu.
const (
	ModeHTTP       = "http"       // default ports 443/80
	ModeHTTPAll    = "http-all"   // all 13 Cloudflare ports
	ModeCustom     = "custom"     // HTTP on custom ports
	ModeDNS        = "dns"        // resolver discovery over UDP/TCP/DoT/DoH
	ModeDNSUDPTCP  = "dns-udptcp" // resolver discovery, UDP/TCP only
	ModeTXT        = "txt"        // TXT lookups against a user domain
)

// Settings is everything the GUI lets the user change. It is saved as JSON
// beside the user's config dir so it survives restarts.
type Settings struct {
	Theme string `json:"theme"` // system | light | dark

	Mode        string `json:"mode"`
	InputFile   string `json:"inputFile"`
	TargetsText string `json:"targetsText"` // pasted targets; used instead of InputFile when set
	OutputDir   string `json:"outputDir"`
	CacheFile   string `json:"cacheFile"`

	TimeoutSecs int    `json:"timeoutSecs"`
	RetryCount  int    `json:"retryCount"`
	UserAgent   string `json:"userAgent"`
	SpoofedSNI  string `json:"spoofedSni"`
	CustomPorts string `json:"customPorts"` // "80,443,8000-8010"

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
	out := filepath.Join(userDocumentsDir(), "WhiteDNS Scanner")
	return Settings{
		Theme:              "system",
		Mode:               ModeHTTP,
		InputFile:          "",
		OutputDir:          out,
		CacheFile:          d.CacheFile,
		TimeoutSecs:        d.TimeoutSecs,
		RetryCount:         d.RetryCount,
		UserAgent:          d.UserAgent,
		SpoofedSNI:         d.SpoofedSNI,
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
	return s
}

func saveSettings(s Settings) error {
	p := settingsPath()
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		return err
	}
	raw, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(p, raw, 0o644)
}

func (s Settings) isDNS() bool {
	return s.Mode == ModeDNS || s.Mode == ModeDNSUDPTCP || s.Mode == ModeTXT
}

// toScanConfig validates the settings and builds the engine config. Pasted
// targets are written to a file in the output dir, which the engine reads.
func (s Settings) toScanConfig() (*engine.ScanConfig, error) {
	if strings.TrimSpace(s.OutputDir) == "" {
		return nil, fmt.Errorf("choose an output folder in Settings")
	}
	if err := os.MkdirAll(s.OutputDir, 0o755); err != nil {
		return nil, fmt.Errorf("cannot create output folder: %v", err)
	}

	cfg := engine.DefaultConfig()
	cfg.OutputDir = s.OutputDir
	cfg.CacheFile = defaultIfEmpty(s.CacheFile, cfg.CacheFile)
	cfg.TimeoutSecs = positive(s.TimeoutSecs, cfg.TimeoutSecs)
	cfg.RetryCount = max(s.RetryCount, 0)
	cfg.UserAgent = defaultIfEmpty(s.UserAgent, cfg.UserAgent)
	cfg.SpoofedSNI = defaultIfEmpty(s.SpoofedSNI, cfg.SpoofedSNI)
	cfg.AutoConcurrency = s.AutoConcurrency
	cfg.MaxConcurrent = positive(s.MaxConcurrent, cfg.MaxConcurrent)
	cfg.MinConcurrent = positive(s.MinConcurrent, cfg.MinConcurrent)
	cfg.Streaming = s.Streaming
	cfg.StreamingAuto = s.StreamingAuto
	cfg.StreamingThreshold = positive(s.StreamingThreshold, cfg.StreamingThreshold)
	cfg.StreamingSizeMB = positive(s.StreamingSizeMB, cfg.StreamingSizeMB)
	cfg.CountTotal = s.CountTotal
	cfg.TargetDomain = defaultIfEmpty(strings.TrimSpace(s.TargetDomain), cfg.TargetDomain)
	cfg.DnsMaxPingMs = positive(s.DnsMaxPingMs, cfg.DnsMaxPingMs)
	cfg.DnsRateLimitPerSecond = max(s.DnsRate, 0)
	cfg.DnsRateLimitPerResolverPerSecond = max(s.DnsRatePerResolver, 0)
	cfg.DnsRateLimitBurst = max(s.DnsBurst, 1)
	cfg.DnsTimingJitter = min(max(s.DnsJitter, 0), 1)

	if strings.TrimSpace(s.CustomPorts) != "" {
		ports, err := parsePorts(s.CustomPorts)
		if err != nil {
			return nil, err
		}
		cfg.CustomPorts = ports
	}

	switch s.Mode {
	case ModeHTTP:
		cfg.CustomPorts = nil
	case ModeHTTPAll:
		cfg.ScanAllPorts = true
		cfg.CustomPorts = nil
	case ModeCustom:
		if len(cfg.CustomPorts) == 0 {
			return nil, fmt.Errorf("enter the custom ports to scan, e.g. 80,443,8000-8010")
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
	default:
		return nil, fmt.Errorf("unknown scan mode %q", s.Mode)
	}

	// Targets: pasted text wins over the input file.
	pasted := strings.TrimSpace(s.TargetsText)
	switch {
	case pasted != "" && s.Mode == ModeTXT:
		cfg.DnsTxtResolversRaw = pasted
	case pasted != "":
		p := filepath.Join(s.OutputDir, "gui_targets.txt")
		if err := os.WriteFile(p, []byte(pasted+"\n"), 0o644); err != nil {
			return nil, fmt.Errorf("cannot save pasted targets: %v", err)
		}
		cfg.InputFile = p
	case strings.TrimSpace(s.InputFile) != "":
		if _, err := os.Stat(s.InputFile); err != nil {
			return nil, fmt.Errorf("input file not found: %s", s.InputFile)
		}
		cfg.InputFile = s.InputFile
	default:
		return nil, fmt.Errorf("choose a targets file or paste targets first")
	}
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
