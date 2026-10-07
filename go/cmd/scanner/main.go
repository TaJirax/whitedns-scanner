package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"

	"reachability-scanner/engine"
	"reachability-scanner/internal/tui"
)

func main() {
	var scanMode, proxyTestURL string
	var sniMode bool
	var input string
	var outDir string
	var concurrent int
	var timeout int
	var retry int
	var allPorts bool
	var dnsMode bool
	var txtMode bool
	var portsFlag string
	var dnsDomain string
	var txtDomain string
	var txtResolversRaw string
	var spoofSNI string
	var autoConcurrency bool
	var minConcurrent int
	var streaming bool
	var streamingAuto bool
	var streamingThreshold int
	var streamingSizeMB int
	var countTotal bool
	var dnsRate, dnsRatePerResolver, dnsJitter float64
	var dnsBurst int
	var antiDPI bool
	var fragmentSize, fragmentDelay int

	flag.StringVar(&scanMode, "mode", "", "Scan type: http, http-all, custom, sni, http-proxy, socks-proxy, dns, dns-udptcp, txt")
	flag.BoolVar(&sniMode, "sni-scan", false, "Enable the dedicated forged SNI scan")
	flag.StringVar(&proxyTestURL, "proxy-test-url", "https://example.com/", "URL fetched through each proxy")
	flag.StringVar(&input, "input", "domains.txt", "Path to target list")
	flag.StringVar(&outDir, "out", ".", "Directory to output reports and cache")
	flag.IntVar(&concurrent, "concurrent", -1, "Worker pool size (<=0 for auto)")
	flag.IntVar(&timeout, "timeout", 10, "Per-request timeout limit (seconds)")
	flag.IntVar(&retry, "retry", 2, "HTTP retry count")
	limited := flag.Bool("limited-network", false, "Slow or lossy network: retry timeouts and pace service checks (slower, more patient)")
	flag.BoolVar(&allPorts, "allports", false, "Scan all 13 Cloudflare ports per host")
	flag.BoolVar(&dnsMode, "dns", false, "DNS Discovery Mode: probe resolver IPs across UDP/TCP/DoT/DoH")
	flag.BoolVar(&txtMode, "txt", false, "TXT Resolver Mode: probe resolvers with TXT lookups")
	flag.StringVar(&portsFlag, "ports", "", "Custom ports (comma-separated or ranges, e.g. 80,443,8000-8010)")
	flag.StringVar(&dnsDomain, "domain", "google.com", "Target domain for DNS integrity verification")
	flag.StringVar(&txtDomain, "txtdomain", "", "Base domain for TXT resolver verification")
	flag.StringVar(&txtResolversRaw, "resolvers", "", "Comma-separated resolver IPs for TXT mode")
	flag.StringVar(&spoofSNI, "sni", "www.speedtest.net", "Spoofed SNI for DPI bypass (e.g. zula.ir)")
	flag.BoolVar(&autoConcurrency, "autoconcurrency", true, "Auto-tune worker pool size")
	flag.IntVar(&minConcurrent, "minconcurrency", 200, "Minimum workers when auto-tuning")
	flag.BoolVar(&streaming, "streaming", false, "Force streaming input mode")
	flag.BoolVar(&streamingAuto, "streaming-auto", true, "Auto-enable streaming for large inputs")
	flag.IntVar(&streamingThreshold, "streaming-threshold", 50000, "Line count to trigger streaming")
	flag.IntVar(&streamingSizeMB, "streaming-size-mb", 64, "File size (MB) to trigger streaming")
	flag.BoolVar(&countTotal, "count-total", false, "Count total lines for progress (extra pass)")
	flag.Float64Var(&dnsRate, "dns-rate", 0, "Max DNS queries per second for the whole scan (0 = unlimited; e.g. 3 where DNS above ~6/s is blocked)")
	flag.Float64Var(&dnsRatePerResolver, "dns-rate-per-resolver", 0, "Max DNS queries per second to any one resolver (0 = unlimited)")
	flag.IntVar(&dnsBurst, "dns-burst", 1, "DNS queries allowed back-to-back before spacing applies")
	flag.Float64Var(&dnsJitter, "dns-jitter", 0, "Timing mask 0..1: randomly lengthen gaps between DNS queries")
	ipFamily := flag.String("ip-family", "", "Scan only ipv4 or ipv6 IP targets (default both; hostnames are kept)")
	flag.BoolVar(&antiDPI, "anti-dpi", false, "Fragment TLS ClientHello in IP and proxy scans (does not affect DNS/SNI modes)")
	flag.IntVar(&fragmentSize, "dpi-fragment-size", 64, "ClientHello TCP fragment size, 1–1024 bytes")
	flag.IntVar(&fragmentDelay, "dpi-fragment-delay-ms", 1, "Delay between fragments, 0–20 ms")
	flag.Parse()

	cfg := engine.DefaultConfig()
	cfg.AntiDPI, cfg.DPIFragmentSize, cfg.DPIFragmentDelayMs = antiDPI, fragmentSize, fragmentDelay
	cfg.InputFile = input
	cfg.OutputDir = outDir
	cfg.AutoConcurrency = autoConcurrency
	cfg.MinConcurrent = minConcurrent
	cfg.Streaming = streaming
	cfg.StreamingAuto = streamingAuto
	cfg.StreamingThreshold = streamingThreshold
	cfg.StreamingSizeMB = streamingSizeMB
	cfg.CountTotal = countTotal
	if concurrent > 0 {
		cfg.MaxConcurrent = concurrent
		cfg.AutoConcurrency = false
	}
	cfg.TimeoutSecs = timeout
	cfg.RetryCount = retry
	cfg.LimitedNetwork = *limited
	cfg.ScanAllPorts = allPorts
	if portsFlag != "" {
		ports, err := parsePortsString(portsFlag)
		if err != nil {
			fmt.Printf("  Error: %v\n", err)
			os.Exit(1)
		}
		cfg.CustomPorts = ports
	}
	cfg.DnsDiscoveryMode = dnsMode
	cfg.TargetDomain = dnsDomain
	cfg.DnsTxtMode = txtMode
	cfg.DnsTxtDomain = txtDomain
	cfg.DnsTxtResolversRaw = txtResolversRaw
	cfg.SpoofedSNI = spoofSNI
	cfg.SNIScan = sniMode
	cfg.ProxyTestURL = proxyTestURL
	if scanMode != "" {
		if err := configureScanMode(cfg, scanMode); err != nil {
			fmt.Printf("Error: %v\n", err)
			os.Exit(1)
		}
	}

	cfg.DnsRateLimitPerSecond = dnsRate
	cfg.DnsRateLimitPerResolverPerSecond = dnsRatePerResolver
	cfg.DnsRateLimitBurst = dnsBurst
	cfg.DnsTimingJitter = dnsJitter
	cfg.IPFamily = *ipFamily

	interactive := len(os.Args) == 1

	for {
		if interactive {
			runInteractiveSetup(cfg)
		}

		runScan := true
		needsInputFile := !cfg.DnsTxtMode || strings.TrimSpace(cfg.DnsTxtResolversRaw) == ""
		if needsInputFile {
			if _, err := os.Stat(cfg.InputFile); os.IsNotExist(err) {
				fmt.Printf("  Error: Could not find target file '%s'\n", cfg.InputFile)
				if !interactive {
					os.Exit(1)
				}
				runScan = false
			}
		}
		if runScan {
			// Run the TUI Model
			model := tui.NewModel(cfg)
			if err := model.Run(cfg); err != nil {
				fmt.Printf("Error running scanner: %v\n", err)
				if !interactive {
					os.Exit(1)
				}
			}
		}

		// POST-SCAN MENU
		for {
			fmt.Println("\n╔══════════════════════════════════════════════════════╗")
			fmt.Println("║               ENTERPRISE POST-SCAN MENU              ║")
			fmt.Println("╚══════════════════════════════════════════════════════╝")
			fmt.Println("  [1] Re-run scan with current configuration")
			fmt.Println("  [2] Change configuration / Scan Mode")
			fmt.Println("  [3] Open output directory (Reports & Cache)")
			fmt.Println("  [4] Exit Application")
			fmt.Printf("\n  Select an option (1-4): ")

			var choice string
			// We use fmt.Scanln to read the single option
			if _, err := fmt.Scanln(&choice); errors.Is(err, io.EOF) {
				return
			}
			choice = strings.TrimSpace(choice)

			if choice == "1" {
				interactive = false
				break
			} else if choice == "2" {
				interactive = true
				break
			} else if choice == "3" {
				openDir(cfg.OutputDir)
			} else if choice == "4" || strings.ToLower(choice) == "q" {
				fmt.Println("  Exiting... Goodbye.")
				return
			} else {
				fmt.Println("  Invalid option. Please enter 1-4.")
			}
		}
	}
}

func runInteractiveSetup(cfg *engine.ScanConfig) {
	fmt.Println("\n╔══════════════════════════════════════════════════════╗")
	fmt.Println("║    WHITEDNS SCANNER - Setup         ║")
	fmt.Println("╚══════════════════════════════════════════════════════╝")
	fmt.Println()

	// Prompt for target file
	fmt.Printf("  Enter target list file (Default: %s): ", cfg.InputFile)
	var userInput string
	fmt.Scanln(&userInput)
	if userInput != "" {
		cfg.InputFile = strings.TrimSpace(userInput)
	}

	// Prompt for concurrent connections
	fmt.Printf("  Enter concurrent connections (Default: %d): ", cfg.MaxConcurrent)
	var concInput string
	fmt.Scanln(&concInput)
	if concInput != "" {
		fmt.Sscanf(concInput, "%d", &cfg.MaxConcurrent)
		if cfg.MaxConcurrent > 0 {
			cfg.AutoConcurrency = false
		}
	}

	// Prompt for scanning mode
	fmt.Println()
	fmt.Println("  Scanning Mode:")
	for i, mode := range engine.ScanModes() {
		fmt.Printf("    [%d] %s — %s\n", i+1, mode.Name, mode.Hint)
	}

	defaultMode := "1"
	for i, mode := range engine.ScanModes() {
		if mode.ID == cfg.ModeID() {
			defaultMode = strconv.Itoa(i + 1)
		}
	}
	fmt.Printf("  Select mode (Default: %s): ", defaultMode)

	var modeInput string
	fmt.Scanln(&modeInput)
	modeInput = strings.TrimSpace(modeInput)
	if modeInput == "" {
		modeInput = defaultMode
	}

	cfg.SNIScan = false
	cfg.ProxyMode = ""
	switch modeInput {
	case "1":
		cfg.ScanAllPorts = false
		cfg.DnsDiscoveryMode = false
		cfg.DnsTxtMode = false
		cfg.DnsUdpTcpOnly = false
		cfg.DnsTxtResolversRaw = ""
		cfg.CustomPorts = nil
	case "2":
		cfg.ScanAllPorts = true
		cfg.DnsDiscoveryMode = false
		cfg.DnsTxtMode = false
		cfg.DnsUdpTcpOnly = false
		cfg.DnsTxtResolversRaw = ""
		cfg.CustomPorts = nil
	case "3":
		cfg.ScanAllPorts = false
		cfg.DnsDiscoveryMode = true
		cfg.DnsTxtMode = false
		cfg.DnsUdpTcpOnly = false
		cfg.DnsTxtResolversRaw = ""
		cfg.CustomPorts = nil
		fmt.Printf("  Enter integrity check domain (Default: %s): ", cfg.TargetDomain)
		var domainInput string
		fmt.Scanln(&domainInput)
		domainInput = strings.TrimSpace(domainInput)
		if domainInput != "" {
			cfg.TargetDomain = domainInput
		}
	case "4":
		cfg.ScanAllPorts = false
		cfg.DnsDiscoveryMode = true
		cfg.DnsTxtMode = false
		cfg.DnsUdpTcpOnly = true
		cfg.DnsTxtResolversRaw = ""
		cfg.CustomPorts = nil
		fmt.Printf("  Enter integrity check domain (Default: %s): ", cfg.TargetDomain)
		var domainInput2 string
		fmt.Scanln(&domainInput2)
		domainInput2 = strings.TrimSpace(domainInput2)
		if domainInput2 != "" {
			cfg.TargetDomain = domainInput2
		}
	case "5":
		cfg.ScanAllPorts = false
		cfg.DnsDiscoveryMode = false
		cfg.DnsUdpTcpOnly = false
		cfg.DnsTxtMode = false
		cfg.DnsTxtResolversRaw = ""
		// Custom ports - apply to non-DNS scans. If DNS mode is wanted, user should
		// select 3 or 4 above and then also enter custom ports using flag or prompt.
		fmt.Printf("  Enter custom ports (e.g. 80,443,8000-8010): ")
		var portsInput string
		fmt.Scanln(&portsInput)
		portsInput = strings.TrimSpace(portsInput)
		if portsInput != "" {
			ports, err := parsePortsString(portsInput)
			if err != nil {
				fmt.Printf("  Error: %v\n", err)
			} else {
				cfg.CustomPorts = ports
			}
		}
	case "6":
		cfg.ScanAllPorts = false
		cfg.DnsDiscoveryMode = false
		cfg.DnsTxtMode = true
		cfg.DnsUdpTcpOnly = false
		cfg.CustomPorts = nil
		if strings.TrimSpace(cfg.DnsTxtDomain) == "" {
			fmt.Printf("  Enter TXT base domain: ")
		} else {
			fmt.Printf("  Enter TXT base domain (Default: %s): ", cfg.DnsTxtDomain)
		}
		var txtDomainInput string
		fmt.Scanln(&txtDomainInput)
		txtDomainInput = strings.TrimSpace(txtDomainInput)
		if txtDomainInput != "" {
			cfg.DnsTxtDomain = txtDomainInput
		}

		fmt.Println("  Resolver source:")
		fmt.Println("    [1] Use resolver file from input path")
		fmt.Println("    [2] Write/paste resolvers inline (comma-separated)")
		fmt.Printf("  Select source (Default: 1): ")
		var resolverSource string
		fmt.Scanln(&resolverSource)
		resolverSource = strings.TrimSpace(resolverSource)
		if resolverSource == "2" {
			fmt.Printf("  Enter resolvers (comma-separated): ")
			var resolverInput string
			fmt.Scanln(&resolverInput)
			cfg.DnsTxtResolversRaw = strings.TrimSpace(resolverInput)
		} else {
			cfg.DnsTxtResolversRaw = ""
		}
	case "7", "8", "9":
		cfg.ScanAllPorts, cfg.DnsDiscoveryMode, cfg.DnsTxtMode, cfg.DnsUdpTcpOnly = false, false, false, false
		cfg.DnsTxtResolversRaw = ""
		cfg.CustomPorts = nil
		if modeInput == "7" {
			cfg.SNIScan = true
			fmt.Printf("  Forged SNI hostname (Default: %s): ", cfg.SpoofedSNI)
			var name string
			fmt.Scanln(&name)
			if strings.TrimSpace(name) != "" {
				cfg.SpoofedSNI = strings.TrimSpace(name)
			}
			cfg.CustomPorts = []int{443}
		} else {
			cfg.ProxyMode = "http"
			cfg.CustomPorts = []int{8080, 3128, 80}
			if modeInput == "9" {
				cfg.ProxyMode = "socks5"
				cfg.CustomPorts = []int{1080, 1081, 9050}
			}
			fmt.Printf("  Proxy test URL (Default: %s): ", cfg.ProxyTestURL)
			var testURL string
			fmt.Scanln(&testURL)
			if strings.TrimSpace(testURL) != "" {
				cfg.ProxyTestURL = strings.TrimSpace(testURL)
			}
		}
		fmt.Printf("  Custom ports (blank keeps defaults): ")
		var custom string
		fmt.Scanln(&custom)
		if strings.TrimSpace(custom) != "" {
			if ports, err := parsePortsString(custom); err == nil {
				cfg.CustomPorts = ports
			} else {
				fmt.Printf("  Error: %v\n", err)
			}
		}

	}

	if cfg.DnsDiscoveryMode || cfg.DnsTxtMode {
		promptDNSRateLimit(cfg)
	}

	fmt.Println()
	fmt.Printf("  Mode: %s\n", cfg.ModeName())
	fmt.Println()
}

// promptDNSRateLimit asks for the optional DNS query cap. Networks that block
// DNS above a fixed rate drop most probes of an unlimited scan, so working
// resolvers look dead.
func promptDNSRateLimit(cfg *engine.ScanConfig) {
	fmt.Println()
	fmt.Println("  DNS query rate limit (for networks that block DNS above a fixed rate, e.g. 6/s):")
	fmt.Printf("  Max queries per second, 0 = unlimited (Default: %g): ", cfg.DnsRateLimitPerSecond)
	var rateInput string
	fmt.Scanln(&rateInput)
	if v, err := strconv.ParseFloat(strings.TrimSpace(rateInput), 64); err == nil && v >= 0 {
		cfg.DnsRateLimitPerSecond = v
	}
	if cfg.DnsRateLimitPerSecond <= 0 {
		return
	}
	fmt.Printf("  Timing mask 0..1, randomizes query gaps (Default: %g): ", cfg.DnsTimingJitter)
	var jitterInput string
	fmt.Scanln(&jitterInput)
	if v, err := strconv.ParseFloat(strings.TrimSpace(jitterInput), 64); err == nil && v >= 0 && v <= 1 {
		cfg.DnsTimingJitter = v
	}
	fmt.Printf("  ⏱ DNS queries capped at %g/s: a large resolver list takes longer, but results stay accurate.\n", cfg.DnsRateLimitPerSecond)
}

func openDir(dir string) {
	if dir == "." || dir == "" {
		dir = "."
	}
	absolute, err := filepath.Abs(dir)
	if err != nil {
		fmt.Printf("  [!] Failed to resolve directory: %v\n", err)
		return
	}
	cmd := outputDirCommand(absolute)
	if err := cmd.Start(); err != nil {
		fmt.Printf("  [!] Failed to open directory: %v\n", err)
	} else {
		go func() { _ = cmd.Wait() }()
		fmt.Println("  [+] Opened output directory.")
	}
}

func outputDirCommand(dir string) *exec.Cmd {
	program := "explorer"
	switch runtime.GOOS {
	case "darwin":
		program = "open"
	case "linux":
		program = "xdg-open"
	}
	return exec.Command(program, dir)
}

// parsePortsString accepts comma-separated ports and ranges like 8000-8010.
// It rejects malformed input instead of silently turning it into a wrong scan.
func parsePortsString(s string) ([]int, error) {
	out := make(map[int]struct{})
	parts := strings.Split(s, ",")
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if strings.Contains(p, "-") {
			bounds := strings.SplitN(p, "-", 2)
			if len(bounds) != 2 || strings.TrimSpace(bounds[0]) == "" || strings.TrimSpace(bounds[1]) == "" {
				return nil, fmt.Errorf("invalid port range %q", p)
			}
			a, err := strconv.Atoi(strings.TrimSpace(bounds[0]))
			if err != nil {
				return nil, fmt.Errorf("invalid port range %q", p)
			}
			b, err := strconv.Atoi(strings.TrimSpace(bounds[1]))
			if err != nil {
				return nil, fmt.Errorf("invalid port range %q", p)
			}
			if a > b {
				a, b = b, a
			}
			for i := a; i <= b; i++ {
				if i >= 1 && i <= 65535 {
					out[i] = struct{}{}
				}
			}
		} else {
			v, err := strconv.Atoi(p)
			if err != nil {
				return nil, fmt.Errorf("invalid port %q", p)
			}
			if v >= 1 && v <= 65535 {
				out[v] = struct{}{}
			} else {
				return nil, fmt.Errorf("port out of range %q", p)
			}
		}
	}
	res := make([]int, 0, len(out))
	for k := range out {
		res = append(res, k)
	}
	// sort for deterministic order
	sort.Ints(res)
	return res, nil
}
