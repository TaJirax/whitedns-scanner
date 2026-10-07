package engine

// ScanMode is shared by the terminal menu and the desktop navigation.
type ScanMode struct {
	ID    string `json:"id"`
	Name  string `json:"name"`
	Group string `json:"group"`
	Hint  string `json:"hint"`
}

func ScanModes() []ScanMode {
	return []ScanMode{
		{"http", "Default Ports (443/80 only)", "Clean IP", "Fast"},
		{"http-all", "All Cloudflare Ports (13 ports)", "Clean IP", "Deep Scan"},
		{"dns", "DNS Resolver Discovery", "DNS scan", "UDP/TCP/DoT/DoH"},
		{"dns-udptcp", "DNS UDP/TCP only", "DNS scan", "faster, no DoT/DoH"},
		{"custom", "Custom ports", "Clean IP", "a list or ranges"},
		{"txt", "TXT Resolver Probe", "DNS scan", "TXT on a user domain"},
		{"sni", "SNI scan", "SNI scan", "forged SNI on HTTPS only"},
		{"http-proxy", "HTTP proxy", "Proxy scan", "verify HTTP forwarding / CONNECT"},
		{"socks-proxy", "SOCKS proxy", "Proxy scan", "verify SOCKS5 forwarding"},
	}
}

func (c *ScanConfig) ModeID() string {
	switch {
	case c.SNIScan:
		return "sni"
	case c.ProxyMode == "http":
		return "http-proxy"
	case c.ProxyMode == "socks5":
		return "socks-proxy"
	case c.DnsTxtMode:
		return "txt"
	case c.DnsDiscoveryMode && c.DnsUdpTcpOnly:
		return "dns-udptcp"
	case c.DnsDiscoveryMode:
		return "dns"
	case c.ScanAllPorts:
		return "http-all"
	case len(c.CustomPorts) > 0:
		return "custom"
	default:
		return "http"
	}
}

func (c *ScanConfig) ModeName() string {
	for _, m := range ScanModes() {
		if m.ID == c.ModeID() {
			return m.Name
		}
	}
	return "Default Ports (443/80 only)"
}

func (e *Engine) forgedSNI() string {
	if e.config.SNIScan {
		return e.config.SpoofedSNI
	}
	return ""
}

func (e *Engine) dnsUnits(t Target) int {
	cfg := *e.config
	if t.ExplicitPort {
		cfg.CustomPorts = []int{t.Port}
	}
	return dnsProgressUnitsPerResolver(&cfg)
}

func (e *Engine) dnsTotalForTargets(targets []Target) int {
	total := 0
	for _, t := range targets {
		total += e.dnsUnits(t)
	}
	return total
}
