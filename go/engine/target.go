package engine

import (
	"bufio"
	"context"
	"fmt"
	"math/big"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
)

// Target represents a single scan end-point with an explicit port and scheme.
type Target struct {
	Label          string
	URL            string
	Host           string // Original hostname/domain (used for SNI / Host header spoofing)
	Port           int    // Explicit port to probe
	Scheme         string // https, http, or socks5
	ExplicitScheme bool
	ExplicitPort   bool
	Username       string
	Password       string
}

// Key identifies the endpoint a target probes, so "https://1.2.3.4" from the
// input and "https://1.2.3.4:443" from the cache of passes are one target.
// Every dedupe uses it.
func (t Target) Key() string {
	return t.Scheme + "://" + net.JoinHostPort(t.Host, strconv.Itoa(t.Port)) + "|" + t.Username + "|" + t.Password
}

// ParseTargets reads domains.txt or Cache and parses them into Target slices.
// If scanAllPorts is true, each domain is expanded into 13 targets (one per CF port).
// If customPorts is non-empty, each host is expanded across the provided ports.
// DNS mode keeps one target per resolver because DNS probes expand ports internally.
func ParseTargets(filePath string, scanAllPorts bool, customPorts []int, dnsMode bool) ([]Target, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var rawTargets []Target
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		parsed, err := parseBaseTargetsFromLine(line)
		if err != nil {
			return nil, err
		}
		rawTargets = append(rawTargets, parsed...)
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	// If ScanAllPorts is enabled, expand each unique host across all 13 CF ports.
	if scanAllPorts {
		return expandAllPorts(rawTargets), nil
	}

	if ports := portsFor(customPorts, dnsMode); ports != nil {
		return expandCustomPorts(rawTargets, ports), nil
	}

	return rawTargets, nil
}

// DefaultPorts are what "Default Ports (443/80)" scans when no ports are set:
// HTTPS on 443 and plain HTTP on 80 for every target without its own port.
var DefaultPorts = []int{443, 80}

// portsFor is the port list targets expand across: the custom ports, or
// DefaultPorts. DNS modes expand ports inside each resolver probe instead.
func portsFor(customPorts []int, dnsMode bool) []int {
	switch {
	case dnsMode:
		return nil
	case len(customPorts) > 0:
		return customPorts
	}
	return DefaultPorts
}

// StreamTargets returns a channel that will produce Target items parsed from
// the provided file. It spawns a goroutine that reads the file and sends
// parsed targets to the channel. The returned `count` is an estimated total
// when it can be determined cheaply; otherwise it is -1.
func StreamTargets(filePath string, scanAllPorts bool, customPorts []int, countTotal bool, dnsMode bool) (<-chan Target, int, error) {
	return streamTargetsContext(context.Background(), filePath, scanAllPorts, customPorts, countTotal, dnsMode)
}

func streamTargetsContext(ctx context.Context, filePath string, scanAllPorts bool, customPorts []int, countTotal bool, dnsMode bool) (<-chan Target, int, error) {
	total := -1
	if countTotal {
		if estimated, err := CountUniqueScannableTargets(filePath, scanAllPorts, customPorts, dnsMode); err == nil {
			total = estimated
		}
	}

	out := make(chan Target, 1024)

	file, err := os.Open(filePath)
	if err != nil {
		return nil, -1, err
	}

	go func() {
		defer file.Close()
		defer close(out)

		scanner := bufio.NewScanner(file)
		scanner.Buffer(make([]byte, 64*1024), 1024*1024)

		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}

			parsed, err := parseBaseTargetsFromLine(line)
			if err != nil {
				continue
			}
			for _, base := range parsed {
				for _, target := range expandForMode(base, scanAllPorts, customPorts, dnsMode) {
					if ctx.Err() != nil {
						return
					}
					select {
					case out <- target:
					case <-ctx.Done():
						return
					}
				}
			}
		}
	}()

	return out, total, nil
}

// EstimateScannableLines counts non-empty, non-comment lines until a limit is reached.
// Returns the number counted and whether the limit was exceeded.
func EstimateScannableLines(filePath string, limit int) (int, bool, error) {
	return EstimateScannableTargets(filePath, false, nil, false, limit)
}

// EstimateScannableTargets estimates how many scan targets will be produced
// after CIDR expansion and port expansion.
func EstimateScannableTargets(filePath string, scanAllPorts bool, customPorts []int, dnsMode bool, limit int) (int, bool, error) {
	f, err := os.Open(filePath)
	if err != nil {
		return 0, false, err
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	count := 0
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		count += estimateTargetsForLine(line, scanAllPorts, customPorts, dnsMode)
		if limit > 0 && count > limit {
			return count, true, nil
		}
	}
	if err := sc.Err(); err != nil {
		return count, false, err
	}
	return count, false, nil
}

// IsLargeInput determines whether the input file should trigger streaming mode.
func IsLargeInput(filePath string, scanAllPorts bool, customPorts []int, dnsMode bool, lineThreshold int, sizeMB int) (bool, int, error) {
	if sizeMB > 0 {
		info, err := os.Stat(filePath)
		if err == nil {
			if info.Size() >= int64(sizeMB)*1024*1024 {
				return true, -1, nil
			}
		}
	}
	if lineThreshold <= 0 {
		return false, -1, nil
	}
	count, exceeded, err := EstimateScannableTargets(filePath, scanAllPorts, customPorts, dnsMode, lineThreshold)
	if err != nil {
		return false, -1, err
	}
	if exceeded {
		return true, count, nil
	}
	return false, count, nil
}

func estimateTargetsForLine(line string, scanAllPorts bool, customPorts []int, dnsMode bool) int {
	lbl := ""
	val := line
	if idx := strings.Index(line, "|"); idx != -1 {
		lbl = strings.TrimSpace(line[:idx])
		val = strings.TrimSpace(line[idx+1:])
	}
	_ = lbl
	val = strings.Trim(val, "'\"")

	if strings.Contains(val, "/") && !strings.HasPrefix(val, "http") {
		if _, ipnet, err := net.ParseCIDR(val); err == nil {
			base := countCIDRTargets(ipnet)
			return base * expansionFactor(scanAllPorts, customPorts, dnsMode)
		}
		return 0
	}

	return expansionFactor(scanAllPorts, customPorts, dnsMode)
}

// CountUniqueScannableTargets counts the unique scan targets that would be
// emitted for the given input file after deduplication.
func CountUniqueScannableTargets(filePath string, scanAllPorts bool, customPorts []int, dnsMode bool) (int, error) {
	return CountUniqueScannableTargetsWithSeed(filePath, nil, scanAllPorts, customPorts, dnsMode)
}

// CountUniqueScannableTargetsWithSeed counts the unique scan targets that would be
// emitted for the given input file after deduplication, seeding the seen set with
// an existing slice of targets.
func CountUniqueScannableTargetsWithSeed(filePath string, seed []Target, scanAllPorts bool, customPorts []int, dnsMode bool) (int, error) {
	f, err := os.Open(filePath)
	if err != nil {
		return 0, err
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	seen := make(map[string]struct{})
	for _, seeded := range seed {
		for _, emitted := range expandForMode(seeded, scanAllPorts, customPorts, dnsMode) {
			seen[emitted.Key()] = struct{}{}
		}
	}
	count := 0

	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		baseTargets, err := parseBaseTargetsFromLine(line)
		if err != nil {
			return 0, err
		}

		for _, base := range baseTargets {
			for _, emitted := range expandForMode(base, scanAllPorts, customPorts, dnsMode) {
				if _, ok := seen[emitted.Key()]; ok {
					continue
				}
				seen[emitted.Key()] = struct{}{}
				count++
			}
		}
	}
	if err := sc.Err(); err != nil {
		return 0, err
	}
	return count, nil
}

func parseBaseTargetsFromLine(line string) ([]Target, error) {
	label, value := "", strings.TrimSpace(line)
	if left, right, ok := strings.Cut(value, "|"); ok {
		label, value = strings.TrimSpace(left), strings.TrimSpace(right)
	}
	value = strings.Trim(value, "'\"")
	if strings.Contains(value, "/") && !strings.Contains(value, "://") {
		ip, network, err := net.ParseCIDR(value)
		if err != nil {
			return nil, fmt.Errorf("invalid CIDR %q: %w", value, err)
		}
		return buildCIDRTargetsFromNet(label, ip, network), nil
	}
	explicitScheme := strings.Contains(value, "://")
	endpoint := value
	if !strings.Contains(endpoint, "://") {
		if net.ParseIP(endpoint) != nil && strings.Contains(endpoint, ":") {
			endpoint = "[" + endpoint + "]"
		}
		endpoint = "https://" + endpoint
	}
	u, err := url.Parse(endpoint)
	if err != nil || u.Hostname() == "" || strings.ContainsAny(u.Hostname(), " \t\n") {
		return nil, fmt.Errorf("invalid endpoint %q", value)
	}
	switch u.Scheme {
	case "http", "https", "socks5", "socks5h", "dns", "dns-txt", "udp", "tcp":
	default:
		return nil, fmt.Errorf("unsupported endpoint scheme %q", u.Scheme)
	}
	if strings.HasSuffix(u.Host, ":") {
		return nil, fmt.Errorf("missing endpoint port in %q", value)
	}
	port := 443
	if u.Scheme == "http" {
		port = 80
	}
	if u.Scheme == "dns" || u.Scheme == "dns-txt" || u.Scheme == "udp" || u.Scheme == "tcp" {
		port = 53
	}
	if strings.HasPrefix(u.Scheme, "socks") {
		port = 1080
	}
	explicit := u.Port() != "" || explicitScheme
	if u.Port() != "" {
		port, err = strconv.Atoi(u.Port())
		if err != nil || port < 1 || port > 65535 {
			return nil, fmt.Errorf("invalid endpoint port in %q", value)
		}
	}
	if label == "" {
		label = u.Host
	}
	target := Target{Label: label, URL: u.Scheme + "://" + u.Host, Host: u.Hostname(), Port: port, Scheme: u.Scheme, ExplicitScheme: explicitScheme, ExplicitPort: explicit}
	if u.User != nil {
		target.Username = u.User.Username()
		target.Password, _ = u.User.Password()
	}
	return []Target{target}, nil
}

func expandForMode(base Target, scanAllPorts bool, customPorts []int, dnsMode bool) []Target {
	if scanAllPorts {
		return expandAllPorts([]Target{base})
	}
	if ports := portsFor(customPorts, dnsMode); ports != nil {
		return expandCustomPorts([]Target{base}, ports)
	}
	return []Target{base}
}

func expansionFactor(scanAllPorts bool, customPorts []int, dnsMode bool) int {
	if scanAllPorts {
		return len(CFHTTPSPorts) + len(CFHTTPPorts)
	}
	return max(len(portsFor(customPorts, dnsMode)), 1)
}

func countCIDRTargets(ipnet *net.IPNet) int {
	if ipnet == nil {
		return 0
	}
	prefix, bits := ipnet.Mask.Size()
	if bits == 32 {
		hostBits := 32 - prefix
		if hostBits <= 0 {
			return 1
		}
		if hostBits == 1 {
			return 2
		}
		return (1 << hostBits) - 2
	}

	hostBits := 128 - prefix
	if hostBits <= 0 {
		return 1
	}
	if ipv6Sampled(ipnet) {
		return len(sampleIPv6CIDR(ipnet, maxIPv6PerCIDR))
	}
	total := new(big.Int).Lsh(big.NewInt(1), uint(hostBits))
	maxInt := int(^uint(0) >> 1)
	if total.Cmp(big.NewInt(int64(maxInt))) > 0 {
		return maxInt
	}
	return int(total.Int64())
}

// broadcastIPv4 returns the broadcast address for an IPv4 CIDR, or nil for IPv6.
func broadcastIPv4(ipnet *net.IPNet) net.IP {
	if ipnet == nil {
		return nil
	}
	ip := ipnet.IP.To4()
	if ip == nil {
		return nil
	}
	mask := ipnet.Mask
	if len(mask) != net.IPv4len {
		return nil
	}
	b := make(net.IP, net.IPv4len)
	for i := 0; i < net.IPv4len; i++ {
		b[i] = ip[i] | ^mask[i]
	}
	return b
}

// buildCIDRTargetsFromNet expands an IPv4 or IPv6 CIDR into individual scan targets.
// For IPv4 networks smaller than /31 it skips the network and broadcast addresses.
func buildCIDRTargetsFromNet(lbl string, ip net.IP, ipnet *net.IPNet) []Target {
	if ipv6Sampled(ipnet) {
		targets := make([]Target, 0, maxIPv6PerCIDR)
		for _, ipStr := range sampleIPv6CIDR(ipnet, maxIPv6PerCIDR) {
			tLbl := ipStr
			if lbl != "" {
				tLbl = lbl + " " + ipStr
			}
			targets = append(targets, Target{Label: tLbl, URL: "https://[" + ipStr + "]", Host: ipStr, Port: 443, Scheme: "https"})
		}
		return targets
	}
	prefix, bits := ipnet.Mask.Size()
	skipEdges := bits == 32 && prefix < 31
	if v4 := ipnet.IP.To4(); v4 != nil && bits == 32 {
		// Integer sweep: one string per address ("https://a.b.c.d", Host is a
		// slice of it) instead of String()/compare/Sprintf on every step.
		first, last := ipv4Bounds(ipnet)
		if skipEdges {
			first, last = first+1, last-1 // network and broadcast addresses
		}
		targets := make([]Target, 0, last-first+1)
		buf := append(make([]byte, 0, len("https://255.255.255.255")), "https://"...)
		for u := first; u <= last; u++ {
			url := string(appendIPv4(buf, uint32(u)))
			host := url[len("https://"):]
			label := host
			if lbl != "" {
				label = lbl + " " + host
			}
			targets = append(targets, Target{Label: label, URL: url, Host: host, Port: 443, Scheme: "https"})
		}
		return targets
	}
	broadcast := broadcastIPv4(ipnet)
	targets := make([]Target, 0)

	for cur := ip.Mask(ipnet.Mask); ipnet.Contains(cur); incIP(cur) {
		ipStr := cur.String()
		if skipEdges {
			if ipStr == ipnet.IP.String() {
				continue
			}
			if broadcast != nil && ipStr == broadcast.String() {
				continue
			}
		}

		tLbl := ipStr
		if lbl != "" {
			tLbl = fmt.Sprintf("%s %s", lbl, ipStr)
		}
		targets = append(targets, Target{
			Label:  strings.TrimSpace(tLbl),
			URL:    "https://" + bracketIPv6(ipStr),
			Host:   ipStr,
			Port:   443,
			Scheme: "https",
		})
	}

	return targets
}

// expandAllPorts takes a list of raw targets and for each unique host, creates
// one target per Cloudflare port (6 HTTPS + 7 HTTP = 13 per host).
func expandAllPorts(rawTargets []Target) []Target {
	var expanded []Target
	seen := make(map[string]struct{}) // track host to avoid double-expanding

	for _, t := range rawTargets {
		if _, exists := seen[targetExpansionKey(t)]; exists {
			continue
		}
		seen[targetExpansionKey(t)] = struct{}{}

		for _, port := range CFHTTPSPorts {
			expanded = append(expanded, Target{
				Label:  fmt.Sprintf("%s:%d", t.Label, port),
				URL:    "https://" + net.JoinHostPort(t.Host, strconv.Itoa(port)),
				Host:   t.Host,
				Port:   port,
				Scheme: "https",
			})
		}
		for _, port := range CFHTTPPorts {
			expanded = append(expanded, Target{
				Label:  fmt.Sprintf("%s:%d", t.Label, port),
				URL:    "http://" + net.JoinHostPort(t.Host, strconv.Itoa(port)),
				Host:   t.Host,
				Port:   port,
				Scheme: "http",
			})
		}
	}

	return expanded
}

// expandCustomPorts expands each unique host into targets using the provided ports.
func targetExpansionKey(t Target) string {
	key := t.Host + "|" + t.Username + "|" + t.Password
	if t.ExplicitPort {
		key += "|" + strconv.Itoa(t.Port) + "|" + t.Scheme
	}
	return key
}

func expandCustomPorts(rawTargets []Target, ports []int) []Target {
	var expanded []Target
	seen := make(map[string]struct{})
	for _, t := range rawTargets {
		if _, exists := seen[t.Host]; exists {
			continue
		}
		seen[targetExpansionKey(t)] = struct{}{}

		if t.ExplicitPort {
			expanded = append(expanded, t)
			continue
		}
		for _, p := range ports {
			scheme := schemeForPort(p, t.Scheme)
			expanded = append(expanded, Target{
				Label:    fmt.Sprintf("%s:%d", t.Label, p),
				URL:      scheme + "://" + net.JoinHostPort(t.Host, strconv.Itoa(p)),
				Host:     t.Host,
				Port:     p,
				Scheme:   scheme,
				Username: t.Username, Password: t.Password,
			})
		}
	}
	return expanded
}

// schemeForPort picks the most likely scheme for a port.
// Known Cloudflare HTTP/HTTPS ports are mapped explicitly; otherwise the
// base scheme is preserved when available.
func schemeForPort(port int, baseScheme string) string {
	switch port {
	case 80, 8080, 8880, 2052, 2082, 2086, 2095:
		return "http"
	case 443, 2053, 2083, 2087, 2096, 8443:
		return "https"
	}
	if baseScheme == "http" || baseScheme == "https" {
		return baseScheme
	}
	return "https"
}

// DeduplicateTargets returns a unique slice of targets, keeping the order of prioritized first.
func DeduplicateTargets(prioritized []Target, main []Target) []Target {
	seen := make(map[string]struct{})
	var result []Target

	for _, t := range prioritized {
		if _, exists := seen[t.Key()]; !exists {
			seen[t.Key()] = struct{}{}
			result = append(result, t)
		}
	}

	for _, t := range main {
		if _, exists := seen[t.Key()]; !exists {
			seen[t.Key()] = struct{}{}
			result = append(result, t)
		}
	}

	return result
}

// incIP increments an IP address.
// bracketIPv6 wraps an IPv6 literal for use in a URL host.
func bracketIPv6(host string) string {
	if strings.Contains(host, ":") {
		return "[" + host + "]"
	}
	return host
}

func incIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}
