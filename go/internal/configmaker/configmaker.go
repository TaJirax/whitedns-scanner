// Package configmaker holds the pure config-rewriting / endpoint-extraction
// logic shared by the desktop TUI and the mobile bridge. It has no UI or engine
// dependencies so any caller can use it.
package configmaker

import (
	"encoding/base64"
	"encoding/json"
	"net"
	"net/url"
	"regexp"
	"sort"
	"strings"
)

// URIRe matches the proxy-config URI schemes the config maker understands.
// wireguard/wg/awg are the URI form some clients emit for a WireGuard or
// AmneziaWG peer; vpn:// is Amnezia's own share link. The INI form of those
// two protocols is not a URI and is handled by ExtractWireguardBlocks.
var URIRe = regexp.MustCompile(`(?i)(?:vless|vmess|trojan|ss|hy2|hysteria2|wireguard|awg|wg|vpn)://[^\s]+`)

// ExtractConfigs pulls proxy configs out of raw text: first the multi-line
// INI-form WireGuard / AmneziaWG blocks, then the URI-shaped tokens in what is
// left. If neither is found it falls back to treating each non-empty line as a
// config.
func ExtractConfigs(raw string) []string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	seen := make(map[string]struct{})
	var out []string

	// A WireGuard config spans many lines, so its block has to be taken whole
	// and removed before the per-line URI scan below runs.
	blocks, raw := ExtractWireguardBlocks(raw)
	for _, block := range blocks {
		if _, ok := seen[block]; ok {
			continue
		}
		seen[block] = struct{}{}
		out = append(out, block)
	}

	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		for _, match := range URIRe.FindAllString(line, -1) {
			if _, ok := seen[match]; ok {
				continue
			}
			seen[match] = struct{}{}
			out = append(out, match)
		}
	}
	if len(out) > 0 {
		return out
	}
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if _, ok := seen[line]; ok {
			continue
		}
		seen[line] = struct{}{}
		out = append(out, line)
	}
	return out
}

// ExtractTargets pulls valid IP:port tokens out of raw text (space/comma/newline
// separated). Returns a sorted, de-duplicated list.
func ExtractTargets(raw string) []string {
	seen := make(map[string]struct{})
	var out []string
	for _, token := range strings.FieldsFunc(raw, splitTokens) {
		token = strings.TrimSpace(token)
		if token == "" {
			continue
		}
		host, port, err := net.SplitHostPort(token)
		if err != nil {
			// No port supplied. If the token is a bare IP, default to :443 so an
			// IP-only list still produces usable IP:port targets.
			if net.ParseIP(token) != nil {
				host, port = token, "443"
			} else {
				continue
			}
		} else if port == "" {
			// "ip:" with an empty port — also default to 443.
			if net.ParseIP(host) != nil {
				port = "443"
			} else {
				continue
			}
		}
		if host == "" || net.ParseIP(host) == nil {
			continue
		}
		endpoint := net.JoinHostPort(host, port)
		if _, ok := seen[endpoint]; ok {
			continue
		}
		seen[endpoint] = struct{}{}
		out = append(out, endpoint)
	}
	sort.Strings(out)
	return out
}

// ExtractIPs pulls IP:port endpoints out of proxy configs and/or plain text
// (the "reverse" operation). Returns a sorted, de-duplicated list.
func ExtractIPs(raw string) []string {
	seen := make(map[string]struct{})
	var out []string
	// INI-form WireGuard / AmneziaWG configs keep their address on an
	// "Endpoint = ip:port" line inside a multi-line block, not on a line of
	// their own.
	blocks, raw := ExtractWireguardBlocks(raw)
	for _, block := range blocks {
		endpoint := wireguardEndpoint(block)
		if endpoint == "" {
			continue
		}
		if _, ok := seen[endpoint]; ok {
			continue
		}
		seen[endpoint] = struct{}{}
		out = append(out, endpoint)
	}
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if match := URIRe.FindString(line); match != "" {
			if endpoint := HostPort(match); endpoint != "" {
				if _, ok := seen[endpoint]; !ok {
					seen[endpoint] = struct{}{}
					out = append(out, endpoint)
				}
			}
		}
		for _, token := range strings.FieldsFunc(line, splitTokens) {
			token = strings.TrimSpace(token)
			if token == "" {
				continue
			}
			host, port, err := net.SplitHostPort(token)
			if err != nil || host == "" || port == "" || net.ParseIP(host) == nil {
				continue
			}
			if _, ok := seen[token]; ok {
				continue
			}
			seen[token] = struct{}{}
			out = append(out, token)
		}
	}
	sort.Strings(out)
	return out
}

// HostPort returns the "host:port" of a proxy-config URI when the host is an IP.
func HostPort(raw string) string {
	raw = strings.TrimSpace(raw)
	// An Amnezia share link carries no host in the URL: the address lives in
	// its compressed JSON payload.
	if strings.HasPrefix(strings.ToLower(raw), "vpn://") {
		return amneziaEndpoint(raw)
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Host == "" {
		return ""
	}
	host := parsed.Host
	if strings.Contains(host, "@") {
		parts := strings.Split(host, "@")
		host = parts[len(parts)-1]
	}
	hn, port, err := net.SplitHostPort(host)
	if err != nil || hn == "" || port == "" || net.ParseIP(hn) == nil {
		return ""
	}
	return host
}

// RewriteConfigs produces one rewritten config per target (cycling configs if
// fewer), each pointing at its IP:port target. Every config and target is used.
func RewriteConfigs(configs, targets []string) []string {
	if len(configs) == 0 || len(targets) == 0 {
		return nil
	}
	n := len(targets)
	if len(configs) > n {
		n = len(configs)
	}
	out := make([]string, 0, n)
	for i := 0; i < n; i++ {
		out = append(out, rewriteConfig(configs[i%len(configs)], targets[i%len(targets)]))
	}
	return out
}

func rewriteConfig(configText, target string) string {
	configText = strings.TrimSpace(configText)
	if configText == "" || target == "" {
		return configText
	}
	// An INI-form WireGuard / AmneziaWG config is not a URI, so it must be
	// routed before the "://" gate below. The trailing newline keeps a blank
	// line between consecutive blocks once the results are joined, so the
	// output stays readable and re-parses into the same configs.
	if IsWireguardConfig(configText) {
		return rewriteWireguardINI(configText, target) + "\n"
	}
	if !strings.Contains(configText, "://") {
		return configText
	}
	switch {
	// vmess:// is base64-encoded JSON, not a URL — rewrite its add/port fields so
	// the config stays valid (a naive host swap corrupts it and the client
	// silently drops it).
	case strings.HasPrefix(strings.ToLower(configText), "vmess://"):
		return rewriteVmess(configText, target)
	// vpn:// is Amnezia's compressed-JSON share link, likewise not a URL.
	case strings.HasPrefix(strings.ToLower(configText), "vpn://"):
		return rewriteAmnezia(configText, target)
	}
	return rewriteURLStyle(configText, target)
}

// rewriteURLStyle repoints a standard URL-form config (vless/trojan/ss/...) at
// the target, preserving the userinfo (uuid/password) and setting the fragment
// label. Returns the input unchanged if it does not parse as a URL.
func rewriteURLStyle(configText, target string) string {
	parsed, err := url.Parse(configText)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return configText
	}
	userInfo := ""
	if strings.Contains(parsed.Host, "@") {
		userInfo = strings.SplitN(parsed.Host, "@", 2)[0]
	}
	if userInfo != "" {
		parsed.Host = userInfo + "@" + target
	} else {
		parsed.Host = target
	}
	parsed.Fragment = target
	return parsed.String()
}

// rewriteVmess decodes a vmess:// base64-JSON config, points its address/port at
// the target, and re-encodes it. Some clients emit a non-standard URL-form
// vmess (vmess://uuid@host:port?...#label) instead of base64 JSON; when the
// payload is not valid base64 JSON we fall back to URL-style rewriting so the
// host is still repointed rather than the entry silently passing through
// unchanged.
func rewriteVmess(configText, target string) string {
	payload := configText[len("vmess://"):]
	if i := strings.IndexAny(payload, "#?"); i >= 0 {
		payload = payload[:i]
	}
	raw, ok := decodeFlexibleBase64(payload)
	if !ok {
		return rewriteURLStyle(configText, target)
	}
	var m map[string]interface{}
	if err := json.Unmarshal(raw, &m); err != nil {
		return rewriteURLStyle(configText, target)
	}
	host, port, err := net.SplitHostPort(target)
	if err != nil || host == "" || net.ParseIP(host) == nil {
		return configText
	}
	m["add"] = host
	m["port"] = port // vmess JSON stores port as a string
	m["ps"] = target // display name
	re, err := json.Marshal(m)
	if err != nil {
		return configText
	}
	return "vmess://" + base64.StdEncoding.EncodeToString(re)
}

// decodeFlexibleBase64 tries the common base64 variants (std/url, padded/raw)
// since vmess payloads appear in all of them across clients.
func decodeFlexibleBase64(s string) ([]byte, bool) {
	s = strings.TrimSpace(s)
	for _, enc := range []*base64.Encoding{
		base64.StdEncoding, base64.RawStdEncoding,
		base64.URLEncoding, base64.RawURLEncoding,
	} {
		if b, err := enc.DecodeString(s); err == nil {
			return b, true
		}
	}
	return nil, false
}

func splitTokens(r rune) bool {
	return r == ' ' || r == ',' || r == ';' || r == '\n' || r == '\r' || r == '\t'
}
