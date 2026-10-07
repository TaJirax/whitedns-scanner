package configmaker

// WireGuard and AmneziaWG support.
//
// Unlike vless/vmess/trojan/ss/hysteria, a WireGuard config is not a URI: it is
// a multi-line INI document ([Interface] / [Peer]) and AmneziaWG adds its
// obfuscation keys (Jc/Jmin/Jmax/S1/S2/H1-H4) to the same format. The whole
// block is one config, so it has to be lifted out of the raw text before the
// line-oriented URI scanning runs, and repointed by rewriting its Endpoint
// line rather than by swapping a URL host.
//
// Amnezia's own share format (vpn://) is a base64url envelope around
// zlib-compressed JSON describing the server plus its containers. That JSON's
// shape varies by Amnezia version, so it is rewritten structurally — walk the
// decoded value, repoint the host/port fields and any embedded WireGuard INI —
// instead of against a hardcoded schema.

import (
	"bytes"
	"compress/zlib"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

var (
	// wgSectionRe matches an INI section header line, e.g. "[Peer]".
	wgSectionRe = regexp.MustCompile(`^\[[A-Za-z][A-Za-z0-9_ -]*\]$`)
	// wgKeyRe matches an INI "Key =" line start. It deliberately does not match
	// a proxy URI (vless://host?type=ws), which also contains "=".
	wgKeyRe = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_-]*[ \t]*=`)
	// wgEndpointRe captures the "Endpoint = host:port" line, keeping its
	// original indentation and spacing in group 1 so a rewrite is byte-faithful
	// everywhere except the value.
	wgEndpointRe = regexp.MustCompile(`(?im)^([ \t]*Endpoint[ \t]*=[ \t]*)([^\r\n]*)$`)
)

// isWGSection reports whether line is the INI section header called name
// (case-insensitive). An empty name matches any section header.
func isWGSection(line, name string) bool {
	trimmed := strings.TrimSpace(strings.TrimRight(line, "\r"))
	if !wgSectionRe.MatchString(trimmed) {
		return false
	}
	if name == "" {
		return true
	}
	return strings.EqualFold(trimmed, "["+name+"]")
}

// IsWireguardConfig reports whether text is an INI-form WireGuard / AmneziaWG
// config rather than a URI-form proxy config.
func IsWireguardConfig(text string) bool {
	for _, line := range strings.Split(text, "\n") {
		if isWGSection(line, "Interface") {
			return true
		}
	}
	return false
}

// IsAmneziaWGConfig reports whether an INI-form config carries the AmneziaWG
// obfuscation parameters, so callers can label it as AmneziaWG rather than
// plain WireGuard.
func IsAmneziaWGConfig(text string) bool {
	for _, line := range strings.Split(text, "\n") {
		key, _, found := strings.Cut(strings.TrimSpace(line), "=")
		if !found {
			continue
		}
		switch strings.ToLower(strings.TrimSpace(key)) {
		case "jc", "jmin", "jmax", "s1", "s2", "h1", "h2", "h3", "h4":
			return true
		}
	}
	return false
}

// ExtractWireguardBlocks lifts every INI-form WireGuard / AmneziaWG config out
// of raw and returns them alongside raw with those blocks removed, so the
// caller can scan the remainder for URI-form configs without the INI lines
// being mistaken for one config per line.
//
// A block starts at an "[Interface]" header and ends at the last consecutive
// INI line after it — the next "[Interface]", or any line that is not a
// section header, a "Key = value" pair, a comment or blank, closes it. That
// keeps proxy URIs pasted directly below a WireGuard config out of the block.
func ExtractWireguardBlocks(raw string) ([]string, string) {
	lines := strings.Split(raw, "\n")
	var blocks []string
	rest := make([]string, 0, len(lines))

	for i := 0; i < len(lines); i++ {
		if !isWGSection(lines[i], "Interface") {
			rest = append(rest, lines[i])
			continue
		}
		last := i
		for j := i + 1; j < len(lines); j++ {
			trimmed := strings.TrimSpace(lines[j])
			// Blank lines and comments may sit inside a config but must not by
			// themselves extend it, or trailing whitespace would swallow text.
			if trimmed == "" || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, ";") {
				continue
			}
			if isWGSection(lines[j], "Interface") {
				break
			}
			if isWGSection(lines[j], "") || wgKeyRe.MatchString(trimmed) {
				last = j
				continue
			}
			break
		}
		blocks = append(blocks, strings.Join(lines[i:last+1], "\n"))
		i = last
	}
	return blocks, strings.Join(rest, "\n")
}

// rewriteWireguardINI repoints a WireGuard / AmneziaWG config at target,
// leaving every other byte (keys, obfuscation parameters, comments, spacing)
// untouched. A config with no Endpoint line gets one added to its [Peer]
// section; without a [Peer] section there is nothing to repoint, so the config
// is returned unchanged rather than silently corrupted.
func rewriteWireguardINI(conf, target string) string {
	if wgEndpointRe.MatchString(conf) {
		return wgEndpointRe.ReplaceAllString(conf, "${1}"+target)
	}
	lines := strings.Split(conf, "\n")
	for i, line := range lines {
		if !isWGSection(line, "Peer") {
			continue
		}
		out := make([]string, 0, len(lines)+1)
		out = append(out, lines[:i+1]...)
		out = append(out, "Endpoint = "+target)
		out = append(out, lines[i+1:]...)
		return strings.Join(out, "\n")
	}
	return conf
}

// wireguardEndpoint returns the "ip:port" a WireGuard config points at, or ""
// when its Endpoint is missing or is a hostname rather than a literal IP.
func wireguardEndpoint(conf string) string {
	match := wgEndpointRe.FindStringSubmatch(conf)
	if match == nil {
		return ""
	}
	value := strings.TrimSpace(match[2])
	// Drop a trailing inline comment, which wg-quick allows.
	if i := strings.IndexAny(value, "#;"); i >= 0 {
		value = strings.TrimSpace(value[:i])
	}
	return normalizeIPPort(value)
}

// normalizeIPPort returns value as "ip:port" when it is exactly that, else "".
func normalizeIPPort(value string) string {
	host, port, err := net.SplitHostPort(value)
	if err != nil || port == "" || net.ParseIP(host) == nil {
		return ""
	}
	if _, err := strconv.Atoi(port); err != nil {
		return ""
	}
	return net.JoinHostPort(host, port)
}

// ------------------------------------------------------------
//  Amnezia vpn:// share links
// ------------------------------------------------------------

// decodeAmnezia unpacks a vpn:// payload into its JSON. qCompressed reports
// which envelope was used, so the config can be re-encoded the same way and
// stay importable by the client that produced it.
func decodeAmnezia(configText string) (data []byte, qCompressed bool, ok bool) {
	payload := configText[len("vpn://"):]
	if i := strings.IndexAny(payload, "#?"); i >= 0 {
		payload = payload[:i]
	}
	raw, decoded := decodeFlexibleBase64(payload)
	if !decoded {
		return nil, false, false
	}
	// Qt's qCompress prefixes the zlib stream with a 4-byte big-endian length.
	if len(raw) > 4 {
		if out, err := inflate(raw[4:]); err == nil && json.Valid(out) {
			return out, true, true
		}
	}
	if out, err := inflate(raw); err == nil && json.Valid(out) {
		return out, false, true
	}
	// Older exports embed the JSON uncompressed.
	if json.Valid(raw) {
		return raw, false, true
	}
	return nil, false, false
}

func inflate(b []byte) ([]byte, error) {
	zr, err := zlib.NewReader(bytes.NewReader(b))
	if err != nil {
		return nil, err
	}
	defer zr.Close()
	return io.ReadAll(zr)
}

// encodeAmnezia repacks JSON into a vpn:// link using the same envelope it was
// decoded from.
func encodeAmnezia(data []byte, qCompressed bool) string {
	var buf bytes.Buffer
	if qCompressed {
		if err := binary.Write(&buf, binary.BigEndian, uint32(len(data))); err != nil {
			return ""
		}
	}
	zw := zlib.NewWriter(&buf)
	if _, err := zw.Write(data); err != nil {
		return ""
	}
	if err := zw.Close(); err != nil {
		return ""
	}
	return "vpn://" + base64.RawURLEncoding.EncodeToString(buf.Bytes())
}

// rewriteAmnezia repoints an Amnezia vpn:// share link at target. The decoded
// JSON is walked rather than matched against a fixed schema, so a config from
// any Amnezia version keeps every field it came with.
func rewriteAmnezia(configText, target string) string {
	host, port, err := net.SplitHostPort(target)
	if err != nil || net.ParseIP(host) == nil {
		return configText
	}
	data, qCompressed, ok := decodeAmnezia(configText)
	if !ok {
		return configText
	}
	var value interface{}
	if err := json.Unmarshal(data, &value); err != nil {
		return configText
	}
	rewritten, err := json.Marshal(repointAmneziaValue(value, host, port, target))
	if err != nil {
		return configText
	}
	out := encodeAmnezia(rewritten, qCompressed)
	if out == "" {
		return configText
	}
	return out
}

// amneziaHostKeys are the JSON fields Amnezia stores a server address in.
var amneziaHostKeys = map[string]struct{}{
	"hostname": {}, "host": {}, "server": {}, "address": {}, "server_address": {},
}

// repointAmneziaValue walks a decoded Amnezia config, repointing the server
// address and port fields and any embedded WireGuard INI at the target. Nested
// JSON stored as a string (Amnezia's "last_config") is decoded, rewritten and
// re-encoded so the container's own copy of the config moves too.
func repointAmneziaValue(value interface{}, host, port, target string) interface{} {
	switch typed := value.(type) {
	case map[string]interface{}:
		for key, child := range typed {
			lower := strings.ToLower(key)
			if _, isHost := amneziaHostKeys[lower]; isHost {
				if _, isString := child.(string); isString {
					typed[key] = host
					continue
				}
			}
			if lower == "port" {
				switch child.(type) {
				case string:
					typed[key] = port
					continue
				case float64:
					if n, err := strconv.Atoi(port); err == nil {
						typed[key] = float64(n)
						continue
					}
				}
			}
			typed[key] = repointAmneziaValue(child, host, port, target)
		}
		return typed
	case []interface{}:
		for i, child := range typed {
			typed[i] = repointAmneziaValue(child, host, port, target)
		}
		return typed
	case string:
		if IsWireguardConfig(typed) {
			return rewriteWireguardINI(typed, target)
		}
		// "last_config" and friends hold a whole JSON document as a string.
		if nested, ok := decodeNestedJSON(typed); ok {
			if out, err := json.Marshal(repointAmneziaValue(nested, host, port, target)); err == nil {
				return string(out)
			}
		}
		return typed
	}
	return value
}

// decodeNestedJSON parses a string that holds a JSON object or array. The
// leading-brace check keeps plain values ("443", "true") from being treated as
// nested documents.
func decodeNestedJSON(s string) (interface{}, bool) {
	trimmed := strings.TrimSpace(s)
	if !strings.HasPrefix(trimmed, "{") && !strings.HasPrefix(trimmed, "[") {
		return nil, false
	}
	var value interface{}
	if err := json.Unmarshal([]byte(trimmed), &value); err != nil {
		return nil, false
	}
	return value, true
}

// amneziaEndpoint returns the "ip:port" an Amnezia vpn:// link points at,
// preferring an embedded WireGuard Endpoint and falling back to the config's
// own host/port fields.
func amneziaEndpoint(configText string) string {
	data, _, ok := decodeAmnezia(configText)
	if !ok {
		return ""
	}
	var value interface{}
	if err := json.Unmarshal(data, &value); err != nil {
		return ""
	}
	host, port := "", ""
	collectAmneziaEndpoint(value, &host, &port)
	if host == "" {
		return ""
	}
	if port == "" {
		port = "443"
	}
	return normalizeIPPort(net.JoinHostPort(host, port))
}

// collectAmneziaEndpoint walks a decoded Amnezia config filling in the first
// host and port it finds. An embedded WireGuard Endpoint wins outright, since
// it is the address the tunnel actually dials.
func collectAmneziaEndpoint(value interface{}, host, port *string) {
	switch typed := value.(type) {
	case map[string]interface{}:
		for key, child := range typed {
			lower := strings.ToLower(key)
			if text, isString := child.(string); isString {
				if _, isHost := amneziaHostKeys[lower]; isHost && *host == "" {
					*host = strings.TrimSpace(text)
				}
			}
			if lower == "port" && *port == "" {
				switch typedPort := child.(type) {
				case string:
					*port = strings.TrimSpace(typedPort)
				case float64:
					*port = strconv.Itoa(int(typedPort))
				}
			}
			collectAmneziaEndpoint(child, host, port)
		}
	case []interface{}:
		for _, child := range typed {
			collectAmneziaEndpoint(child, host, port)
		}
	case string:
		if endpoint := wireguardEndpoint(typed); endpoint != "" {
			if h, p, err := net.SplitHostPort(endpoint); err == nil {
				*host, *port = h, p
				return
			}
		}
		if nested, ok := decodeNestedJSON(typed); ok {
			collectAmneziaEndpoint(nested, host, port)
		}
	}
}

// WriteWireguardConfFiles writes every INI-form WireGuard / AmneziaWG config in
// configs to its own file under dir/stem, and returns the paths written.
//
// WireGuard and AmneziaWG clients import one tunnel per .conf file and cannot
// read the combined multi-config text output, so without this the rewritten
// configs would have to be split by hand. The files go in their own folder and
// are named "wg-N.conf" because the WireGuard Android client derives the tunnel
// name from the filename and rejects anything over 15 characters — a
// timestamped name would not import.
func WriteWireguardConfFiles(dir, stem string, configs []string) ([]string, error) {
	var written []string
	for _, conf := range configs {
		if !IsWireguardConfig(conf) {
			continue
		}
		if written == nil {
			if err := os.MkdirAll(filepath.Join(dir, stem), 0o755); err != nil {
				return nil, err
			}
		}
		path := filepath.Join(dir, stem, fmt.Sprintf("wg-%d.conf", len(written)+1))
		if err := os.WriteFile(path, []byte(strings.TrimSpace(conf)+"\n"), 0o644); err != nil {
			return written, err
		}
		written = append(written, path)
	}
	return written, nil
}

// Endpoint returns the "ip:port" a config points at, for any format the config
// maker understands, or "" when it carries no literal IP endpoint.
func Endpoint(config string) string {
	config = strings.TrimSpace(config)
	if IsWireguardConfig(config) {
		return wireguardEndpoint(config)
	}
	return HostPort(config)
}

// FormatName names the protocol of a single parsed config, for display.
func FormatName(raw string) string {
	raw = strings.TrimSpace(raw)
	if IsWireguardConfig(raw) {
		if IsAmneziaWGConfig(raw) {
			return "AmneziaWG"
		}
		return "WireGuard"
	}
	scheme, _, found := strings.Cut(raw, "://")
	if !found {
		return "unknown"
	}
	switch strings.ToLower(scheme) {
	case "vpn":
		return "Amnezia"
	case "wireguard", "wg", "awg":
		return "WireGuard"
	case "hy2", "hysteria2":
		return "hysteria2"
	default:
		return strings.ToLower(scheme)
	}
}

// FormatTally summarises the protocols in a parsed config list, in the order
// they first appear, e.g. "2 vless  |  1 AmneziaWG". It lets a caller show that
// a multi-line WireGuard block was read as one config rather than split into
// lines, before anything is written.
func FormatTally(configs []string) string {
	counts := map[string]int{}
	order := make([]string, 0, len(configs))
	for _, config := range configs {
		name := FormatName(config)
		if _, seen := counts[name]; !seen {
			order = append(order, name)
		}
		counts[name]++
	}
	parts := make([]string, 0, len(order))
	for _, name := range order {
		parts = append(parts, fmt.Sprintf("%d %s", counts[name], name))
	}
	return strings.Join(parts, "  |  ")
}
