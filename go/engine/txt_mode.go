package engine

import (
	"crypto/rand"
	"encoding/hex"
	"net"
	"os"
	"strconv"
	"strings"
)

// buildTxtQueryName prepends a random label so TXT probes avoid cache hits.
func buildTxtQueryName(domain string) string {
	cleanDomain := strings.TrimSpace(domain)
	cleanDomain = strings.TrimSuffix(cleanDomain, ".")
	if cleanDomain == "" {
		cleanDomain = "example.invalid"
	}

	var nonce [6]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return "random." + cleanDomain
	}
	return hex.EncodeToString(nonce[:]) + "." + cleanDomain
}

// loadTxtResolverTargets resolves either a file-backed resolver list or an
// inline, comma/newline separated resolver string into scan targets.
func loadTxtResolverTargets(filePath, raw string) ([]Target, error) {
	text := strings.TrimSpace(raw)
	if text == "" {
		data, err := os.ReadFile(filePath)
		if err != nil {
			return nil, err
		}
		text = string(data)
	}

	lines := strings.FieldsFunc(text, func(r rune) bool { return r == ',' || r == '\n' || r == '\r' || r == ';' })
	seen := map[string]struct{}{}
	var targets []Target
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		tokens := []string{line}
		if !strings.Contains(line, "|") {
			tokens = strings.Fields(line)
		}
		for _, token := range tokens {
			for _, prefix := range []string{"dns://", "dns-txt://", "udp://", "tcp://"} {
				token = strings.Replace(token, prefix, "https://", 1)
			}
			parsed, err := parseBaseTargetsFromLine(token)
			if err != nil {
				continue
			}
			for _, target := range parsed {
				if !target.ExplicitPort {
					target.Port = 53
				}
				target.Scheme = "dns"
				target.URL = "dns-txt://" + net.JoinHostPort(target.Host, strconv.Itoa(target.Port))
				if _, ok := seen[target.URL]; ok {
					continue
				}
				seen[target.URL] = struct{}{}
				targets = append(targets, target)
			}
		}
	}
	return targets, nil
}

func parseTxtResolverToken(token string) (Target, bool) {
	line := strings.TrimSpace(token)
	if line == "" || strings.HasPrefix(line, "#") {
		return Target{}, false
	}

	label := ""
	value := line
	if idx := strings.Index(line, "|"); idx != -1 {
		label = strings.TrimSpace(line[:idx])
		value = strings.TrimSpace(line[idx+1:])
	}

	value = strings.Trim(value, "'\"")
	value = strings.TrimPrefix(strings.TrimPrefix(value, "dns://"), "dns-txt://")
	value = strings.TrimPrefix(strings.TrimPrefix(value, "udp://"), "tcp://")
	value = strings.TrimPrefix(strings.TrimPrefix(value, "https://"), "http://")
	value = strings.Trim(value, "[]")
	value = strings.TrimSuffix(value, ".")

	host := value
	if strings.Count(host, ":") == 1 {
		if splitHost, _, err := net.SplitHostPort(host); err == nil {
			host = splitHost
		} else {
			parts := strings.SplitN(host, ":", 2)
			if net.ParseIP(parts[0]) != nil {
				host = parts[0]
			}
		}
	}

	if net.ParseIP(host) == nil {
		return Target{}, false
	}
	if label == "" {
		label = host
	}

	return Target{
		Label:  label,
		URL:    "dns-txt://" + host,
		Host:   host,
		Port:   53,
		Scheme: "dns",
	}, true
}
