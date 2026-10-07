package engine

import (
	"bufio"
	"fmt"
	"net"
	"net/url"
	"os"
	"strings"
)

const TargetIP = "ip"
const TargetDomain = "domain"

// TargetKind classifies an input line without expanding a CIDR or resolving DNS.
func TargetKind(line string) (string, error) {
	value := strings.TrimSpace(line)
	if _, right, ok := strings.Cut(value, "|"); ok {
		value = strings.TrimSpace(right)
	}
	value = strings.Trim(value, "'\"")
	if value == "" {
		return "", fmt.Errorf("empty target")
	}
	if strings.Contains(value, "/") && !strings.Contains(value, "://") {
		if _, _, err := net.ParseCIDR(value); err != nil {
			return "", fmt.Errorf("invalid IP range %q", value)
		}
		return TargetIP, nil
	}
	endpoint := value
	if !strings.Contains(endpoint, "://") {
		if net.ParseIP(endpoint) != nil && strings.Contains(endpoint, ":") {
			endpoint = "[" + endpoint + "]"
		}
		endpoint = "https://" + endpoint
	}
	u, err := url.Parse(endpoint)
	if err != nil || u.Hostname() == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return "", fmt.Errorf("invalid HTTP/HTTPS target %q", value)
	}
	if strings.HasSuffix(u.Host, ":") {
		return "", fmt.Errorf("missing target port in %q", value)
	}
	if net.ParseIP(u.Hostname()) != nil {
		return TargetIP, nil
	}
	if err := ValidateSNI(u.Hostname()); err != nil {
		return "", fmt.Errorf("invalid domain target %q", value)
	}
	numeric := true
	for _, r := range u.Hostname() {
		if (r < '0' || r > '9') && r != '.' {
			numeric = false
			break
		}
	}
	if numeric {
		return "", fmt.Errorf("invalid IP target %q", value)
	}
	return TargetDomain, nil
}

// ValidateTargetFile validates only input identities. No CIDRs are expanded.
func ValidateTargetFile(path, kind string) error {
	if kind == "" {
		return nil
	} // old settings keep their original mixed-input behavior
	if kind != TargetIP && kind != TargetDomain {
		return fmt.Errorf("choose IPs or Edge domains as the target type")
	}
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 64<<10), 1<<20)
	lineNo := 0
	for scanner.Scan() {
		lineNo++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		actual, err := TargetKind(line)
		if err != nil {
			return fmt.Errorf("line %d: %w", lineNo, err)
		}
		if actual != kind {
			if kind == TargetIP {
				return fmt.Errorf("line %d is a domain; select Edge domains or supply IPs/CIDRs for Cloudflare clean IP finder", lineNo)
			}
			return fmt.Errorf("line %d is an IP or CIDR; select Cloudflare clean IP finder or supply hostnames for Edge domains", lineNo)
		}
	}
	return scanner.Err()
}
