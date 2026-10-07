package engine

import (
	"bufio"
	"os"
	"strings"
)

func (e *Engine) countDNSUnits(path string, seed []Target) (int, error) {
	file, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer file.Close()
	seen := map[string]bool{}
	total := 0
	add := func(t Target) {
		if !seen[t.Key()] {
			seen[t.Key()] = true
			total += e.dnsUnits(t)
		}
	}
	for _, target := range seed {
		add(target)
	}
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 64<<10), 1<<20)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parsed, err := parseBaseTargetsFromLine(line)
		if err != nil {
			return 0, err
		}
		for _, target := range parsed {
			add(target)
		}
	}
	return total, scanner.Err()
}

func (e *Engine) countProxyTargets(path string, seed []Target) (int, error) {
	file, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer file.Close()
	seen := map[string]bool{}
	add := func(t Target) { seen[normalizeProxyTarget(t, e.config.ProxyMode).URL] = true }
	for _, t := range seed {
		add(t)
	}
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 64<<10), 1<<20)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parsed, err := parseBaseTargetsFromLine(line)
		if err != nil {
			return 0, err
		}
		for _, base := range parsed {
			for _, target := range expandForMode(base, false, e.config.CustomPorts, false) {
				add(target)
			}
		}
	}
	return len(seen), scanner.Err()
}
