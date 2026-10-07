package main

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"reachability-scanner/internal/configmaker"
)

// The config maker is the TUI's (cleanip-finder internal/configmaker): it
// repoints proxy configs (vless, vmess, trojan, ss, hysteria, WireGuard,
// AmneziaWG) at clean IP:port targets, or extracts IP:port from configs.

// ConfigMakerInfo is what pasted text parses into, from the parser the
// rewrite itself uses, so the counts on screen are what will be produced.
type ConfigMakerInfo struct {
	Configs int    `json:"configs"`
	Summary string `json:"summary"` // e.g. "2 vless  |  1 AmneziaWG"
	Targets int    `json:"targets"`
}

type ConfigMakerResult struct {
	Text      string `json:"text"`
	Count     int    `json:"count"`
	Path      string `json:"path"`      // the saved .txt
	WireGuard int    `json:"wireguard"` // importable .conf files written beside it
}

func (a *App) ConfigMakerInspect(configs, targets string) ConfigMakerInfo {
	parsed := configmaker.ExtractConfigs(configs)
	return ConfigMakerInfo{Configs: len(parsed), Summary: configmaker.FormatTally(parsed), Targets: len(configmaker.ExtractTargets(targets))}
}

// ConfigMakerRewrite writes one config per target (cycling the configs when
// there are fewer), each pointing at its IP:port.
func (a *App) ConfigMakerRewrite(configs, targets string) (ConfigMakerResult, error) {
	parsed := configmaker.ExtractConfigs(configs)
	if len(parsed) == 0 {
		return ConfigMakerResult{}, fmt.Errorf("no proxy configs found; paste vless://, vmess://, trojan://, ss:// or WireGuard configs")
	}
	ips := configmaker.ExtractTargets(targets)
	if len(ips) == 0 {
		return ConfigMakerResult{}, fmt.Errorf("no IP:port targets found; paste clean IPs such as 104.16.0.1:443")
	}
	out := configmaker.RewriteConfigs(parsed, ips)
	stem := "rewritten-" + time.Now().Format("20060102-150405")
	path, err := a.saveConfigMakerFile(stem+".txt", out)
	if err != nil {
		return ConfigMakerResult{}, err
	}
	confs, err := configmaker.WriteWireguardConfFiles(filepath.Dir(path), stem, out)
	if err != nil {
		return ConfigMakerResult{}, fmt.Errorf("saved %s, but the WireGuard .conf files failed: %v", path, err)
	}
	return ConfigMakerResult{Text: strings.Join(out, "\n"), Count: len(out), Path: path, WireGuard: len(confs)}, nil
}

// ConfigMakerExtract lists the IP:port endpoints inside configs or any text.
func (a *App) ConfigMakerExtract(configs string) (ConfigMakerResult, error) {
	ips := configmaker.ExtractIPs(configs)
	if len(ips) == 0 {
		return ConfigMakerResult{}, fmt.Errorf("no IP:port endpoints found")
	}
	path, err := a.saveConfigMakerFile("extracted-ips-"+time.Now().Format("20060102-150405")+".txt", ips)
	if err != nil {
		return ConfigMakerResult{}, err
	}
	return ConfigMakerResult{Text: strings.Join(ips, "\n"), Count: len(ips), Path: path}, nil
}

func (a *App) saveConfigMakerFile(name string, lines []string) (string, error) {
	dir := filepath.Join(a.GetSettings().OutputDir, "Config maker")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	path := filepath.Join(dir, name)
	return path, os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o644)
}

// ReadTextFile loads a picked configs or targets file into the page.
func (a *App) ReadTextFile(path string) (string, error) {
	info, err := os.Stat(path)
	if err != nil {
		return "", err
	}
	if info.Size() > 16<<20 {
		return "", fmt.Errorf("%s is larger than 16 MB", filepath.Base(path))
	}
	raw, err := os.ReadFile(path)
	return string(bytes.TrimPrefix(raw, []byte{0xEF, 0xBB, 0xBF})), err // editors may add a UTF-8 BOM
}
