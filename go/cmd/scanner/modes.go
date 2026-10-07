package main

import (
	"fmt"
	"reachability-scanner/engine"
)

func configureScanMode(cfg *engine.ScanConfig, mode string) error {
	cfg.SNIScan, cfg.ScanAllPorts, cfg.DnsDiscoveryMode, cfg.DnsTxtMode, cfg.DnsUdpTcpOnly = false, false, false, false, false
	cfg.ProxyMode = ""
	switch mode {
	case "http":
	case "custom":
		if len(cfg.CustomPorts) == 0 {
			return fmt.Errorf("Custom ports mode requires -ports, e.g. -ports 80,443")
		}
	case "http-all":
		cfg.ScanAllPorts = true
	case "sni":
		cfg.SNIScan = true
		if len(cfg.CustomPorts) == 0 {
			cfg.CustomPorts = []int{443}
		}
		if err := engine.ValidateSNI(cfg.SpoofedSNI); err != nil {
			return err
		}
	case "http-proxy", "socks-proxy":
		cfg.ProxyMode = "http"
		if mode == "socks-proxy" {
			cfg.ProxyMode = "socks5"
		}
		if len(cfg.CustomPorts) == 0 {
			cfg.CustomPorts = []int{8080, 3128, 80}
			if cfg.ProxyMode == "socks5" {
				cfg.CustomPorts = []int{1080, 1081, 9050}
			}
		}
		if _, err := engine.ParseProbeURL(cfg.ProxyTestURL); err != nil {
			return err
		}
	case "dns":
		cfg.DnsDiscoveryMode = true
	case "dns-udptcp":
		cfg.DnsDiscoveryMode = true
		cfg.DnsUdpTcpOnly = true
	case "txt":
		cfg.DnsTxtMode = true
		if cfg.DnsTxtDomain == "" {
			return fmt.Errorf("TXT mode requires -txtdomain")
		}
	default:
		return fmt.Errorf("unknown scan mode %q", mode)
	}
	return nil
}
