# Cloudflare CDN Scanner

This repository contains a scanner for checking Cloudflare-backed targets and related DNS behavior. It includes both the Go implementation under `go/` and the packaged Windows executables in the repository root.

## Included Files

- `scanner.exe` - Go-based Windows executable.
- `scanner_py.exe` - Python/PyInstaller Windows executable.
- `go/` - Go source, build scripts, and the scanner engine.
- `python/` - Python source and packaging files.
- `cidrs.txt`, `domains.txt` - sample input lists used by the scanner.

## Quick Start

1. Build the Go scanner:

   ```bash
   go build -o scanner.exe ./cmd/scanner
   ```

2. Build the cross-platform Go matrix:

   ```bash
   cd go
   pwsh ./build_matrix.ps1
   ```

   Or on Linux, macOS, or Termux:

   ```bash
   cd go
   bash ./build_matrix.sh
   ```

   This produces:

   - `scanner-android-arm64` for Termux / Android arm64
   - `scanner-linux-armv7` for Linux arm
   - `scanner-darwin-arm64` for macOS arm64
   - `scanner-windows-amd64.exe` for Windows amd64
   - `scanner-linux-amd64` for Linux amd64

3. Run the scanner and provide an input file such as `domains.txt`.

4. Review the generated output files in the repository root, including:

   - `reachable_<timestamp>.txt`
   - `full_log_<timestamp>.txt`
   - `poisoned_dns_<timestamp>.txt`
   - `hijacked_dns_<timestamp>.txt`
   - `raw_ip_dump_<timestamp>.txt`

## DNS query rate limit

Some networks (Iran, for example) drop or block DNS above a fixed rate, about 6 queries per second. An unlimited resolver scan then loses most of its probes, and working resolvers look dead. DNS and TXT modes can cap the query rate. All settings are off by default.

| Flag | Meaning |
|---|---|
| `-dns-rate 3` | Max DNS queries per second for the whole scan |
| `-dns-rate-per-resolver 3` | Max queries per second to any one resolver |
| `-dns-burst 1` | Queries allowed back-to-back (1 = evenly spaced, safest) |
| `-dns-jitter 0.3` | Timing mask: randomly lengthen gaps (0..1) so probes have no fixed rhythm |

The interactive menu asks for the rate after you pick a DNS or TXT mode. A probe waits for its slot before its timeout starts, so a capped scan is slower but still accurate. Each resolver takes several queries (UDP, TCP, DoT, DoH), so at 3 per second a scan covers roughly one resolver per second.

## Notes

- The scanner performs active network probing, so only use it on targets you are authorized to test.
- Some build outputs are intentionally ignored by git, but the two packaged executables are kept trackable in the repository root.
## Desktop GUI scan modes

The desktop and terminal menus share the same mode names. Clean IP scans include Default Ports (443/80 only), All Cloudflare Ports (13 ports), and Custom ports. Dedicated modes provide SNI scan, HTTP proxy, SOCKS proxy, DNS Resolver Discovery, DNS UDP/TCP only, and TXT Resolver Probe.

Forged SNI applies only to SNI scan. Clean IP and proxy scans do not use that setting. Proxy probes fetch a configurable test URL through the selected proxy; SOCKS5 supports username/password authentication and proxy-side DNS resolution.

Each mode keeps its own pasted targets, input file, port list, cache and reports. Inputs accept domains, IPv4/IPv6, CIDRs, explicit `host:port` endpoints, `[IPv6]:port`, and full URLs. Explicit endpoints and URLs keep their selected/default port; bare hosts expand over the mode's port list. Proxy credentials can be supplied as `http://user:pass@host:port` or `socks5://user:pass@host:port`. DNS/TXT probes support custom resolver ports.

To measure download performance, open Results and use the speed action on a successful IP or proxy row. Speed test lets you set a direct download URL, time limit and size limit, and shows Mbps, bytes received and response latency. Traffic stays pinned to the selected IP or proxy; redirects are rejected. DNS rows cannot be used as HTTP download endpoints.

Appearance settings include Taro purple, Teal tea and Milk tea palettes. Dark mode uses quiet surfaces without the left-side glow.

The total is worked out before the first probe, so progress is real from the start. Overlapping ranges count once, matching how they are scanned. **Live activity** shows a scan log by default (setup steps, every result with its reason, a line at each 10%) next to the list of passed results. Automatic concurrency reacts to local socket exhaustion within your minimum/maximum; manual concurrency stays fixed.

IP and proxy pages include optional **Anti-DPI / fragment ClientHello**, disabled by default. Configure 1–1024 bytes per fragment and 0–20 ms between writes (defaults: 64 bytes, 1 ms). It preserves TLS bytes and original hostname policy; it does not affect SNI or DNS modes. TCP writes may be coalesced by the operating system, so circumvention depends on the network. CLI equivalents: `-anti-dpi -dpi-fragment-size 64 -dpi-fragment-delay-ms 1`.

The native `WhiteDNS-Android` app keeps its tunnel scan and adds the same nine-mode scanner under **Scan → IP, proxy & DNS**. It includes provider-specific profiles, custom inputs/ports, concurrency, Anti-DPI, paged result details, selected-result download tests, saved-result review, report export and bubble-tea palettes. Its Gradle build regenerates the AAR from a sibling `whitedns-scanner` checkout. Standalone bindings can be built with `scripts/build-android-engine.ps1` or `.sh`; use JDK 17+, Go, Android SDK and NDK 29.

CLI examples from `go/`:

```powershell
go run ./cmd/scanner -mode sni -input targets.txt -sni example.com -ports 443,8443
go run ./cmd/scanner -mode http-proxy -input proxies.txt -ports 8080,3128 -proxy-test-url https://example.com/
go run ./cmd/scanner -mode socks-proxy -input proxies.txt -ports 1080 -proxy-test-url https://example.com/
```
Choose **Clean IP finder** in the menu for IPs/CIDRs, or **Edge domains** for hostnames and domain URLs. Each choice keeps its own target text, file and ports; passed-target caches are separated by `ip-` and `domain-` filename prefixes. The backend checks that the input matches the chosen type, and live results and saved reports retain that choice. Existing mixed pasted lists are split into separate drafts when the GUI loads them.
### Clean IPs for IP fronting

A clean IP is one your Worker or CDN domains can be reached through, so it can be used as the address in your configs. **Default Ports** checks HTTPS on 443 and plain HTTP on 80, **All Cloudflare Ports** covers all 13 ports, and **Custom ports** takes your own list.

- **Fronting domains:** enter the Worker / Pages hostnames from your configs, for example `my-worker.me.workers.dev`. They are tested through each IP as both SNI and Host, together with the shared service domains. An IP is clean when **any** tested domain answers through it; Results lists which domains passed.
- **Quick check:** with service checks off, each IP is checked once through the first fronting domain. A server error (5xx) from that domain counts as a failure.
- **Clean IP list:** each run saves `clean_ips.txt` (`ip:port`, fastest first), and **Copy clean IPs** in Results copies the same list.
- **Re-checks:** IPs that passed before are re-checked first on the next scan, once each.

### ASN list

**ASN list** on every scan page offers the same 1,782 networks as the Android app (built into the app; no data files). Search by name or AS number, and choose IPv4, IPv6 or both. Added networks appear as entries under the target list and are expanded only when the scan starts, so large networks such as Cloudflare (26,000 ranges) keep the page responsive. **Export IPs** writes every address of the selected networks to a file; IPv6 prefixes wider than /120 are sampled (256 addresses each). The **IP version** setting limits a scan to IPv4 or IPv6. Pasted IP lists and added ASNs are not saved: closing the app clears them.

### Config maker

**Config maker** (Workspace) is the terminal version's config maker. Paste or load vless, vmess, trojan, ss, hysteria2, WireGuard or AmneziaWG configs and a list of `IP:port` targets, or press **Use clean IPs from Results**. You get one config per target with only the address and port replaced; UUIDs, SNI, Host and paths are kept. WireGuard and AmneziaWG tunnels are also written as importable `.conf` files. **Extract IP:port** does the reverse. Output is saved under `Config maker` in the output folder.

### Results

Results are paged, filterable and exportable as CSV. Delete a single row, or use **Delete shown** (with a confirmation) to delete everything matching the current tab, search and protocol filter; the run's `results.csv` and tallies are rewritten so deleted rows stay deleted. Deleting is disabled while a scan runs.

### DNS scans

A resolver answer is judged on evidence rather than an exact IP match, because CDN domains return different IPs per region. An answer is clean when an IP matches the trusted lookup or serves a valid certificate for the domain. It is poisoned when it points to a private or reserved address (block pages such as `10.10.34.35`) or answers TLS with a certificate for another name; an unreachable IP is not called poisoned. DoH uses the standard RFC 8484 format, a dead resolver costs one timeout, and TXT passthrough (tunnel readiness) is tested over every protocol that answered.

### Edge domains and preserved service checks

Navigation groups scans into Clean IP finder, Edge domains, SNI scan, Proxy scan and DNS scan. Choose provider and scan variant inside the page; narrow windows use a single navigation dropdown.

The original Cloudflare service set is preserved exactly: `workers.dev`, `pages.dev`, `gemini.google.com`, `notebooklm.google.com`, `instagram.com`, `chatgpt.com`, `web.telegram.org`, `reddit.com`, and `claude.ai`. Cloudflare stays the default. Other providers replace the Workers/Pages slots with their platform domains while retaining the seven common service checks. Per-domain requests stay pinned to the selected candidate IP; normal domain Host/TLS names are used, and forged SNI remains confined to SNI scan. Results and CSV reports retain passed domains and per-domain outcomes.

Provider seed/probe mappings are reused from the existing `WhiteDNS-cleanip-finder/internal/config/edge.go`: Cloudflare, Cloudflare Pages, Render, Fly.io, Railway, Vercel, Netlify, Koyeb and Glitch. Fastly, Akamai and a custom profile are also available. Each provider and scan option retains independent targets, ports and request settings.

Only Cloudflare profiles offer the 13-port Cloudflare strategy. Standard HTTP/HTTPS and custom ports are available for the other profiles. These profiles select tests and configuration; provider labels are not automatic ownership claims.

### Concurrency

Every scan page has **Automatic / Manual** concurrency controls. Select **Manual** and enter **Concurrent workers** to use your own limit, just as in the TUI. The limit is shared across scan modes and saved between launches. Automatic mode uses CPU-based sizing between the selected minimum and maximum. Its minimum does not restrict manual mode: a manual limit of 7 remains valid when the automatic minimum is 200. Small input lists use only as many workers as needed. Changes apply to the next scan.

### Windows, macOS and Linux GUI builds

Build on the target OS with Go 1.26 or newer and the matching Wails CLI:

```sh
go install github.com/wailsapp/wails/v2/cmd/wails@v2.12.0
```

Run from the repository root:

| Platform | Command | Package |
|---|---|---|
| Windows x64 | `pwsh -File scripts/build-gui.ps1` | ZIP containing `WhiteDNS-Scanner.exe` |
| macOS Intel + Apple Silicon | `bash scripts/build-gui.sh darwin/universal` | ZIP containing `WhiteDNS Scanner.app` |
| Linux x64 | `bash scripts/build-gui.sh linux/amd64` | `.tar.gz` containing `WhiteDNS-Scanner` |
| Linux ARM64 | `bash scripts/build-gui.sh linux/arm64` | `.tar.gz` containing `WhiteDNS-Scanner` |

Scripts run the Go tests and vet checks before building, then put packages and SHA-256 checksums in `build/gui/<platform>/`. macOS needs Xcode Command Line Tools (`xcode-select --install`). Windows needs WebView2. Linux builds need GCC, pkg-config, GTK3 and WebKitGTK development packages; Ubuntu 24.04 uses:

```sh
sudo apt-get install build-essential pkg-config libgtk-3-dev libwebkit2gtk-4.1-dev
```

The Linux script detects WebKitGTK 4.1 and applies `webkit2_41`; 4.0 is also supported when available. The resulting Linux app needs the matching GTK/WebKit runtime libraries and `xdg-utils` for opening report folders. Run it in a graphical desktop session. macOS packages are unsigned; signing and notarization require the distributor's Apple credentials.

The **Desktop GUI builds** GitHub Actions workflow builds all four packages on native runners for pushes, pull requests, or manual runs; download them from the run's Artifacts section. Pushing a version tag (for example `v0.2.0`) runs the **Release** workflow, which builds every package and publishes a GitHub release with `SHA256SUMS.txt` and the notes in `docs/release-notes.md`.

### UI audit fixes and verification

The desktop UI keeps live result actions stable while users focus, hover or inspect a row. Updates resume when the interaction ends. Result categories are keyboard-operable filter buttons, validation errors are linked to their inputs, and light-mode text remains readable in all three palettes. Coarse-pointer controls use at least 44 px hit areas. Results display 50, 100 or 250 rows per page; CSV export includes every matching result.

The nine initial audit findings and their resolution evidence are recorded in [UI_AUDIT.md](UI_AUDIT.md). Run the frontend regression checks from the repository root:

```sh
npm ci --prefix scripts/gui-qa
npm test --prefix scripts/gui-qa
```

The checks exercise the embedded UI against controlled Wails backend responses. They cover live-focus races, error descriptions, semantics, contrast, rendering limits, responsive layouts and synthesized touch. On Windows they use installed Edge automatically. On other systems, install the test browser first:

```sh
cd scripts/gui-qa
npx playwright install chromium
```

Set `WHITEDNS_BROWSER` to a browser executable path to choose another Chromium-based browser. Measurements and screenshots are written under the ignored `build/gui/audit-fixed/` folder. The test dependencies are development tools and are not included in the desktop application.
