WhiteDNS Scanner desktop app: find clean Cloudflare IPs, check DNS resolvers and turn the results into ready-to-use configs.

## Downloads

| System | File |
|---|---|
| Windows 10/11 (64-bit) | `WhiteDNS-Scanner-windows-amd64.zip` |
| macOS (Intel and Apple silicon) | `WhiteDNS-Scanner-darwin-universal.zip` |
| Linux x64 | `WhiteDNS-Scanner-linux-amd64.tar.gz` |
| Linux ARM64 | `WhiteDNS-Scanner-linux-arm64.tar.gz` |

Unpack and run `WhiteDNS-Scanner`. Checksums are in `SHA256SUMS.txt`. On Linux the app needs GTK 3 and WebKitGTK 4.1.

## Finding clean IPs

- **Default Ports scans HTTPS on 443 and plain HTTP on 80** for every IP. *All Cloudflare Ports* covers all 13 ports, and *Custom ports* takes your own list.
- **An IP is clean when any tested domain answers through it.** Put your own Worker / Pages hostnames in **Fronting domains**. They are tested through each IP as both SNI and Host, alongside the shared services.
- **Copy clean IPs** in Results copies every passed IP as `ip:port`, fastest first. Each run also saves them to `clean_ips.txt`.
- IPs that passed before are re-checked first on the next scan, and are no longer scanned twice.

## ASN list

- **Pick from the same 1,782 networks as the Android app** on every scan page, with IPv4, IPv6 or both. Search by name or AS number.
- Added networks appear as entries and are expanded only when the scan starts, so even Cloudflare's 26,000 ranges keep the app responsive.
- **Export IPs** saves every address of the selected networks to a file.
- An **IP version** setting limits any scan to IPv4 or IPv6.

## Config maker

Paste your vless, vmess, trojan, ss, hysteria2, WireGuard or AmneziaWG configs and a list of clean IPs, or press **Use clean IPs from Results**. You get one config per IP, with only the address and port changed. It can also extract the `IP:port` endpoints from existing configs. Output is saved under the output folder in `Config maker`.

## Scanning

- **The total appears as soon as a scan starts** and the progress bar shows real progress. Overlapping ranges are counted once.
- **Live activity shows a scan log:** setup steps, every result with its reason, and progress milestones.
- **Results can be deleted:** one row at a time, or everything matching the current filters. The run's saved results are updated too.
- **The pasted IP list and added ASNs are cleared when the app closes.**

## Fixes

- **Clean IP scans give honest answers and are much faster.**
  - Every IP check now sends a real hostname, because networks silently drop TLS connections that don't name one.
  - A blocked TLS handshake is no longer reported as clean.
  - Dead IPs fail after one connection attempt instead of tens of seconds.
- **DNS scans find working resolvers again.**
  - Genuine answers from CDN domains are no longer flagged as poisoned.
  - DoH works with standard servers.
  - Each dead resolver costs one timeout instead of two.
  - The tunnel-ready check runs over every protocol that answered.
- **SNI scans need one connection per IP instead of two.**
