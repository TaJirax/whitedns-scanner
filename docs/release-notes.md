WhiteDNS: the desktop app (WhiteDNS Scanner v0.2.0), the Android app (WhiteDNS IP Scanner v1.4.6) and the terminal app, all in one place. Find clean Cloudflare IPs, check DNS resolvers and turn the results into ready-to-use configs.

## Downloads

| App | System | File |
|---|---|---|
| Desktop | Windows 10/11 (64-bit) | `WhiteDNS-Scanner-windows-amd64.zip` |
| Desktop | macOS (Intel and Apple silicon) | `WhiteDNS-Scanner-darwin-universal.zip` |
| Desktop | Linux x64 | `WhiteDNS-Scanner-linux-amd64.tar.gz` |
| Desktop | Linux ARM64 | `WhiteDNS-Scanner-linux-arm64.tar.gz` |
| Android | Most phones (64-bit) | `WhiteDNS-IP-Scanner-arm64-v8a-release.apk` |
| Android | Older 32-bit phones | `WhiteDNS-IP-Scanner-armeabi-v7a-release.apk` |
| Android | Not sure which | `WhiteDNS-IP-Scanner-universal-release.apk` (larger, works everywhere) |
| Android | Emulators / x86 devices | `WhiteDNS-IP-Scanner-x86_64-release.apk`, `WhiteDNS-IP-Scanner-x86-release.apk` |
| Android | Google Play upload | `WhiteDNS-IP-Scanner-release.aab` |
| Terminal | Windows | `whitedns-windows-amd64.exe` |
| Terminal | Linux | `whitedns-linux-amd64`, `whitedns-linux-arm64` |
| Terminal | macOS | `whitedns-macos-arm64` (Apple silicon), `whitedns-macos-amd64` (Intel) |
| Terminal | Android (Termux) | `whitedns-termux-arm64` |

Checksums for every file are in `SHA256SUMS.txt`.

- **Desktop on Windows:** needs WebView2, which Windows 10 and 11 already include.
- **Desktop on macOS:** the app is not signed. The first time, right-click **WhiteDNS Scanner** and choose **Open**.
- **Desktop on Linux:** needs GTK 3 and WebKitGTK 4.1.
- **Android:** the APKs are signed with the same key as earlier releases, so they install over your current version.

# Desktop app: WhiteDNS Scanner v0.2.0

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

# Android app: WhiteDNS IP Scanner v1.4.6

- **A new look**, matching the desktop app: its colours, icons, light and dark themes, and accent colours. Forms are easier to scan and the progress bar shows real progress.
- **Faster everywhere.**
  - The app starts about three times faster.
  - The APK is much smaller: 9 MB for arm64, down from 32 MB.
  - ASN search answers each keystroke about 20 times faster.
  - Exporting ASN IPs is about 5 times faster.
- **Saved results:** reopen past scans from the home screen, and search inside results.
- **"Cloudflare all (13)" port preset:** scan every Cloudflare HTTPS and HTTP port in one go.
- **Speed test through a found IP:** measure download speed through the endpoint itself.
- **Anti-DPI:** optional ClientHello fragmentation for IP and proxy scans.
- **DNS rate limit:** an optional query rate, per resolver or overall, with timing jitter, for networks that drop DNS above a fixed rate.
- Works better on large screens and in landscape, keyboard handling is fixed, and changing the font size no longer resets your place.

# Android and terminal scanning engine

- **Overlapping ranges are scanned once.** ASN exports and scans merge overlapping ranges, so every IP appears exactly once. Tests check every one of the 159.6 million IPv4 addresses in the bundled ASN data.
- **The ASN tables are built in;** no data files are needed.
- Domain targets are supported in IP scans.
