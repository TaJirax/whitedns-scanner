WhiteDNS: desktop app v0.2.1, Android app v1.4.7 and the terminal app. This release adds **Limited network mode** for slow or lossy connections.

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

## New: Limited network mode

Clean IP scans are tuned for speed: an IP that does not accept a connection is dropped after one quick check, and on the desktop a domain that times out is not tried again. That is the right trade on a normal connection. On a slow or lossy one, where connections drop at random, it can miss IPs that would have passed on a second try.

Limited network mode brings back the earlier, more patient checks. Scans take longer, but miss fewer IPs on unreliable networks. It never brings back wrong answers: a blocked IP still never counts as clean.

**Desktop:** Settings → Requests → **Limited network mode**. When it's on:
- Service checks skip the quick connection check, so each domain gets its own connection attempts.
- Domains are checked 3 at a time instead of all at once.
- Timeouts are retried up to your **Retries** setting, including TLS timeouts in the quick check.
- The DNS scan's plain-query fallback gets its own full timeout.

When it's on, every scan page's summary line says so.

**Android:** on the IP scan form, **Limited network mode** sits under Low bandwidth mode. When it's on:
- IPs skip the quick connection check.
- At most 3 domains are checked at a time.
- Retries stay on, and **Fast** effort is turned off.
