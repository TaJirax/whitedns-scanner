#!/usr/bin/env bash
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
output="${1:-$root/build/mobile/scanner.aar}"
mkdir -p "$(dirname "$output")"
cd "$root/go"
go test ./engine ./mobile
go run golang.org/x/mobile/cmd/gomobile bind -target=android -androidapi 26 -o "$output" ./mobile
