#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
gui_dir="$repo_root/go/cmd/scanner-gui"
native_os="$(go env GOOS)"
native_arch="$(go env GOARCH)"
target="${1:-$native_os/$native_arch}"
if [[ "$native_os" == darwin && $# == 0 ]]; then target=darwin/universal; fi
if [[ "${target%%/*}" != "$native_os" ]]; then
    echo "Build $target on its native OS. Windows uses scripts/build-gui.ps1." >&2
    exit 1
fi
if ! command -v wails >/dev/null; then
    echo "Install Wails: go install github.com/wailsapp/wails/v2/cmd/wails@v2.12.0" >&2
    exit 1
fi

tag_args=()
case "$target" in
    linux/amd64|linux/arm64)
        if [[ "${target##*/}" != "$native_arch" ]]; then
            echo "Linux builds require a runner with the matching CPU architecture." >&2
            exit 1
        fi
        if pkg-config --exists gtk+-3.0 webkit2gtk-4.1; then
            tag_args=(-tags webkit2_41)
        elif ! pkg-config --exists gtk+-3.0 webkit2gtk-4.0; then
            echo "Install GTK3 and WebKitGTK development packages (see README)." >&2
            exit 1
        fi
        ;;
    darwin/universal|darwin/amd64|darwin/arm64) ;;
    *) echo "Unsupported GUI target: $target" >&2; exit 1 ;;
esac

cd "$repo_root/go"
go test ${tag_args[@]+"${tag_args[@]}"} ./...
go vet ${tag_args[@]+"${tag_args[@]}"} ./...
cd "$gui_dir"
wails build -platform "$target" ${tag_args[@]+"${tag_args[@]}"} -trimpath -ldflags '-s -w' -skipbindings

output_dir="$repo_root/build/gui/${target//\//-}"
mkdir -p "$output_dir"
cp "$repo_root/README.md" "$output_dir/README.md"
case "$native_os" in
    linux)
        archive="WhiteDNS-Scanner-${target//\//-}.tar.gz"
        tar -czf "$output_dir/$archive" -C "$gui_dir/build/bin" WhiteDNS-Scanner -C "$repo_root" README.md
        (cd "$output_dir" && sha256sum "$archive" > "$archive.sha256")
        ;;
    darwin)
        app="$gui_dir/build/bin/WhiteDNS Scanner.app"
        if [[ "$target" == darwin/universal ]]; then
            lipo "$app/Contents/MacOS/WhiteDNS-Scanner" -verify_arch x86_64 arm64
        fi
        archive="WhiteDNS-Scanner-${target//\//-}.zip"
        ditto -c -k --sequesterRsrc --keepParent "$app" "$output_dir/$archive"
        (cd "$output_dir" && shasum -a 256 "$archive" > "$archive.sha256")
        ;;
esac
echo "Built $output_dir/$archive"
