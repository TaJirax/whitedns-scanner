package main

import (
	"reflect"
	"runtime"
	"testing"
)

func TestOpenPathUsesNativeOpenerAndLiteralPath(t *testing.T) {
	path := "/tmp/Scan results & reports"
	opener := map[string]string{"darwin": "open", "linux": "xdg-open", "windows": "explorer"}[runtime.GOOS]
	if opener == "" {
		t.Skip("unsupported desktop platform")
	}
	cmd := openPathCommand(path)
	if !reflect.DeepEqual(cmd.Args, []string{opener, path}) {
		t.Fatalf("native opener arguments: %q", cmd.Args)
	}
}
