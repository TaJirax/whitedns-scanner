package main

import (
	"os/exec"
	"runtime"
)

func openPathCommand(path string) *exec.Cmd {
	switch runtime.GOOS {
	case "darwin":
		return exec.Command("open", path)
	case "linux":
		return exec.Command("xdg-open", path)
	default:
		return exec.Command("explorer", path)
	}
}
