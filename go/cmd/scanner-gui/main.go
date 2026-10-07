// WhiteDNS Scanner: a cross-platform GUI for the reachability / DNS resolver scanner.
// Build from the repository root with scripts/build-gui.ps1 or scripts/build-gui.sh.
package main

import (
	"embed"
	"log"

	"github.com/wailsapp/wails/v2"
	"github.com/wailsapp/wails/v2/pkg/options"
	"github.com/wailsapp/wails/v2/pkg/options/assetserver"
	"github.com/wailsapp/wails/v2/pkg/options/windows"
)

//go:embed all:frontend/dist
var assets embed.FS

func main() {
	app := NewApp()
	err := wails.Run(&options.App{
		Title:            "WhiteDNS Scanner",
		Width:            1240,
		Height:           800,
		MinWidth:         640,
		MinHeight:        560,
		AssetServer:      &assetserver.Options{Assets: assets},
		BackgroundColour: &options.RGBA{R: 14, G: 17, B: 22, A: 1},
		OnStartup:        app.startup,
		Bind:             []interface{}{app},
		Windows:          &windows.Options{Theme: windows.SystemDefault},
	})
	if err != nil {
		log.Fatal(err)
	}
}
