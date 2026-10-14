package main

import (
	"embed"

	"github.com/wailsapp/wails/v2"
	"github.com/wailsapp/wails/v2/pkg/options"
	"github.com/wailsapp/wails/v2/pkg/options/assetserver"
	"github.com/wailsapp/wails/v2/pkg/options/windows"
)

//go:embed all:frontend/dist
var assets embed.FS

func main() {
	if err := checkRuntime(); err != nil {
		showStartupError(err)
		return
	}
	app := NewApp()
	err := wails.Run(&options.App{Title: "Certificate Doctor", Width: 1380, Height: 900, MinWidth: 1000, MinHeight: 660,
		AssetServer: &assetserver.Options{Assets: assets}, BackgroundColour: &options.RGBA{R: 13, G: 19, B: 29, A: 255},
		OnStartup: app.startup, Bind: []interface{}{app}, DragAndDrop: &options.DragAndDrop{EnableFileDrop: true, DisableWebViewDrop: true}, Windows: &windows.Options{DisableWindowIcon: false},
	})
	if err != nil {
		showStartupError(err)
	}
}
