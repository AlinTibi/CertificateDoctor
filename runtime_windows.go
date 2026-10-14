//go:build windows

package main

import (
	"fmt"
	"syscall"
	"unsafe"

	"github.com/wailsapp/go-webview2/webviewloader"
)

func showStartupError(err error) {
	message, _ := syscall.UTF16PtrFromString(err.Error())
	title, _ := syscall.UTF16PtrFromString("Certificate Doctor could not start")
	syscall.NewLazyDLL("user32.dll").NewProc("MessageBoxW").Call(0, uintptr(unsafe.Pointer(message)), uintptr(unsafe.Pointer(title)), 0x10)
}
func checkRuntime() error {
	version, err := webviewloader.GetAvailableCoreWebView2BrowserVersionString("")
	if err != nil {
		return fmt.Errorf("Cannot check Microsoft Edge WebView2 Runtime: %w. Nothing will be downloaded automatically", err)
	}
	if version == "" {
		return fmt.Errorf("Certificate Doctor requires the separate Microsoft Edge WebView2 Runtime. Install it from https://developer.microsoft.com/microsoft-edge/webview2/ and restart. Nothing is downloaded or installed automatically")
	}
	cmp, err := webviewloader.CompareBrowserVersions(version, "94.0.992.31")
	if err != nil {
		return err
	}
	if cmp < 0 {
		return fmt.Errorf("Update the separate Microsoft Edge WebView2 Runtime before starting Certificate Doctor. No automatic installation will occur")
	}
	return nil
}
