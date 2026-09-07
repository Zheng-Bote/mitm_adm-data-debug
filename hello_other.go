//go:build !windows

package main

import (
	"fyne.io/fyne/v2"
)

// verifyWindowsHello is a no-op stub for non-Windows platforms.
func verifyWindowsHello(w fyne.Window) (bool, error) {
	return true, nil
}
