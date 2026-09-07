//go:build windows

package main

import (
	"fmt"
	"time"
	"unsafe"

	"mitm_adm-data/windows/security/credentials/ui"

	"fyne.io/fyne/v2"
	"github.com/go-ole/go-ole"
	"github.com/saltosystems/winrt-go/windows/foundation"
)

func waitAsync(asyncOp *foundation.IAsyncOperation) (unsafe.Pointer, error) {
	disp, err := asyncOp.QueryInterface(ole.NewGUID(foundation.GUIDIAsyncInfo))
	if err != nil {
		return nil, err
	}
	asyncInfo := (*foundation.IAsyncInfo)(unsafe.Pointer(disp))
	defer asyncInfo.Release()

	for {
		status, err := asyncInfo.GetStatus()
		if err != nil {
			return nil, err
		}
		if status != 0 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}

	status, err := asyncInfo.GetStatus()
	if err != nil {
		return nil, err
	}

	if status == 1 {
		return asyncOp.GetResults()
	} else if status == 2 {
		return nil, fmt.Errorf("canceled")
	} else {
		hres, err := asyncInfo.GetErrorCode()
		if err != nil {
			return nil, err
		}
		return nil, fmt.Errorf("failed with HRESULT %08x", hres.Value)
	}
}

func verifyWindowsHello(w fyne.Window) (bool, error) {
	_ = ole.CoInitializeEx(0, ole.COINIT_MULTITHREADED)
	defer ole.CoUninitialize()

	asyncOp, err := ui.UserConsentVerifierCheckAvailabilityAsync()
	if err != nil {
		return false, fmt.Errorf("failed to check availability: %w", err)
	}
	defer asyncOp.Release()

	resPtr, err := waitAsync(asyncOp)
	if err != nil {
		return false, err
	}
	availability := ui.UserConsentVerifierAvailability(uintptr(resPtr))
	if availability != ui.UserConsentVerifierAvailabilityAvailable {
		return false, fmt.Errorf("not available (status: %d)", availability)
	}

	asyncOpVerify, err := ui.UserConsentVerifierRequestVerificationAsync("Verifizieren Sie sich, um auf das Admin-Programm zuzugreifen.")
	if err != nil {
		return false, fmt.Errorf("failed to request verification: %w", err)
	}
	defer asyncOpVerify.Release()

	resPtrVerify, err := waitAsync(asyncOpVerify)
	if err != nil {
		return false, err
	}
	result := ui.UserConsentVerificationResult(uintptr(resPtrVerify))

	if result == ui.UserConsentVerificationResultVerified {
		return true, nil
	}
	if result == ui.UserConsentVerificationResultCanceled {
		return false, fmt.Errorf("verification canceled by user")
	}
	return false, fmt.Errorf("failed (result: %d)", result)
}
