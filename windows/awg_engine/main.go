//go:build windows

// SPDX-License-Identifier: MIT
//
// Win's VPN hosts the exact AmneziaWG Go engine used by the reviewed official
// Windows client, but keeps lifecycle and configuration under the already
// privileged, authenticated Win's VPN tunnel manager. The engine accepts no
// paths or configuration on its command line and exposes only AmneziaWG's
// administrator/System protected UAPI pipe.
package main

import (
	"os"
	"os/signal"
	"unsafe"

	"github.com/amnezia-vpn/amneziawg-go/v3/conn"
	"github.com/amnezia-vpn/amneziawg-go/v3/device"
	"github.com/amnezia-vpn/amneziawg-go/v3/ipc"
	"github.com/amnezia-vpn/amneziawg-go/v3/tun"
	"golang.org/x/sys/windows"
)

const (
	interfaceName = "winsvpn"
	stopEventName = `Global\WinsVPN.AwgEngine.Stop.v1`
)

func runningAsLocalSystem() bool {
	token := windows.GetCurrentProcessToken()
	user, err := token.GetTokenUser()
	if err != nil {
		return false
	}
	systemSID, err := windows.StringToSid("S-1-5-18")
	return err == nil && user.User.Sid.Equals(systemSID)
}

func createStopEvent() (windows.Handle, bool) {
	descriptor, err := windows.SecurityDescriptorFromString(
		"O:SYD:P(A;;GA;;;SY)(A;;GA;;;BA)S:(ML;;NWNRNX;;;HI)",
	)
	if err != nil {
		return 0, false
	}
	name, err := windows.UTF16PtrFromString(stopEventName)
	if err != nil {
		return 0, false
	}
	attributes := windows.SecurityAttributes{
		Length:             uint32(unsafe.Sizeof(windows.SecurityAttributes{})),
		SecurityDescriptor: descriptor,
	}
	handle, createErr := windows.CreateEvent(&attributes, 1, 0, name)
	if handle == 0 || createErr == windows.ERROR_ALREADY_EXISTS {
		if handle != 0 {
			windows.CloseHandle(handle)
		}
		return 0, false
	}
	if createErr != nil {
		windows.CloseHandle(handle)
		return 0, false
	}
	return handle, true
}

func main() {
	if len(os.Args) != 1 || !runningAsLocalSystem() {
		os.Exit(2)
	}
	stopEvent, ok := createStopEvent()
	if !ok {
		os.Exit(3)
	}
	defer windows.CloseHandle(stopEvent)

	// A product-specific type avoids colliding with unrelated Wintun adapters.
	tun.WintunTunnelType = "WinsVPN"
	tunDevice, err := tun.CreateTUN(interfaceName, 1420)
	if err != nil {
		os.Exit(4)
	}
	logger := device.NewLogger(device.LogLevelSilent, "")
	awgDevice := device.NewDevice(tunDevice, conn.NewDefaultBind(), logger)
	if err := awgDevice.Up(); err != nil {
		awgDevice.Close()
		os.Exit(5)
	}

	uapi, err := ipc.UAPIListen(interfaceName)
	if err != nil {
		awgDevice.Close()
		os.Exit(6)
	}
	acceptErrors := make(chan error, 1)
	go func() {
		for {
			connection, err := uapi.Accept()
			if err != nil {
				acceptErrors <- err
				return
			}
			go awgDevice.IpcHandle(connection)
		}
	}()

	stopRequested := make(chan struct{}, 1)
	go func() {
		waitResult, _ := windows.WaitForSingleObject(stopEvent, windows.INFINITE)
		if waitResult == windows.WAIT_OBJECT_0 {
			stopRequested <- struct{}{}
		}
	}()
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, os.Interrupt, windows.SIGTERM)
	select {
	case <-stopRequested:
	case <-signals:
	case <-acceptErrors:
	case <-awgDevice.Wait():
	}

	uapi.Close()
	awgDevice.Close()
}
