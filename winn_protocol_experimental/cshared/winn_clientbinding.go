// Command winn_clientbinding exposes package clientbinding over a C ABI so the
// Win's VPN Flutter desktop targets (Windows, macOS, Linux) can consume Winn
// Protocol v3 through dart:ffi, matching how the app already consumes
// libwins_api. Android and iOS use gomobile bind instead and do not link this.
//
// Build with:
//
//	CGO_ENABLED=1 go build -buildmode=c-shared -o libwinn_clientbinding.<ext> ./cshared
//
// cgo is mandatory for -buildmode=c-shared. That is the reason the desktop
// targets cannot reuse the CGO_ENABLED=0 cross-compile that the protocol core
// enjoys: each desktop target needs a real C toolchain for its own platform.
//
// MEMORY CONTRACT. Every non-NULL char* this library returns is heap-allocated
// by the library and MUST be released by the caller with WinnFreeString.
//
// Two return conventions exist. They must not be confused:
//
//  1. Query and connect functions (WinnFacadeVersion, WinnConnect,
//     WinnCapabilitiesJSON, and the other emit-style entry points): a non-NULL
//     return is the result. NULL is never success. Failures write an allocated
//     error string through errorOut; after a successful call *errorOut is NULL.
//     Passing errorOut itself as NULL discards the error text, but the function
//     still returns NULL on failure — it never synthesizes success.
//  2. Validate and disconnect functions (WinnValidateReadinessJSON,
//     WinnValidateBindingJSON, WinnValidateDeviceID, WinnValidatePeerPublicKey,
//     WinnDisconnect): NULL means success. A non-NULL return is an allocated
//     error string the caller must free.
//
// A NULL C string argument is refused with a named error. It is never converted
// to "" and forwarded: that error looks like a protocol or path failure and is
// indistinguishable from censorship.
package main

/*
#include <stdlib.h>
*/
import "C"

import (
	"errors"
	"unsafe"

	"winsvpn.local/winnprotocol/clientbinding"
)

var (
	errNullSuite       = errors.New("suite is NULL")
	errNullMode        = errors.New("mode is NULL")
	errNullConnectJSON = errors.New("connect request JSON is NULL")
)

func main() {}

//export WinnFreeString
func WinnFreeString(value *C.char) {
	if value != nil {
		C.free(unsafe.Pointer(value))
	}
}

//export WinnFacadeVersion
func WinnFacadeVersion() *C.char {
	return C.CString(clientbinding.FacadeVersion())
}

//export WinnProtocolVersion
func WinnProtocolVersion() *C.char {
	return C.CString(clientbinding.ProtocolVersion())
}

//export WinnRekeyProtocolVersion
func WinnRekeyProtocolVersion() *C.char {
	return C.CString(clientbinding.RekeyProtocolVersion())
}

// WinnTunnelSupported returns 1 when clientbinding.TunnelSupported is true
// (a relay engine subprocess is configured and present on a platform that
// can spawn it), otherwise 0.
//
//export WinnTunnelSupported
func WinnTunnelSupported() C.int {
	if clientbinding.TunnelSupported() {
		return 1
	}
	return 0
}

//export WinnTunnelBackendJSON
func WinnTunnelBackendJSON() *C.char {
	return C.CString(clientbinding.TunnelBackendJSON())
}

//export WinnSupportedSuitesJSON
func WinnSupportedSuitesJSON() *C.char {
	return C.CString(clientbinding.SupportedSuitesJSON())
}

//export WinnSupportedModesJSON
func WinnSupportedModesJSON() *C.char {
	return C.CString(clientbinding.SupportedModesJSON())
}

//export WinnCapabilitiesJSON
func WinnCapabilitiesJSON(suite *C.char, errorOut **C.char) *C.char {
	if suite == nil {
		return emit("", errNullSuite, errorOut)
	}
	encoded, err := clientbinding.CapabilitiesJSON(C.GoString(suite))
	return emit(encoded, err, errorOut)
}

//export WinnRequiredAuthAlgorithm
func WinnRequiredAuthAlgorithm(suite *C.char, errorOut **C.char) *C.char {
	if suite == nil {
		return emit("", errNullSuite, errorOut)
	}
	algorithm, err := clientbinding.RequiredAuthAlgorithm(C.GoString(suite))
	return emit(algorithm, err, errorOut)
}

//export WinnCarriersForModeJSON
func WinnCarriersForModeJSON(mode *C.char, errorOut **C.char) *C.char {
	if mode == nil {
		return emit("", errNullMode, errorOut)
	}
	encoded, err := clientbinding.CarriersForModeJSON(C.GoString(mode))
	return emit(encoded, err, errorOut)
}

// WinnValidateReadinessJSON returns NULL when the document is valid, otherwise
// an allocated error string the caller must free.
//
//export WinnValidateReadinessJSON
func WinnValidateReadinessJSON(document *C.char) *C.char {
	if document == nil {
		return C.CString("readiness document is NULL")
	}
	return failure(clientbinding.ValidateReadinessJSON(C.GoString(document)))
}

//export WinnValidateBindingJSON
func WinnValidateBindingJSON(document *C.char) *C.char {
	if document == nil {
		return C.CString("binding document is NULL")
	}
	return failure(clientbinding.ValidateBindingJSON(C.GoString(document)))
}

//export WinnValidateDeviceID
func WinnValidateDeviceID(value *C.char) *C.char {
	if value == nil {
		return C.CString("device_id is NULL")
	}
	return failure(clientbinding.ValidateDeviceID(C.GoString(value)))
}

//export WinnValidatePeerPublicKey
func WinnValidatePeerPublicKey(value *C.char) *C.char {
	if value == nil {
		return C.CString("peer public key is NULL")
	}
	return failure(clientbinding.ValidatePeerPublicKey(C.GoString(value)))
}

// WinnConnect forwards to clientbinding.Connect. It must never be changed to
// report a synthetic success. A missing engine is an error, not a connected
// session. A NULL request is an error, not an empty document.
//
//export WinnConnect
func WinnConnect(requestJSON *C.char, errorOut **C.char) *C.char {
	if requestJSON == nil {
		return emit("", errNullConnectJSON, errorOut)
	}
	encoded, err := clientbinding.Connect(C.GoString(requestJSON))
	return emit(encoded, err, errorOut)
}

//export WinnStatusJSON
func WinnStatusJSON() *C.char {
	return C.CString(clientbinding.Status())
}

//export WinnDisconnect
func WinnDisconnect() *C.char {
	return failure(clientbinding.Disconnect())
}

func emit(value string, err error, errorOut **C.char) *C.char {
	if errorOut != nil {
		*errorOut = nil
	}
	if err != nil {
		if errorOut != nil {
			*errorOut = C.CString(err.Error())
		}
		return nil
	}
	return C.CString(value)
}

func failure(err error) *C.char {
	if err == nil {
		return nil
	}
	return C.CString(err.Error())
}
