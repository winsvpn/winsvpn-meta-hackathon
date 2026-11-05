//go:build darwin

// Carrier-profile entry point for the C ABI.
//
// # The gap this closes
//
// datapath/carrier.go states the boundary this archive has honoured since it
// was written: "a carrier needs an authenticated configuration that has no
// business crossing the C ABI... the C surface in cdatapath therefore still
// builds direct-awg only; a Go host that wants a carrier constructs the
// dialer itself and calls [OpenWithCarrier]." That is still true, letter for
// letter, after this file: nothing here hands a dialer, or anything
// Go-shaped, across the boundary. What was missing was not a way to cross a
// dialer — cgo has no such thing, a Go interface value cannot be marshaled
// into a C function argument — it was a way to cross the DOCUMENT the dialer
// is built from, so that the building could still happen entirely on this
// side of the boundary.
//
// Android and Windows already have that document: they spawn
// cmd/winn-datapath as a subprocess with argv and a filesystem, and pass
// `-carrier-profile PATH`. iOS and macOS reach this package through the C ABI
// in this directory, which has neither. WinnTunnelCreateWithCarrier is the
// same document, delivered the only way this boundary can carry one: as a
// string, exactly like configJSON already is. See the package doc on
// datapath/carrierhost for why the string itself is safe to move this way —
// in short, it names no secret, only paths a caller-trusted, same-process
// engine will open itself.
//
// # What crosses, restated
//
// Two JSON documents, both plain data, both already representable as C
// strings: datapath.Config (unchanged, already crossed via WinnTunnelCreate)
// and carrierhost.Profile (new). Neither carries key material — see
// datapath/carrierhost/profile.go's package doc — and both are parsed,
// validated, and turned into engine state entirely in Go, on this side of the
// call. The caller never constructs, inspects, or forwards anything
// Go-shaped.
package main

/*
#include <stdlib.h>
*/
import "C"

import (
	"context"
	"errors"
	"fmt"
	"time"

	"winsvpn.local/winnprotocol/datapath"
	"winsvpn.local/winnprotocol/datapath/carrierhost"
)

// carrierDialTimeout bounds one carrier dial: a QUIC or TLS handshake plus the
// signed request/response round trip that authenticates it. Mirrors
// cmd/winn-datapath's identically-named, identically-valued constant; the two
// are not shared because importing a `main` package from another is not
// possible in Go, and this one is small enough that duplicating it is safer
// than restructuring either binary's package shape to share it.
const carrierDialTimeout = 30 * time.Second

// openWithCarrierProfile is the decision logic behind WinnTunnelCreateWithCarrier,
// factored out of the cgo entry point so it can be exercised with `go test`
// without marshaling C strings. It mirrors cmd/winn-datapath's openWithProfile
// field for field, including the anti-downgrade checks and their messages,
// because the two are the same seam reached by a subprocess host and an
// in-process one and must refuse the same things for the same reasons. If one
// changes, the other must change with it.
func openWithCarrierProfile(
	configJSON []byte,
	carrierProfileJSON []byte,
	transportFD int,
) (*datapath.Engine, error) {
	profile, err := carrierhost.ParseProfile(carrierProfileJSON)
	if err != nil {
		return nil, err
	}
	config, err := datapath.ParseConfig(configJSON)
	if err != nil {
		return nil, err
	}
	if config.Carrier == datapath.CarrierDirectAWG {
		return nil, fmt.Errorf(
			"this engine was given a %s carrier profile but the configuration "+
				"asks for %q: refusing rather than opening an unauthenticated "+
				"carrier for a session that was configured for an authenticated "+
				"one",
			profile.Carrier, config.Carrier,
		)
	}
	if config.Carrier != profile.Carrier {
		return nil, fmt.Errorf(
			"carrier disagreement: the configuration asks for %q and the "+
				"carrier profile builds %q",
			config.Carrier, profile.Carrier,
		)
	}
	dialer, err := carrierhost.BuildDialer(profile)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), carrierDialTimeout)
	defer cancel()
	return datapath.OpenConfigWithCarrier(ctx, config, transportFD, dialer)
}

// WinnTunnelCreateWithCarrier opens one datapath over an authenticated
// carrier — currently http3-connect-udp (MASQUE) — instead of direct-awg.
//
// configJSON is the same datapath configuration WinnTunnelCreate takes, except
// that "carrier" must name a carrier this function was given a matching
// profile for; "direct-awg" is refused here precisely because that is what
// WinnTunnelCreate is for, and calling this instead would make a downgrade
// available through the wrong entry point.
//
// carrierProfileJSON is a carrierhost.Profile document: the authenticated
// carrier configuration datapath.Config deliberately does not carry (URI
// template, public target, device identity, TLS suite, response verifier).
// It is decoded with DisallowUnknownFields, exactly like configJSON, so a
// misspelled or stray field is a hard refusal here rather than a silent
// default. It carries no secret: every credential is named by PATH
// (controller_pins_path, root_ca_path, ech_config_list_path,
// device_seed_path, client_cert_path, client_key_path) and every one of those
// files is opened by this process, under its own identity, by the loader
// that already owns that file format — never by the caller, and never parsed
// by anything in this file. See datapath/carrierhost/profile.go.
//
// udpFD, errorOut and the handle/ownership contract are identical to
// WinnTunnelCreate: THE ENGINE TAKES OWNERSHIP of udpFD on success, a NULL
// configJSON or carrierProfileJSON is a synchronous refusal, and a failure
// writes an allocated message through errorOut rather than through a panic
// or a partially-constructed handle.
//
//export WinnTunnelCreateWithCarrier
func WinnTunnelCreateWithCarrier(
	configJSON *C.char,
	carrierProfileJSON *C.char,
	udpFD C.int,
	errorOut **C.char,
) C.longlong {
	if errorOut != nil {
		*errorOut = nil
	}
	if configJSON == nil {
		setError(errorOut, errors.New("winn datapath configuration is NULL"))
		return 0
	}
	if carrierProfileJSON == nil {
		setError(errorOut, errors.New("winn datapath carrier profile is NULL"))
		return 0
	}
	engine, err := openWithCarrierProfile(
		[]byte(C.GoString(configJSON)),
		[]byte(C.GoString(carrierProfileJSON)),
		int(udpFD),
	)
	if err != nil {
		setError(errorOut, err)
		return 0
	}
	handle := nextHandle.Add(1)
	registryMu.Lock()
	registry[handle] = engine
	registryMu.Unlock()
	return C.longlong(handle)
}
