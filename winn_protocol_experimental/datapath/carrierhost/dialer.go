package carrierhost

// Dialer construction.
//
// This is the code the comment in datapath/carrier.go asks a Go host to write:
// it turns the authenticated configuration into an internal/carrier dialer, and
// hands nothing to the caller except that dialer. It performs no I/O on the
// network — the dial itself belongs to datapath.OpenWithCarrier, which installs
// the host's already-protected descriptor first.
//
// ORDER MATTERS AND IS ENFORCED ELSEWHERE. This function must not install a
// socket, and it does not: it returns a dialer with no supplied socket, and
// datapath.openWithCarrier refuses a dialer that arrived pre-loaded
// (ErrCarrierSocketReused) precisely so the descriptor the engine adopted is
// provably the descriptor the carrier used.

import (
	"crypto/tls"
	"errors"
	"fmt"
	"time"

	"github.com/quic-go/quic-go/http3"
	"golang.org/x/net/http2"

	"winsvpn.local/winnprotocol/internal/carrier"
	"winsvpn.local/winnprotocol/internal/carrierauth"
	"winsvpn.local/winnprotocol/internal/echconfig"
	"winsvpn.local/winnprotocol/internal/knock"
	"winsvpn.local/winnprotocol/internal/knockdial"
	"winsvpn.local/winnprotocol/internal/pqauth"
	"winsvpn.local/winnprotocol/internal/tlsconfig"
)

// responseSkew is how much clock difference a signed carrier response may
// carry. It matches the value cmd/winn-carrier-client uses.
const responseSkew = 2 * time.Minute

// BuildDialer assembles the carrier dialer a profile describes.
//
// The returned dialer holds NO socket. The caller passes it to
// datapath.OpenWithCarrier together with the descriptor the host opened and
// protected, and that function installs the socket.
//
// Every failure is a load or validation failure of material the profile names.
// None of them is recoverable by weakening the session, so every one is
// returned rather than defaulted around.
func BuildDialer(profile Profile) (carrier.SuppliedSocketDialer, error) {
	normalized, err := profile.normalize()
	if err != nil {
		return nil, err
	}
	suite, err := tlsconfig.ParseSuite(normalized.Suite)
	if err != nil {
		return nil, fmt.Errorf("winn carrier profile suite: %w", err)
	}
	// The PINNED controller keys. This is the profile's trust anchor and the
	// only thing that makes a carrier response meaningful, so it is loaded
	// before anything that could succeed without it.
	pins, err := pqauth.LoadVerifierSet(normalized.ControllerPinsPath)
	if err != nil {
		return nil, fmt.Errorf("winn carrier controller pins: %w", err)
	}
	deviceSigner, err := pqauth.LoadSigner(
		normalized.DeviceAlgorithm, normalized.DeviceSeedPath,
	)
	if err != nil {
		return nil, fmt.Errorf("winn carrier device signer: %w", err)
	}
	responseVerifier := &carrierauth.ResponseVerifier{
		Verifiers:    pins,
		ControllerID: normalized.ControllerID,
		Suite:        suite.Name,
		MaxSkew:      responseSkew,
	}

	alpn := http3.NextProtoH3
	if normalized.Carrier == CarrierHTTP2 {
		alpn = http2.NextProtoTLS
	}
	// The trust anchor decides which constructor may be used, and the two are
	// not interchangeable: the fronted anchor is anonymous-only by
	// construction, because a TLS-terminating CDN is the mTLS peer and the
	// origin never sees a device certificate. normalizeTrustAnchor has already
	// refused the other combination, so this switch cannot silently downgrade.
	trust := normalized.ClientTrust()
	var clientTLS *tls.Config
	if trust.Anchor == tlsconfig.TrustWebPKI {
		clientTLS, err = tlsconfig.ClientAnonymousTrusted(
			trust, normalized.ServerName, suite, alpn,
		)
	} else {
		clientTLS, err = tlsconfig.ClientForALPN(
			normalized.ClientCertPath, normalized.ClientKeyPath,
			normalized.RootCAPath, normalized.ServerName, suite, alpn,
		)
	}
	if err != nil {
		return nil, fmt.Errorf("winn carrier client TLS: %w", err)
	}
	// ECH is required, not preferred. echconfig.ConfigureClient's third
	// argument is that requirement, and passing false here would let a network
	// that strips the extension downgrade the session to a ClientHello whose
	// SNI names the deployment in the clear.
	echList, err := echconfig.LoadClientConfigList(normalized.ECHConfigListPath)
	if err != nil {
		return nil, fmt.Errorf("winn carrier ECH config list: %w", err)
	}
	err = echconfig.ConfigureClient(clientTLS, echList, true)
	clear(echList)
	if err != nil {
		return nil, fmt.Errorf("winn carrier ECH: %w", err)
	}

	var dialer carrier.SuppliedSocketDialer
	switch normalized.Carrier {
	case CarrierHTTP3:
		dialer, err = buildH3(normalized, suite, clientTLS, deviceSigner,
			responseVerifier)
	case CarrierHTTP2:
		dialer, err = buildH2(normalized, suite, clientTLS, deviceSigner,
			responseVerifier)
	default:
		// Unreachable: normalize already refused every other carrier. Returning
		// rather than falling through keeps that true if normalize changes.
		return nil, fmt.Errorf("%w (requested %q)",
			ErrCarrierUnsupported, normalized.Carrier)
	}
	if err != nil {
		return nil, err
	}
	return wrapSPA(normalized, dialer)
}

// wrapSPA decorates the carrier dialer with the alternative initiation step
// when the profile asks for it, and returns it untouched when it does not.
//
// This is the last step, deliberately: the decorator must wrap a dialer that is
// already complete and still holds no socket, because datapath.OpenWithCarrier
// installs the host's protected descriptor through it and then refuses a dialer
// that arrived pre-loaded. Wrapping earlier would put this between the dialer
// and its own field assignment; wrapping later is impossible, since BuildDialer
// is the last code that sees a concrete dialer type.
func wrapSPA(
	profile Profile, dialer carrier.SuppliedSocketDialer,
) (carrier.SuppliedSocketDialer, error) {
	if profile.SPAMode != SPAModeRequired {
		return dialer, nil
	}
	// knock.LoadKeysFromFile is the loader that owns this file format, which is
	// what keeps this package free of any key parsing of its own — the same rule
	// pqauth.LoadSigner and tlsconfig.Client* follow above.
	keys, err := knock.LoadKeysFromFile(profile.SPAKeyPath)
	if err != nil {
		// The loader's messages name the file and the failure, never a byte of
		// its contents.
		return nil, fmt.Errorf("winn carrier SPA key: %w", err)
	}
	defer func() {
		for _, key := range keys {
			clear(key)
		}
	}()
	if len(keys) != 1 {
		// A server takes several keys for a rotation overlap; a client holds
		// exactly one. Picking one silently would mean a rotation could leave a
		// device knocking with a key nobody chose.
		return nil, fmt.Errorf(
			"winn carrier SPA key file must contain exactly one key for a "+
				"client, found %d", len(keys),
		)
	}
	spaDialer, err := knockdial.New(dialer, knockdial.Config{
		Key:        keys[0],
		Target:     profile.SPATarget,
		PacketSize: profile.SPAPacketSize,
		Options:    profile.SPAOptions(),
	})
	if err != nil {
		return nil, fmt.Errorf("winn carrier SPA initiation: %w", err)
	}
	return spaDialer, nil
}

func buildH3(
	profile Profile,
	suite tlsconfig.Suite,
	clientTLS *tls.Config,
	deviceSigner *pqauth.Signer,
	responseVerifier *carrierauth.ResponseVerifier,
) (carrier.SuppliedSocketDialer, error) {
	dialer, err := carrier.NewH3Dialer(
		profile.MASQUETemplate, profile.PublicTarget, profile.DeviceID,
		profile.SessionID, suite, clientTLS, deviceSigner, responseVerifier,
	)
	if err != nil {
		return nil, fmt.Errorf("winn carrier H3 dialer: %w", err)
	}
	applyCommon(profile, &dialer.MaxDatagram, &dialer.MaxOuterDatagram,
		&dialer.ManifestDigest, &dialer.AuthorizationMode,
		&dialer.DisableLengthPadding, &dialer.SequenceEpoch)
	if dialer.HasSuppliedSocket() {
		// Defensive: a dialer must reach datapath.OpenWithCarrier with no
		// socket, or the descriptor the engine adopted cannot be proven to be
		// the one the carrier used.
		return nil, errors.New(
			"winn carrier H3 dialer was built holding a socket",
		)
	}
	return dialer, nil
}

func buildH2(
	profile Profile,
	suite tlsconfig.Suite,
	clientTLS *tls.Config,
	deviceSigner *pqauth.Signer,
	responseVerifier *carrierauth.ResponseVerifier,
) (carrier.SuppliedSocketDialer, error) {
	dialer, err := carrier.NewH2Dialer(
		profile.H2URL, profile.PublicTarget, profile.DeviceID,
		profile.SessionID, suite, clientTLS, deviceSigner, responseVerifier,
	)
	if err != nil {
		return nil, fmt.Errorf("winn carrier H2 dialer: %w", err)
	}
	applyCommon(profile, &dialer.MaxDatagram, &dialer.MaxOuterDatagram,
		&dialer.ManifestDigest, &dialer.AuthorizationMode,
		&dialer.DisableLengthPadding, &dialer.SequenceEpoch)
	if dialer.HasSuppliedSocket() {
		return nil, errors.New(
			"winn carrier H2 dialer was built holding a socket",
		)
	}
	return dialer, nil
}

// applyCommon sets the fields both dialers share. They are set through pointers
// rather than by duplicating two near-identical blocks, so a field that is
// added to one dialer and forgotten on the other is a compile error at the call
// site instead of a silent asymmetry between carriers.
func applyCommon(
	profile Profile,
	maxDatagram *int,
	maxOuterDatagram *int,
	manifestDigest *string,
	authorizationMode *string,
	disableLengthPadding *bool,
	sequenceEpoch *string,
) {
	*maxDatagram = profile.MaxInnerDatagram
	*maxOuterDatagram = profile.MaxInnerDatagram + carrier.CarrierEnvelopeOverhead
	*manifestDigest = profile.ManifestDigest
	*authorizationMode = profile.AuthorizationMode
	// High risk pads; standard does not. The comparison is written this way
	// round so that any future privacy profile defaults to padding.
	*disableLengthPadding = profile.PrivacyProfile != carrierauth.PrivacyHighRisk
	*sequenceEpoch = profile.SequenceEpoch
}
