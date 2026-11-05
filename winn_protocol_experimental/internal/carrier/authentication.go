package carrier

import (
	"crypto/rsa"
	"errors"
	"net/http"
	"time"

	"winsvpn.local/winnprotocol/internal/carrierauth"
	"winsvpn.local/winnprotocol/internal/identity"
	"winsvpn.local/winnprotocol/internal/pqauth"
	"winsvpn.local/winnprotocol/internal/privacytoken"
)

// #nosec G101 -- this is a public HTTP header name, not credential material.
const HeaderPrivacyToken = "X-Winn-Privacy-Token"

// PrivacyTokenVerifier contains the redemption-only trust material deployed to
// a carrier. The issuer's private key belongs on a separate controller.
type PrivacyTokenVerifier struct {
	PublicKey   *rsa.PublicKey
	KeyID       string
	NotBefore   time.Time
	NotAfter    time.Time
	Redemptions privacytoken.RedemptionStore
	LabMode     bool
}

type AnonymousCredential struct {
	Pseudonym string
	Signer    *pqauth.Signer
	Token     privacytoken.Token
	Resource  AnonymousCredentialResource
}

type AnonymousCredentialResource interface {
	// Destroy must be idempotent and safe to call after source retirement.
	Destroy()
}

// Destroy releases the ephemeral signer exactly once when Resource is
// idempotent. Legacy sources without a Resource still get signer destruction.
func (credential *AnonymousCredential) Destroy() {
	if credential == nil {
		return
	}
	if credential.Resource != nil {
		credential.Resource.Destroy()
	} else if credential.Signer != nil {
		credential.Signer.Destroy()
	}
	credential.Pseudonym = ""
	credential.Signer = nil
	credential.Token = privacytoken.Token{}
	credential.Resource = nil
}

type AnonymousCredentialSource interface {
	NextAnonymousCredential() (AnonymousCredential, error)
}

func authenticateCarrierRequest(request *http.Request, expectedCarrier, expectedTarget string, verifier *carrierauth.RequestVerifier, tokens *PrivacyTokenVerifier) (carrierauth.RequestClaims, string, error) {
	if request == nil || request.TLS == nil || verifier == nil {
		return carrierauth.RequestClaims{}, "", errors.New("carrier authentication is not configured")
	}
	switch request.Header.Get(carrierauth.HeaderAuthMode) {
	case carrierauth.AuthModeIdentity:
		if request.Header.Get(HeaderPrivacyToken) != "" {
			return carrierauth.RequestClaims{}, "", errors.New("identity carrier request contains a privacy token")
		}
		deviceID, err := identity.DeviceID(request.TLS)
		if err != nil {
			return carrierauth.RequestClaims{}, "", err
		}
		claims, err := verifier.Verify(
			request, expectedCarrier, expectedTarget, deviceID,
		)
		return claims, deviceID, err

	case carrierauth.AuthModeAnonymousToken:
		if len(request.TLS.PeerCertificates) != 0 {
			return carrierauth.RequestClaims{}, "", errors.New("anonymous carrier request presented a stable client certificate")
		}
		if tokens == nil || tokens.PublicKey == nil ||
			tokens.Redemptions == nil {
			return carrierauth.RequestClaims{}, "", errors.New("anonymous carrier authentication is disabled")
		}
		if !tokens.LabMode &&
			!privacytoken.IsDurableRedemptionStore(tokens.Redemptions) {
			return carrierauth.RequestClaims{}, "", errors.New(
				"production anonymous carrier requires durable token redemption",
			)
		}
		now := verifier.CurrentTime()
		if err := privacytoken.ValidateKeyWindow(tokens.NotBefore, tokens.NotAfter, now); err != nil {
			return carrierauth.RequestClaims{}, "", err
		}
		token, err := privacytoken.DecodeTokenHeader(request.Header.Get(HeaderPrivacyToken))
		if err != nil {
			return carrierauth.RequestClaims{}, "", err
		}
		verified, err := privacytoken.Verify(token, tokens.PublicKey, tokens.KeyID)
		if err != nil {
			return carrierauth.RequestClaims{}, "", err
		}
		claims, err := verifier.VerifyAnonymous(
			request, expectedCarrier, expectedTarget, verified.Pseudonym,
			verified.TokenID, verified.Verifier,
		)
		if err != nil {
			return carrierauth.RequestClaims{}, "", err
		}
		// Redeem only after proof of possession of the token's committed
		// ephemeral ML-DSA key. This prevents unauthenticated token burning.
		if err := tokens.Redemptions.Redeem(
			request.Context(), verified.TokenID, tokens.NotAfter,
		); err != nil {
			return carrierauth.RequestClaims{}, "", err
		}
		return claims, verified.Pseudonym, nil

	default:
		return carrierauth.RequestClaims{}, "", errors.New("unsupported carrier authorization mode")
	}
}

func addPrivacyTokenHeader(header http.Header, mode string, token *privacytoken.Token) error {
	if mode == carrierauth.AuthModeIdentity {
		if token != nil {
			return errors.New("identity carrier cannot send a privacy token")
		}
		return nil
	}
	if mode != carrierauth.AuthModeAnonymousToken || token == nil {
		return errors.New("anonymous carrier requires a privacy token")
	}
	encoded, err := privacytoken.EncodeTokenHeader(*token)
	if err != nil {
		return err
	}
	header.Set(HeaderPrivacyToken, encoded)
	return nil
}

func resolveClientCredential(
	mode, deviceID string,
	signer *pqauth.Signer,
	token *privacytoken.Token,
	source AnonymousCredentialSource,
) (
	string,
	*pqauth.Signer,
	*privacytoken.Token,
	func(),
	error,
) {
	if mode == carrierauth.AuthModeIdentity {
		return deviceID, signer, token, func() {}, nil
	}
	if mode != carrierauth.AuthModeAnonymousToken {
		return "", nil, nil, func() {},
			errors.New("unsupported carrier authorization mode")
	}
	if source == nil {
		return deviceID, signer, token, func() {}, nil
	}
	credential, err := source.NextAnonymousCredential()
	if err != nil {
		return "", nil, nil, func() {}, err
	}
	return credential.Pseudonym, credential.Signer, &credential.Token,
		func() { credential.Destroy() }, nil
}
