package core

import (
	"bytes"
	"encoding/base64"
	"testing"
)

// IA-CP-05 (Fable 5.1 ruling, 2026-09-29): the app now generates this
// device's winn/3 static keypair itself (lib/winn3_device_key.dart) and the hub
// publishes only the public half the app sent. The engine still receives the
// private half as `static_private` and derives the public key itself
// (NewStaticKey, Public). If the two derivations ever disagreed, the gateway
// would hold a public key the engine never proves possession of, and the
// session would be silently ignored. These vectors are pinned byte for byte in
// test/winn3_device_key_test.dart on the Dart side.
func TestDeviceGeneratedStaticKeyDerivesThePublishedPublicKey(t *testing.T) {
	for _, tc := range []struct {
		name, private, public string
	}{
		{
			// RFC 7748 section 6.1, Alice.
			name:    "rfc7748-alice",
			private: "dwdtCnMYpX08FsFyUbJmRd9ML4frwJkqsXf7pR25LCo=",
			public:  "hSDwCYkwp1R0i33ctD73Wg2/Og0mOBr066SpjqqbTmo=",
		},
		{
			// Bytes i*7+3, clamped exactly as the app clamps a fresh scalar.
			name:    "app-clamped",
			private: "AAoRGB8mLTQ7QklQV15lbHN6gYiPlp2kq7K5wMfO1Vw=",
			public:  "u1D/noKldM+/gg6X9g+5wUPsdBXPUU+M/Zjv9Z4FlhQ=",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			private, err := base64.StdEncoding.DecodeString(tc.private)
			if err != nil {
				t.Fatal(err)
			}
			want, err := base64.StdEncoding.DecodeString(tc.public)
			if err != nil {
				t.Fatal(err)
			}
			key, err := NewStaticKey(private)
			if err != nil {
				t.Fatalf("engine refused a device-generated static key: %v", err)
			}
			if got := key.Public(); !bytes.Equal(got, want) {
				t.Fatalf("engine public %x, app/hub public %x", got, want)
			}
		})
	}
}
