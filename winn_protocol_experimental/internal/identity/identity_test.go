package identity

import (
	"crypto/tls"
	"crypto/x509"
	"net/url"
	"strings"
	"testing"
)

func testURI(t *testing.T, value string) *url.URL {
	t.Helper()
	parsed, err := url.Parse(value)
	if err != nil {
		t.Fatalf("parse URI %q: %v", value, err)
	}
	return parsed
}

func TestDeviceIDRequiresVerifiedLeaf(t *testing.T) {
	valid := &x509.Certificate{
		URIs: []*url.URL{testURI(t, "spiffe://winn.local/device/device-1")},
	}
	tests := []struct {
		name    string
		state   *tls.ConnectionState
		want    string
		wantErr string
	}{
		{name: "nil state", wantErr: "no verified client certificate"},
		{
			name:    "no verified chains",
			state:   &tls.ConnectionState{},
			wantErr: "no verified client certificate",
		},
		{
			name: "empty verified chain",
			state: &tls.ConnectionState{
				VerifiedChains: [][]*x509.Certificate{{}},
			},
			wantErr: "no verified client certificate",
		},
		{
			name: "unverified peer certificate is not identity",
			state: &tls.ConnectionState{
				PeerCertificates: []*x509.Certificate{valid},
			},
			wantErr: "no verified client certificate",
		},
		{
			name: "verified leaf",
			state: &tls.ConnectionState{
				VerifiedChains: [][]*x509.Certificate{{valid}},
			},
			want: "device-1",
		},
		{
			name: "verified leaf wins over different unverified peer certificate",
			state: &tls.ConnectionState{
				PeerCertificates: []*x509.Certificate{{
					URIs: []*url.URL{testURI(t, "spiffe://winn.local/device/attacker")},
				}},
				VerifiedChains: [][]*x509.Certificate{{valid}},
			},
			want: "device-1",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := DeviceID(test.state)
			if test.want == "" {
				if err == nil || got != "" {
					t.Fatalf("DeviceID() = %q, %v; want refusal", got, err)
				}
				if err.Error() != test.wantErr {
					t.Fatalf("DeviceID() error = %q; want %q", err.Error(), test.wantErr)
				}
				return
			}
			if test.wantErr != "" {
				t.Fatalf("success case %q must not set wantErr", test.name)
			}
			if err != nil || got != test.want {
				t.Fatalf("DeviceID() = %q, %v; want %q", got, err, test.want)
			}
		})
	}
}

func TestDeviceIDFromCertificateRequiresExactCanonicalURISAN(t *testing.T) {
	valid64 := "d" + strings.Repeat("a", 63)
	tests := []struct {
		name    string
		uris    []*url.URL
		want    string
		wantErr string
	}{
		{name: "nil certificate", wantErr: "client certificate is missing"},
		{name: "no URI SAN", uris: []*url.URL{}, wantErr: "device URI SAN is missing"},
		{name: "nil URI entry", uris: []*url.URL{nil}, wantErr: "device URI SAN is missing"},
		{
			name: "canonical identity",
			uris: []*url.URL{
				testURI(t, "spiffe://winn.local/device/device-1"),
			},
			want: "device-1",
		},
		{
			name: "maximum length identity",
			uris: []*url.URL{
				testURI(t, "spiffe://winn.local/device/"+valid64),
			},
			want: valid64,
		},
		{
			name: "wrong scheme",
			uris: []*url.URL{
				testURI(t, "https://winn.local/device/device-1"),
			},
			wantErr: "device URI SAN is missing",
		},
		{
			name: "wrong trust domain",
			uris: []*url.URL{
				testURI(t, "spiffe://other.local/device/device-1"),
			},
			wantErr: "device URI SAN is missing",
		},
		{
			name: "trust domain with port",
			uris: []*url.URL{
				testURI(t, "spiffe://winn.local:443/device/device-1"),
			},
			wantErr: "device URI SAN is missing",
		},
		{
			name: "userinfo alias",
			uris: []*url.URL{
				testURI(t, "spiffe://operator@winn.local/device/device-1"),
			},
			wantErr: "device URI SAN is missing",
		},
		{
			name: "wrong path",
			uris: []*url.URL{
				testURI(t, "spiffe://winn.local/devices/device-1"),
			},
			wantErr: "device URI SAN is missing",
		},
		{
			name: "empty identity",
			uris: []*url.URL{
				testURI(t, "spiffe://winn.local/device/"),
			},
			wantErr: "device URI SAN is missing",
		},
		{
			name: "nested path",
			uris: []*url.URL{
				testURI(t, "spiffe://winn.local/device/device-1/child"),
			},
			wantErr: "device URI SAN is missing",
		},
		{
			name: "escaped path separator",
			uris: []*url.URL{
				testURI(t, "spiffe://winn.local/device/device-1%2Fchild"),
			},
			wantErr: "device URI SAN is missing",
		},
		{
			name: "escaped unreserved identity byte",
			uris: []*url.URL{
				testURI(t, "spiffe://winn.local/device/device%2D1"),
			},
			wantErr: "device URI SAN is missing",
		},
		{
			name: "query alias",
			uris: []*url.URL{
				testURI(t, "spiffe://winn.local/device/device-1?role=other"),
			},
			wantErr: "device URI SAN is missing",
		},
		{
			name: "fragment alias",
			uris: []*url.URL{
				testURI(t, "spiffe://winn.local/device/device-1#other"),
			},
			wantErr: "device URI SAN is missing",
		},
		{
			name: "invalid leading byte",
			uris: []*url.URL{
				testURI(t, "spiffe://winn.local/device/-device"),
			},
			wantErr: "device URI SAN is missing",
		},
		{
			name: "identity too long",
			uris: []*url.URL{
				testURI(t, "spiffe://winn.local/device/d"+strings.Repeat("a", 64)),
			},
			wantErr: "device URI SAN is missing",
		},
		{
			name: "different valid identities are ambiguous",
			uris: []*url.URL{
				testURI(t, "spiffe://winn.local/device/device-1"),
				testURI(t, "spiffe://winn.local/device/device-2"),
			},
			wantErr: "ambiguous device identities",
		},
		{
			name: "duplicate exact identity is stable",
			uris: []*url.URL{
				testURI(t, "spiffe://winn.local/device/device-1"),
				testURI(t, "spiffe://winn.local/device/device-1"),
			},
			want: "device-1",
		},
		{
			name: "unrelated URI does not shadow canonical identity",
			uris: []*url.URL{
				testURI(t, "https://example.test/device/device-2"),
				testURI(t, "spiffe://winn.local/device/device-1"),
			},
			want: "device-1",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var certificate *x509.Certificate
			if test.uris != nil {
				certificate = &x509.Certificate{URIs: test.uris}
			}
			got, err := DeviceIDFromCertificate(certificate)
			if test.want == "" {
				if err == nil || got != "" {
					t.Fatalf(
						"DeviceIDFromCertificate() = %q, %v; want refusal",
						got, err,
					)
				}
				if test.wantErr == "" {
					t.Fatalf("refusal case %q missing wantErr", test.name)
				}
				if err.Error() != test.wantErr {
					t.Fatalf(
						"DeviceIDFromCertificate() error = %q; want %q",
						err.Error(), test.wantErr,
					)
				}
				return
			}
			if test.wantErr != "" {
				t.Fatalf("success case %q must not set wantErr", test.name)
			}
			if err != nil || got != test.want {
				t.Fatalf(
					"DeviceIDFromCertificate() = %q, %v; want %q",
					got, err, test.want,
				)
			}
		})
	}
}
