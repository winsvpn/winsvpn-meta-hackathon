package tlsconfig

import "crypto/x509"

// TrustPoolForTest exposes ClientTrust.pool to the external test package.
//
// It lives in an _test.go file so it is compiled only under `go test` and adds
// nothing to the package's public surface. The unexported method is worth
// reaching directly because two of its refusals — a client certificate under
// TrustWebPKI, and the exact (pool, error) pairing for every anchor — are not
// reachable through the exported constructors: ClientAnonymousTrusted never
// supplies certificates, which is itself part of the design. Testing the guard
// only through a constructor that cannot trigger it would leave the guard
// unasserted and free to rot.
func TrustPoolForTest(
	trust ClientTrust, hasClientCertificate bool, serverName string,
) (*x509.CertPool, error) {
	return trust.pool(hasClientCertificate, serverName)
}
