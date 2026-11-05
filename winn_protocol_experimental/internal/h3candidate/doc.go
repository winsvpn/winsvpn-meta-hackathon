// Package h3candidate adapts the authenticated RFC 9298 HTTP/3 CONNECT-UDP
// carrier to the Winn v3 connectivity candidate contract.
//
// The production constructor accepts only carrier.H3Dialer and replaces its
// QUIC dial hook with a ProtectedUnderlay lease. Verification remains about the
// real inner AWG tunnel: the adapter delegates handshake and byte-flow proof to
// TunnelSession, and protected DNS/canary proof to CandidateVerifier. It never
// treats an HTTP/3 or MTU handshake as proof that AWG is online.
package h3candidate
