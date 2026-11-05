// The local endpoint, and why it can only ever be this machine.
//
// The bridge contract describes the proxy BY PORT NUMBER ALONE. There is no
// host field in any message, so there is nothing for a routable address to
// travel in. This file is where that structural property is converted into a
// usable endpoint: the port comes from the wire, bounded and integer-checked,
// and the host comes from a constant compiled into this extension.
//
// The consequence is worth stating plainly, because it is the security argument
// for the whole component: a bridge that has been replaced, compromised or
// simply written wrong cannot make this browser send traffic anywhere except
// 127.0.0.1. It cannot even name somewhere else. And since the extension holds
// no other address, in the bundle or at runtime, there is no address in this
// software for anyone to read out of it.
//
// The check below is retained anyway. A guarantee that depends on nobody ever
// adding a host field is a habit; a guarantee plus an assertion is a design.

import { LOOPBACK_HOST } from './constants.js';

export function validatePort(port) {
  return Number.isInteger(port) && port >= 1 && port <= 65535;
}

/**
 * The literal string "localhost" is never used anywhere in this extension.
 *
 * "localhost" is a name, and a name is a resolution step. On a machine whose
 * resolver has been tampered with, or simply on a network with an aggressive
 * search domain, "localhost" is not guaranteed to be 127.0.0.1. Using only the
 * numeric literal takes the resolver out of the trust path.
 */
export function isLoopbackHost(host) {
  if (typeof host !== 'string' || host.length === 0) return false;
  if (host === '::1' || host === '[::1]') return true;
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(host);
  if (!m) return false;
  const parts = [m[1], m[2], m[3], m[4]];
  // Non-canonical forms such as 127.000.000.001 are refused. They parse, and
  // that is exactly why: a value written that way is a value trying to get past
  // a string comparison.
  if (parts.some((s) => s.length > 1 && s[0] === '0')) return false;
  const octets = parts.map(Number);
  if (octets.some((n) => !Number.isInteger(n) || n < 0 || n > 255)) return false;
  return octets[0] === 127;
}

/**
 * Final assertion before an endpoint is used for anything.
 * @returns {{ok: true, endpoint: object} | {ok: false, reason: string}}
 */
export function validateEndpoint(endpoint) {
  if (!endpoint || typeof endpoint !== 'object') {
    return { ok: false, reason: 'no endpoint' };
  }
  if (endpoint.kind !== 'http') {
    // HTTP CONNECT is the only mechanism the desktop bridge implements. A
    // SOCKS5 endpoint would have to be unauthenticated (no extension API for
    // SOCKS5 user/pass on any of the three browsers), and the previous TLS
    // `https` kind was removed with the certificate design per ruling
    // 2026-08-07: Firefox now authenticates via webRequest over plaintext.
    return { ok: false, reason: `unsupported endpoint kind: ${String(endpoint.kind).slice(0, 16)}` };
  }
  if (!isLoopbackHost(endpoint.host)) {
    // Does not echo the rejected value. If something upstream produced a
    // routable address, repeating it into a log or the popup would put it
    // exactly where this design says it must never be.
    return { ok: false, reason: 'endpoint host is not a numeric loopback address' };
  }
  if (!validatePort(endpoint.port)) {
    return { ok: false, reason: 'endpoint port is not in 1-65535' };
  }
  return { ok: true, endpoint: { kind: endpoint.kind, host: endpoint.host, port: endpoint.port } };
}

/**
 * PAC proxy token, e.g. "PROXY 127.0.0.1:49704".
 *
 * Note the absence of a "; DIRECT" suffix anywhere in this file. That suffix is
 * the classic fail-open bug: it tells the browser to connect directly when the
 * proxy is unreachable, which is the behaviour this extension exists to prevent.
 */
export function pacToken(endpoint) {
  // OI-17 (Round 36 treaty): validateEndpoint is the final assertion before an
  // endpoint is used for anything, so the PAC token builder runs it too. The
  // caller must treat a throw as a failed connection and never fall back to a
  // "; DIRECT" token.
  const checked = validateEndpoint(endpoint);
  if (!checked.ok) {
    throw new TypeError(`invalid loopback proxy endpoint: ${checked.reason}`);
  }
  endpoint = checked.endpoint;
  // `isLoopbackHost` accepts both '::1' and '[::1]', so normalise before
  // bracketing. Wrapping an already-bracketed literal a second time produces
  // "PROXY [[::1]]:port", which no PAC resolver parses. Unreachable while the
  // only producer is protocol.js pinning LOOPBACK_HOST, and asserted anyway for
  // the reason stated at the top of this file.
  const bare = endpoint.host.startsWith('[') && endpoint.host.endsWith(']')
    ? endpoint.host.slice(1, -1)
    : endpoint.host;
  const host = bare.includes(':') ? `[${bare}]` : bare;
  return `PROXY ${host}:${endpoint.port}`;
}

export { LOOPBACK_HOST };
