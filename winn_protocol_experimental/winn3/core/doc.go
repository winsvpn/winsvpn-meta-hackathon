// Package core implements the standalone Winn Protocol v3 cryptographic core:
// its own handshake, its own key schedule, and its own transport crypto.
//
// It has no dependency on AmneziaWG, on WireGuard, or on Xray, and it never
// will. The full design rationale — including the measured fingerprint this
// replaces and the adversary reasoning behind every choice — lives in
// docs/handoff/WINN3_STANDALONE_PROTOCOL_DESIGN_20260808.md. What follows is
// the part an implementer needs at the call site.
//
// # What this package is, and what it is deliberately not
//
// This package is pure. It opens no socket, resolves no name, learns no
// address, and reads no clock it was not handed. It turns keys and plaintext
// into byte strings and back. That is the whole contract, and it is what makes
// the datapath separable from the transport: a carrier is anything that can
// move a bounded byte string, so blocking UDP wholesale — which today kills a
// v3 session after 24 retries and 100% loss — is a carrier problem that can be
// solved without touching a line of cryptography.
//
// It is therefore NOT a session driver. Nothing here decides when to send a
// keepalive, when to rekey, when to pad, or when to give up on a carrier. It
// reports when a rekey is due and it enforces the hard ceilings; the policy
// that satisfies the timing and padding rules of the design lives above.
//
// # The two shapes on the wire
//
// There are exactly two message classes, and there is no third. No cookie
// message, no version message, no error message, and no close that a censor can
// tell from data.
//
//	Handshake:  AdmissionTag || whitened( ephemeral || sealed-static || sealed-payload )
//	Transport:  DemuxToken   || AEAD( frames || padding )
//
// A transport message is unconditionally uniform random to any observer: the
// demux token is a PRF output and everything after it is AEAD output. There is
// no counter on the wire, no session index, no type byte, no length field and
// no version, because the counter is implicit in the demux token (see
// tokenWindow) and everything else is inside the AEAD.
//
// A handshake message is uniform random only to an observer who does not hold
// that gateway's admission key. That scoping is real and is stated here rather
// than hidden: the whitening keystream in admission.go is a COST boundary, not
// a security boundary. Its job is to move fleet identification from "byte
// pattern match at line rate" to "hold a per-gateway secret". An adversary
// holding the key does not need the whitening removed; they can verify the tag.
//
// The reason that scoping is still a large improvement over what it replaces:
// the key is per gateway, so burning one gateway does not burn the fleet. The
// fingerprint being replaced — 0B 00 00 00 at offset 16 of every initiation —
// was a fleet-wide constant that required no key at all.
//
// # Why the admission tag is the first field
//
// internal/initauth established the reasoning and it survives the move to
// standalone intact: no knock at all beats a better knock, because a separate
// authorisation packet is a separate flow, and a port that receives
// uniform-length maximum-entropy datagrams and never answers one is a signature
// with essentially no false-positive population to hide in.
//
// What changes here is that initauth had to hide its authenticator inside a
// field AmneziaWG defined for another purpose, and so inherited AmneziaWG's
// constraints — it says in its own doc comment that it cannot fix the header
// word four bytes later. Owning the header removes that ceiling. The
// authenticator is simply the first field; the whitening covers everything
// after it; and there is no unsealed variant whose existence could ever be a
// discriminator, because there never was one.
//
// Two properties are preserved from initauth verbatim. The freshness bucket is
// an authenticated input to the tag and is NEVER TRANSMITTED, because an
// explicit timestamp only ever takes values near true wall-clock time and that
// is a learnable statistical shape. And the tag costs zero added packets and
// zero added bytes: it replaces mac1, mac2 and the cookie exchange rather than
// adding to them.
//
// # NON-GOAL: the admission layer never contributes to integrity
//
// This is an invariant, not an observation, and it is stated here because it is
// the kind of separation that is true by construction, load-bearing, and easy
// for a later editor to erase by accident.
//
//	The handshake's integrity, authenticity and key agreement MUST NEVER
//	depend on the admission tag, the whitening, the never-transmitted
//	freshness bucket, the tag length or the gateway identity. Delete the
//	entire admission layer and the cryptographic core must remain exactly as
//	sound as it is today. Only its cost and its unlinkability change.
//
// The same rule read the other way is what makes admission-key ROTATION safe,
// and it is worth spelling out because the obvious implementation of rotation
// is a security defect. Because the admission layer contributes nothing to the
// core, a rotation must change nothing but the key set — see
// Responder.SetAdmissionKeys. Constructing a fresh Responder instead would
// discard the handshake replay cache, and that cache is the only thing stopping
// a captured initiation working as a gateway detector. Worse, the window it
// re-opens is aligned to the rotation instant, so it is a clock: rotation is
// otherwise invisible on the wire, because the admission key is used once in
// the initiation and never again.
//
// What the admission layer IS for: cost, unlinkability, and a knock that adds
// no packet. It moves fleet identification from a byte-pattern match in an ASIC
// at line rate to holding a per-gateway secret; it makes an initiation
// unpairable with its response by an observer who lacks the gateway static
// private key; and it discards unauthorised traffic before any asymmetric
// operation, so a flood costs one HMAC rather than one X25519. It is a COST
// boundary, in the exact words admission.go uses about itself.
//
// What it is emphatically NOT for: integrity, authentication, transcript
// binding, or peer identity. It authenticates nothing a peer cares about. An
// adversary holding the admission key can mint an initiation that passes it
// perfectly — that is not a break, because passing it grants nothing.
//
// Hence the transcript hash h commits to protocolLabel, the responder's static
// public key, the ephemeral, the sealed static and the sealed payload — and to
// NONE of the admission parameters. That omission is deliberate and is not a
// gap to be filled. Adding the tag to the transcript would make the core's
// security depend on an obfuscation secret that is, by design, spread across
// every client of a gateway, and would forbid the response tag being keyed from
// the chain instead of from the admission key.
//
// The separation holds because the layer is stripped before the core runs and
// the body it wraps is independently authenticated by the two inner AEADs whose
// AAD is h. Alter any whitened byte and the recovered body changes, so h
// changes, so the inner AEAD fails. Re-wrap a captured body for a different
// gateway and newChain's seeding on the responder static key means the inner
// AEAD fails there too — see TestInnerCryptoRejectsCrossGatewayInitiation,
// which asserts precisely that the rejection is the INNER AEAD's and not the
// outer tag's.
//
// The rule that follows, for anyone extending this package: nothing derived
// from the admission key may ever reach the chain, the AAD, or any accept
// decision, and no failure of the core may ever be repaired by a property of
// the tag. If a change makes the outer tag necessary for correctness, the
// change is wrong.
//
// The ephemeral codec (EphemeralCodec, and Elligator2Codec in elligator.go)
// sits INSIDE that boundary and is the most recent test of it. It is the one
// place where a change made for obfuscation reasons touches a field the core
// depends on, so the rule applies to it word for word: the codec reads no
// admission key, no gateway identity, no freshness bucket and no tag, and
// TestElligatorDoesNotDependOnTheAdmissionLayer runs one ephemeral draw under
// two admission profiles that share nothing and requires the wire field to come
// out byte-identical. What the transcript binds is the codec's WIRE OUTPUT, not
// the point behind it, which is what keeps a codec change a change of
// representation rather than a change of key schedule.
//
// The other direction of the same invariant is worth stating too, because
// Elligator2 is what makes it true. "Delete the admission layer and the core is
// as sound" was always true of SOUNDNESS and, until 2026-08-08, false of
// UNLINKABILITY: strip the whitening and the raw ephemeral's top bit is a
// fleet-wide constant at a fixed offset. Under Elligator2 the body is uniform
// with the layer deleted, so the layer is now genuinely a cost boundary in both
// senses rather than in one.
//
// That sentence is true of Elligator2Codec, which is opt-in. DefaultEphemeralCodec
// remains identityCodec: the codec is not negotiated, so both ends must be
// configured together, and shipping Elligator2 as the default would be a
// deployment decision this package does not make. A Config that leaves Codec
// nil still has the top-bit bias once the admission layer is stripped. See
// keys.go on DefaultEphemeralCodec.
//
// # Silence
//
// Every error in this package is a LOCAL diagnostic. The responder writes
// nothing back on any path for any failure: not for a bad tag, not for a
// replay, not for a decryption failure. There is no cookie reply, because a
// cookie reply is an answer to an unauthenticated packet and therefore a probe
// oracle by construction. Callers MUST NOT turn any error here into anything a
// peer can observe.
//
// The one honest exception is timing: the tag check is cheap and runs first, so
// "tag failed" and "tag passed, crypto failed" differ by microseconds. That
// branch is reachable only by a key holder, who has better attacks available.
//
// # Post-quantum
//
// Confidentiality is hybrid; authentication is not. ML-KEM-768 is mixed in by
// Session.MixPQ as an in-band ratchet AFTER the handshake, not inside it,
// because ephemeral-ephemeral ML-KEM-768 needs 1184 + 1088 bytes and would push
// the first packet past the 1280-byte IPv6 minimum MTU. A fragmented first
// packet is itself a distinctive fingerprint and fragments are widely dropped.
// Carrying the KEM as ordinary transport frames also makes it indistinguishable
// from data, which putting it in the handshake would not.
//
// Authentication rests on X25519. Forging it needs a contemporaneous quantum
// computer, whereas harvest-now-decrypt-later attacks confidentiality today.
// The gateway's static key reaches the client inside an Ed25519-signed
// descriptor (the ML-DSA-65 descriptor signature was designed but has not
// shipped; the dual-signature session attestation, docs/DUAL_SIGNATURE_SPEC.md,
// adds ML-DSA-65 at the session layer). Gateway identity is NOT post-quantum
// authenticated today. Client authentication has no equivalent mitigation.
// That is a known weakness, recorded in the design document rather than
// papered over.
package core
