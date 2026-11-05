package core

import (
	"bytes"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
)

// Cross-implementation known-answer vectors.
//
// # What these are for, and how they differ from vectors_test.go
//
// vectors_test.go pins this implementation against itself. That catches drift
// and it is worth having, but the design document says plainly what it cannot
// do (§6.11): "The vectors prove stability, not correctness. They were produced
// by this implementation."
//
// The gap that matters is not a wrong byte, it is an AMBIGUOUS SPECIFICATION.
// §5.1's pseudocode did not match transcript.go until it was corrected on
// 2026-08-08 — the document specified a chaining-key seed and a Noise-style
// split() that the code does not implement. Nobody noticed for as long as the
// only reader of the document was somebody who could also read the Go. A second
// implementation and a symbolic proof both consume that document, so the
// document has to be checkable on its own.
//
// These vectors are the checkable form. Every case carries its inputs, its
// expected outputs, AND the derivation that connects them, in enough detail
// that an implementer can reproduce the value with a hash, an HMAC, an HKDF, an
// X25519 and an AEAD — and never needs to open handshake.go to find out what
// order the fields go in or what exactly is fed to a MAC.
//
// The handshake groups carry every intermediate — every chaining key, every
// transcript hash, every stage key, every raw DH output — so that a second
// implementation that gets a different final message can bisect to the exact
// step where it diverged instead of staring at 134 bytes of ciphertext.
//
// # Why the file is checked in rather than generated at test time
//
// A test that regenerates its own expectations proves nothing. testdata/
// winn3_kat_v1.json is the artifact a second implementer receives; this test
// rebuilds it from the live code and requires it to be byte-identical, so the
// artifact cannot silently drift away from the implementation it describes.
//
// To regenerate after a deliberate protocol change:
//
//	WINN3_WRITE_KAT=1 go test ./winn3/core/ -run TestCrossImplementationVectors
//
// which is deliberately awkward, because doing it by accident is how a wire
// break gets blessed.

const katFilePath = "testdata/winn3_kat_v1.json"

type katField struct {
	Name  string `json:"name"`
	Type  string `json:"type"`
	Value string `json:"value"`
}

type katCase struct {
	Name string     `json:"name"`
	Note string     `json:"note,omitempty"`
	In   []katField `json:"in"`
	Out  []katField `json:"out"`
}

type katGroup struct {
	ID         string    `json:"id"`
	What       string    `json:"what"`
	Derivation []string  `json:"derivation"`
	Cases      []katCase `json:"cases"`
}

type katFile struct {
	Format      string     `json:"format"`
	Version     int        `json:"version"`
	Protocol    string     `json:"protocol"`
	Suite       string     `json:"suite"`
	Purpose     []string   `json:"purpose"`
	Conventions []string   `json:"conventions"`
	Groups      []katGroup `json:"groups"`
}

func kh(name string, v []byte) katField   { return katField{name, "hex", hex.EncodeToString(v)} }
func ks(name, v string) katField          { return katField{name, "utf8", v} }
func ki(name string, v int64) katField    { return katField{name, "int", strconv.FormatInt(v, 10)} }
func kd(name string, v *big.Int) katField { return katField{name, "dec", v.String()} }

// --- primitives restated, so the vector file is checked against a second
// spelling of each construction rather than against the one that produced it ---

func katHKDFExpand(prk []byte, info string, n int) []byte {
	out, err := hkdf.Expand(sha256.New, prk, info, n)
	if err != nil {
		panic(err)
	}
	return out
}

func katHKDFExtract(salt, ikm []byte) []byte {
	out, err := hkdf.Extract(sha256.New, ikm, salt)
	if err != nil {
		panic(err)
	}
	return out
}

func katMixHash(h, data []byte) []byte {
	s := sha256.New()
	s.Write(h)
	s.Write(data)
	return s.Sum(nil)
}

func katMixSecret(ck, secret []byte, label string) []byte {
	return katHKDFExpand(katHKDFExtract(ck, secret), label+" | "+labelChainNext, hashSize)
}

func katSeal(key, aad, pt []byte) []byte {
	a, err := chacha20poly1305.New(key)
	if err != nil {
		panic(err)
	}
	return a.Seal(nil, make([]byte, AEADNonceSize), pt, aad)
}

func katX25519(t *testing.T, priv, pub []byte) []byte {
	t.Helper()
	sk, err := ecdh.X25519().NewPrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	pk, err := ecdh.X25519().NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	out, err := sk.ECDH(pk)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func katPublic(t *testing.T, priv []byte) []byte {
	t.Helper()
	sk, err := ecdh.X25519().NewPrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	return sk.PublicKey().Bytes()
}

// katAdmissionTagInput serialises the exact byte string the admission MAC is
// computed over. It is emitted as a vector of its own because it is the single
// most likely thing for a second implementation to get wrong: none of it is on
// the wire, so a mistake here is invisible until two implementations refuse
// each other's traffic with no diagnostic.
func katAdmissionTagInput(gatewayID []byte, tagLen int, bucket int64, body []byte) []byte {
	var b []byte
	b = append(b, []byte(labelAdmitTag)...)
	b = append(b, 0x00)
	b = append(b, tagVersion)
	b = binary.BigEndian.AppendUint16(b, uint16(tagLen))
	b = binary.BigEndian.AppendUint64(b, uint64(bucket))
	b = append(b, byte(len(gatewayID)))
	b = append(b, gatewayID...)
	b = append(b, body...)
	return b
}

func katResponseTagInput(tagLen int, body []byte) []byte {
	var b []byte
	b = append(b, []byte(labelRespTag)...)
	b = append(b, 0x00, tagVersion, byte(tagLen))
	b = append(b, body...)
	return b
}

func katDemuxInput(counter uint64) []byte {
	b := append([]byte(nil), []byte(labelDemux)...)
	return binary.BigEndian.AppendUint64(b, counter)
}

func katTruncMAC(key, msg []byte, n int) []byte {
	m := hmac.New(sha256.New, key)
	m.Write(msg)
	return m.Sum(nil)[:n]
}

func katXOR(a, b []byte) []byte {
	out := make([]byte, len(a))
	subtle.XORBytes(out, a, b)
	return out
}

// --- the vector set ----------------------------------------------------------

func buildKATFile(t *testing.T) katFile {
	t.Helper()

	f := katFile{
		Format:   "winn3-cross-implementation-kat",
		Version:  1,
		Protocol: WireVersion,
		Suite:    Suite,
		Purpose: []string{
			"Vectors an INDEPENDENT implementation of Winn Protocol v3 can be built from and checked against.",
			"Every case carries its inputs, its outputs and the derivation that connects them; no Go is needed to reproduce any value here.",
			"The primitives assumed are SHA-256, HMAC-SHA-256, HKDF-SHA-256 (RFC 5869), X25519 (RFC 7748) and ChaCha20-Poly1305 (RFC 8439). Nothing else.",
			"Companion prose: docs/handoff/WINN3_STANDALONE_PROTOCOL_DESIGN_20260808.md sections 3 and 5, and docs/handoff/WINN3_ELLIGATOR_AND_KATS_20260808.md.",
		},
		Conventions: []string{
			"type=hex: lowercase hex, no prefix. type=utf8: the literal string, no terminator, no length prefix. type=int: decimal, signed 64-bit. type=dec: decimal bignum.",
			"HKDF-Expand(PRK, info, L) and HKDF-Extract(salt, IKM) are RFC 5869 with SHA-256. Note the argument ORDER: Extract's salt is named first here.",
			"All multi-byte integers on the wire and in MAC inputs are BIG-ENDIAN unless a field says otherwise. Field elements in the Elligator2 group are LITTLE-ENDIAN, as X25519 requires.",
			"Every handshake AEAD uses an ALL-ZERO 12-byte nonce. That is correct and not an oversight: each stage key is derived under its own label from a chaining key that has already absorbed every preceding secret, so no stage key is ever used twice.",
			"Handshake padding is zero bytes and is inside the AEAD. These vectors use padTo=0 so the pad length is 0 and the messages are the unpadded floor.",
		},
	}

	f.Groups = append(f.Groups,
		katLabels(),
		katChainGroup(t),
		katAdmissionGroup(t),
		katBucketGroup(),
		katInitiationGroup(t),
		katResponseGroup(t),
		katTrafficGroup(t),
		katTransportGroup(t),
		katRatchetGroup(t),
		katFrameGroup(t),
		katElligatorGroup(t),
	)
	return f
}

// 1. Labels. Every one of them, exactly, because a label is an HKDF info string
// and a single wrong character is a completely different protocol that fails
// with no diagnostic.
func katLabels() katGroup {
	g := katGroup{
		ID:   "labels",
		What: "Every domain-separation string in the protocol, verbatim.",
		Derivation: []string{
			"protocol_label = wire_version || \" \" || suite. It is hashed to seed the transcript and never appears on the wire.",
			"chain_next is not used alone: mixSecret's info string is <stage label> || \" | \" || chain_next.",
			"epoch keys append to epoch_base; see the traffic_keys group for the exact composition.",
		},
	}
	add := func(name, v string) {
		g.Cases = append(g.Cases, katCase{Name: name, Out: []katField{ks("value", v)}})
	}
	add("protocol_label", protocolLabel)
	add("chain_next", labelChainNext)
	add("dh_ephemeral_static", labelDHEphStatic)
	add("dh_static_static", labelDHStaticStatic)
	add("dh_ephemeral_ephemeral", labelDHEphEph)
	add("dh_static_ephemeral", labelDHStaticEph)
	add("preshared_key", labelPSK)
	add("stage_static", labelStageStatic)
	add("stage_payload", labelStagePayload)
	add("stage_response", labelStageResponse)
	add("pq_ratchet", labelPQ)
	add("rekey_ratchet", labelRekey)
	add("response_tag", labelRespTag)
	add("response_whiten", labelRespWhite)
	add("admission_tag", labelAdmitTag)
	add("admission_whiten", labelAdmitWhtn)
	add("epoch_base", labelEpoch)
	add("demux", labelDemux)
	add("stream_length_reserved", labelStreamLen)
	return g
}

// 2. The three chain primitives, in isolation.
func katChainGroup(t *testing.T) katGroup {
	t.Helper()
	g := katGroup{
		ID:   "chain",
		What: "The transcript hash h and the chaining key ck: seeding, mixHash, mixSecret, and the non-advancing derive.",
		Derivation: []string{
			"seed:      h = SHA-256(protocol_label); ck = h. The responder static key does NOT enter ck.",
			"           Then mixHash(responder_static_public), which binds the gateway identity into h only.",
			"mixHash(x):     h  <- SHA-256(h || x)",
			"mixSecret(s,L): ck <- HKDF-Expand(PRK = HKDF-Extract(salt = ck, IKM = s), info = L || \" | \" || chain_next, L_out = 32)",
			"                This is the ONLY way secret material enters the chain and the only thing that advances ck.",
			"derive(L,n):    HKDF-Expand(PRK = ck, info = L, L_out = n). It reads ck directly as the PRK, SKIPPING Extract, and does NOT advance ck.",
			"There is no split(). A stage key is a derive off the current ck.",
		},
	}

	h0 := sha256.Sum256([]byte(protocolLabel))
	rstat := mustSeedPub(t, "winn3-kat-gateway-static")
	h1 := katMixHash(h0[:], rstat)
	g.Cases = append(g.Cases, katCase{
		Name: "seed",
		In:   []katField{ks("protocol_label", protocolLabel), kh("responder_static_public", rstat)},
		Out: []katField{
			kh("h_after_label", h0[:]),
			kh("ck_after_label", h0[:]),
			kh("h_after_responder_static", h1),
		},
		Note: "ck is unchanged by the mixHash; only h moves.",
	})

	g.Cases = append(g.Cases, katCase{
		Name: "mix_hash",
		In:   []katField{kh("h", h1), kh("data", []byte("winn3 mixhash vector"))},
		Out:  []katField{kh("h_next", katMixHash(h1, []byte("winn3 mixhash vector")))},
	})

	ck := h0[:]
	secret := bytes.Repeat([]byte{0x11}, 32)
	prk := katHKDFExtract(ck, secret)
	g.Cases = append(g.Cases, katCase{
		Name: "mix_secret",
		In: []katField{
			kh("ck", ck), kh("secret", secret), ks("label", labelDHEphStatic),
		},
		Out: []katField{
			ks("info", labelDHEphStatic+" | "+labelChainNext),
			kh("hkdf_extract_prk", prk),
			kh("ck_next", katMixSecret(ck, secret, labelDHEphStatic)),
		},
		Note: "hkdf_extract_prk is emitted so a mismatch can be localised to Extract or to Expand.",
	})

	g.Cases = append(g.Cases, katCase{
		Name: "derive",
		In:   []katField{kh("ck", ck), ks("label", labelStageStatic), ki("length", 32)},
		Out:  []katField{kh("out", katHKDFExpand(ck, labelStageStatic, 32))},
		Note: "No Extract. ck is used directly as the HKDF PRK.",
	})
	g.Cases = append(g.Cases, katCase{
		Name: "derive_short",
		In:   []katField{kh("ck", ck), ks("label", "winn3 epoch v1 e0 i2r salt"), ki("length", 4)},
		Out:  []katField{kh("out", katHKDFExpand(ck, "winn3 epoch v1 e0 i2r salt", 4))},
		Note: "A 4-byte derive, to pin that L_out is honoured rather than truncated from 32.",
	})
	return g
}

// 3. The admission layer. NONE of this is specified anywhere else in prose, and
// none of its inputs appear on the wire, so it is the part of the protocol a
// second implementation is most likely to get silently wrong.
func katAdmissionGroup(t *testing.T) katGroup {
	t.Helper()
	g := katGroup{
		ID: "admission",
		What: "The admission tag that is the first field of every initiation, and the whitening keystream that covers everything after it. " +
			"NOTE: this layer contributes nothing to integrity or authentication; deleting it entirely leaves the cryptographic core exactly as sound.",
		Derivation: []string{
			"tag_input = admission_tag_label || 0x00 || tag_version(1) || tag_len(2 BE) || bucket(8 BE, two's complement) || len(gateway_id)(1) || gateway_id || body",
			"tag       = HMAC-SHA-256(key = admission_key, tag_input) truncated to tag_len bytes",
			"tag_version is 1. bucket, tag_len and gateway_id are AUTHENTICATED INPUTS and are NEVER TRANSMITTED.",
			"keystream = HKDF-Expand(PRK = HKDF-Extract(salt = admission_key, IKM = tag), info = admission_whiten_label, L_out = len(body))",
			"           note the unusual assignment: the per-packet TAG is the Extract input keying material and the per-gateway KEY is the salt.",
			"message   = tag || (body XOR keystream)",
			"The MAC is computed over the PLAINTEXT body, not over the whitened bytes. That is safe here because the keystream is derived from the tag itself, so altering any whitened byte alters the recovered body and the recomputed tag fails.",
			"The response is the same shape with a different key and a shorter header:",
			"resp_tag_input = response_tag_label || 0x00 || tag_version(1) || tag_len(1) || body      <- tag_len is ONE byte here, not two",
			"resp_tag       = HMAC-SHA-256(key = derive(response_tag_label, 32), resp_tag_input)[:tag_len]",
			"resp_keystream = HKDF-Expand(HKDF-Extract(salt = derive(response_whiten_label, 32), IKM = resp_tag), info = response_whiten_label, L_out = len(body))",
			"Both response keys come from the chain as it stands AFTER the initiation and BEFORE any response secret is mixed.",
		},
	}

	key := mustSeed("winn3-kat-admission")
	gid := []byte(vecGatewayIDText)
	body := bytes.Repeat([]byte{0x5A}, 64)
	in := katAdmissionTagInput(gid, DefaultTagSize, vecBucket, body)
	tag := katTruncMAC(key, in, DefaultTagSize)
	g.Cases = append(g.Cases, katCase{
		Name: "tag_default_size",
		In: []katField{
			kh("admission_key", key), ks("gateway_id", string(gid)),
			ki("tag_len", int64(DefaultTagSize)), ki("bucket", vecBucket), kh("body", body),
		},
		Out: []katField{kh("tag_input", in), kh("tag", tag)},
	})

	in16 := katAdmissionTagInput(gid, MinTagSize, vecBucket, body)
	g.Cases = append(g.Cases, katCase{
		Name: "tag_min_size",
		In: []katField{
			kh("admission_key", key), ks("gateway_id", string(gid)),
			ki("tag_len", int64(MinTagSize)), ki("bucket", vecBucket), kh("body", body),
		},
		Out: []katField{kh("tag_input", in16), kh("tag", katTruncMAC(key, in16, MinTagSize))},
		Note: "tag_len is bound into the MAC input, so a 16-byte tag is NOT the prefix of the 32-byte tag over the same body. " +
			"Without that binding a message sealed for a 32-byte-tag gateway would verify at a 16-byte-tag gateway sharing the key.",
	})

	ksArb := expandFrom([]byte("tag"), []byte("key"), labelAdmitWhtn, 16)
	g.Cases = append(g.Cases, katCase{
		Name: "whiten_keystream_arbitrary",
		In:   []katField{ks("admission_key", "key"), ks("tag", "tag"), ki("length", 16)},
		Out:  []katField{kh("keystream", ksArb)},
		Note: "Deliberately short, non-key-sized inputs, so an implementer can check the HKDF wiring without first getting a handshake right.",
	})

	ks64 := expandFrom(tag, key, labelAdmitWhtn, len(body))
	g.Cases = append(g.Cases, katCase{
		Name: "whiten_and_seal",
		In:   []katField{kh("admission_key", key), kh("tag", tag), kh("body", body)},
		Out:  []katField{kh("keystream", ks64), kh("message", append(append([]byte{}, tag...), katXOR(body, ks64)...))},
	})

	rtk := bytes.Repeat([]byte{0x2B}, 32)
	rBody := bytes.Repeat([]byte{0xC3}, 48)
	rIn := katResponseTagInput(DefaultTagSize, rBody)
	g.Cases = append(g.Cases, katCase{
		Name: "response_tag",
		In:   []katField{kh("response_tag_key", rtk), ki("tag_len", int64(DefaultTagSize)), kh("body", rBody)},
		Out:  []katField{kh("tag_input", rIn), kh("tag", katTruncMAC(rtk, rIn, DefaultTagSize))},
		Note: "The response header is THREE bytes (0x00, tag_version, tag_len) where the initiation's is twelve. They are not the same serialisation.",
	})
	return g
}

// 4. The never-transmitted freshness bucket.
func katBucketGroup() katGroup {
	g := katGroup{
		ID:   "freshness_bucket",
		What: "The time bucket that is an authenticated input to the admission tag and is never transmitted.",
		Derivation: []string{
			"bucket = floor(unix_seconds / bucket_window_seconds), FLOORED TOWARD NEGATIVE INFINITY.",
			"That is not the same as C-style integer division: truncation toward zero would make the bucket immediately before the Unix epoch twice as wide.",
			"A verifier tries buckets nearest-first: centre, centre-1, centre+1, centre-2, centre+2, ... up to spread = ceil(max_skew / bucket_window).",
			"Defaults: bucket_window = 10s, max_skew = 60s, therefore spread = 6 and 13 candidate buckets.",
			"The handshake replay cache lifetime is exactly (2*spread + 1) * bucket_window, which is the same span as the acceptance window.",
		},
	}
	for _, tc := range []struct {
		name string
		secs int64
		win  int64
	}{
		{"pinned_kat_time", 1786924800, 10},
		{"epoch", 0, 10},
		{"just_before_epoch", -1, 10},
		{"ten_before_epoch", -10, 10},
		{"eleven_before_epoch", -11, 10},
		{"one_second_window", 1786924807, 1},
	} {
		got := bucketIndex(timeUnix(tc.secs), durSeconds(tc.win))
		g.Cases = append(g.Cases, katCase{
			Name: tc.name,
			In:   []katField{ki("unix_seconds", tc.secs), ki("bucket_window_seconds", tc.win)},
			Out:  []katField{ki("bucket", got)},
		})
	}
	g.Cases = append(g.Cases, katCase{
		Name: "candidate_order",
		In:   []katField{ki("centre", 100), ki("spread", 3)},
		Out:  []katField{ks("buckets", "100,99,101,98,102,97,103")},
		Note: "Nearest first, so a client with a correct clock costs exactly one HMAC.",
	})
	return g
}

// 5 and 6. The two handshake messages, every intermediate.
func katInitiationGroup(t *testing.T) katGroup {
	t.Helper()
	w := katWalkInitiation(t)
	return katGroup{
		ID:   "handshake_initiation",
		What: "A complete initiation, client to gateway, with every chaining key, transcript hash, DH output and stage key on the way.",
		Derivation: []string{
			"wire: admission_tag(tag_len) || whitened( ephemeral(32) || sealed_static(48) || sealed_payload(3 + payload + pad + 16) )",
			"1.  h  = SHA-256(protocol_label); ck = h; mixHash(responder_static_public)",
			"2.  mixHash(ephemeral_public)                        <- the WIRE encoding of the ephemeral, whatever the codec produced",
			"3.  es = X25519(ephemeral_private, responder_static_public); mixSecret(es, dh_ephemeral_static)",
			"4.  k1 = derive(stage_static, 32)",
			"5.  sealed_static = ChaCha20-Poly1305(key = k1, nonce = 0^12, aad = h, plaintext = initiator_static_public)",
			"6.  mixHash(sealed_static)",
			"7.  ss = X25519(initiator_static_private, responder_static_public); mixSecret(ss, dh_static_static)",
			"8.  if a PSK is configured: mixSecret(psk, preshared_key)     <- omitted entirely when there is none",
			"9.  k2 = derive(stage_payload, 32)",
			"10. inner = flags(1, must be 0) || payload_len(2 BE) || payload || pad(zero bytes)",
			"11. sealed_payload = ChaCha20-Poly1305(key = k2, nonce = 0^12, aad = h, plaintext = inner)",
			"12. mixHash(sealed_payload)",
			"13. body = ephemeral || sealed_static || sealed_payload; then the admission group's tag and whitening.",
			"The order of steps 2..12 IS the protocol. A reordering is a different protocol that fails with no diagnostic.",
		},
		Cases: []katCase{{
			Name: "pinned_initiation",
			In: []katField{
				kh("initiator_static_private", w.cliPriv), kh("initiator_static_public", w.cliPub),
				kh("responder_static_private", w.gwPriv), kh("responder_static_public", w.gwPub),
				kh("psk", w.psk),
				kh("ephemeral_private", w.ephPriv), kh("ephemeral_public", w.ephPub),
				kh("admission_key", w.admKey), ks("gateway_id", string(w.gwID)),
				ki("tag_len", int64(DefaultTagSize)), ki("bucket", vecBucket),
				ks("payload", string(w.payload)), ki("pad_len", 0),
			},
			Out: []katField{
				kh("h0_after_protocol_label", w.h0),
				kh("h1_after_responder_static", w.h1),
				kh("h2_after_ephemeral", w.h2),
				kh("dh_es", w.es),
				kh("ck1_after_es", w.ck1),
				kh("k1_stage_static", w.k1),
				kh("sealed_static", w.cstat),
				kh("h3_after_sealed_static", w.h3),
				kh("dh_ss", w.ss),
				kh("ck2_after_ss", w.ck2),
				kh("ck3_after_psk", w.ck3),
				kh("k2_stage_payload", w.k2),
				kh("inner_plaintext", w.inner),
				kh("sealed_payload", w.cpay),
				kh("h4_after_sealed_payload", w.h4),
				kh("body", w.body),
				kh("admission_tag", w.tag),
				kh("whiten_keystream", w.wks),
				kh("message", w.msg),
				ki("message_len", int64(len(w.msg))),
			},
		}},
	}
}

func katResponseGroup(t *testing.T) katGroup {
	t.Helper()
	w := katWalkInitiation(t)
	r := katWalkResponse(t, w)
	return katGroup{
		ID:   "handshake_response",
		What: "The gateway's reply to the pinned initiation, with every intermediate. Continues directly from handshake_initiation.",
		Derivation: []string{
			"wire: response_tag(tag_len) || whitened( ephemeral(32) || sealed_payload(3 + payload + pad + 16) )",
			"There is no sealed static: the responder's identity is never on the wire at all.",
			"1. response_tag_key    = derive(response_tag, 32)     <- BOTH off the post-initiation ck,",
			"2. response_whiten_key = derive(response_whiten, 32)     BEFORE any response secret is mixed. Order matters.",
			"3. mixHash(responder_ephemeral_public)",
			"4. ee = X25519(responder_ephemeral_private, initiator_ephemeral_public); mixSecret(ee, dh_ephemeral_ephemeral)",
			"5. se = X25519(responder_ephemeral_private, initiator_static_public);    mixSecret(se, dh_static_ephemeral)",
			"6. k3 = derive(stage_response, 32)",
			"7. sealed_payload = ChaCha20-Poly1305(key = k3, nonce = 0^12, aad = h, plaintext = flags || payload_len || payload || pad)",
			"8. mixHash(sealed_payload)      <- AFTER the AEAD, not before",
			"The chain state at the end of step 8 is what both ends carry into the transport keys.",
		},
		Cases: []katCase{{
			Name: "pinned_response",
			In: []katField{
				kh("ck_after_initiation", w.ck3), kh("h_after_initiation", w.h4),
				kh("initiator_ephemeral_public", w.ephPub), kh("initiator_static_public", w.cliPub),
				kh("responder_ephemeral_private", r.ephPriv), kh("responder_ephemeral_public", r.ephPub),
				ki("tag_len", int64(DefaultTagSize)),
				ks("payload", string(r.payload)), ki("pad_len", 0),
			},
			Out: []katField{
				kh("response_tag_key", r.tagKey),
				kh("response_whiten_key", r.whitenKey),
				kh("h5_after_ephemeral", r.h5),
				kh("dh_ee", r.ee),
				kh("ck4_after_ee", r.ck4),
				kh("dh_se", r.se),
				kh("ck5_after_se", r.ck5),
				kh("k3_stage_response", r.k3),
				kh("inner_plaintext", r.inner),
				kh("sealed_payload", r.cpay),
				kh("h6_final", r.h6),
				kh("body", r.body),
				kh("response_tag", r.tag),
				kh("whiten_keystream", r.wks),
				kh("message", r.msg),
				ki("message_len", int64(len(r.msg))),
			},
		}},
	}
}

// 7. Traffic keys.
func katTrafficGroup(t *testing.T) katGroup {
	t.Helper()
	w := katWalkInitiation(t)
	r := katWalkResponse(t, w)
	g := katGroup{
		ID:   "traffic_keys",
		What: "The per-epoch, per-direction transport keys derived from the final handshake chaining key.",
		Derivation: []string{
			"info(E, dir, what) = \"winn3 epoch v1 e\" || decimal(E) || \" \" || dir || \" \" || what",
			"                     dir is exactly \"i2r\" or \"r2i\"; what is exactly \"key\", \"salt\" or \"demux\".",
			"                     decimal(E) has no padding: epoch 0 is \"e0\", epoch 10 is \"e10\".",
			"key   = derive(info(E, dir, \"key\"),   32)",
			"salt  = derive(info(E, dir, \"salt\"),   4)      <- the nonce prefix; never transmitted",
			"demux = derive(info(E, dir, \"demux\"), 32)      <- keys the per-packet token",
			"All three are non-advancing derives off the SAME ck. Epoch 0 is installed the moment the handshake completes.",
			"Send/receive assignment is by role: the initiator sends i2r and receives r2i; the responder is the mirror.",
			"The epoch number is inside every info string, so two epochs cannot share a key even if a future ratchet installed an epoch without advancing the chain.",
		},
	}
	for _, dir := range []string{dirI2R, dirR2I} {
		g.Cases = append(g.Cases, katCase{
			Name: "epoch0_" + dir,
			In:   []katField{kh("ck", r.ck5), ki("epoch", 0), ks("direction", dir)},
			Out: []katField{
				ks("info_key", epochInfo(0, dir, "key")),
				kh("key", katHKDFExpand(r.ck5, epochInfo(0, dir, "key"), KeySize)),
				ks("info_salt", epochInfo(0, dir, "salt")),
				kh("nonce_salt", katHKDFExpand(r.ck5, epochInfo(0, dir, "salt"), nonceSaltSize)),
				ks("info_demux", epochInfo(0, dir, "demux")),
				kh("demux_key", katHKDFExpand(r.ck5, epochInfo(0, dir, "demux"), KeySize)),
			},
		})
	}
	g.Cases = append(g.Cases, katCase{
		Name: "info_string_shape",
		In:   []katField{ki("epoch", 10), ks("direction", dirR2I)},
		Out:  []katField{ks("info_key", epochInfo(10, dirR2I, "key"))},
		Note: "Pins that the epoch is rendered as unpadded decimal.",
	})
	return g
}

// 8. Transport messages.
func katTransportGroup(t *testing.T) katGroup {
	t.Helper()
	w := katWalkInitiation(t)
	r := katWalkResponse(t, w)
	dk := katHKDFExpand(r.ck5, epochInfo(0, dirI2R, "demux"), KeySize)
	key := katHKDFExpand(r.ck5, epochInfo(0, dirI2R, "key"), KeySize)
	salt := katHKDFExpand(r.ck5, epochInfo(0, dirI2R, "salt"), nonceSaltSize)

	g := katGroup{
		ID:   "transport",
		What: "A transport message: the demux token that replaces every header field, and the AEAD around it.",
		Derivation: []string{
			"wire: demux_token(8) || ChaCha20-Poly1305 ciphertext+tag",
			"There is NO counter on the wire, no session index, no type byte, no length field and no version. The counter is implicit in the token.",
			"token_input = demux_label || counter(8 BE)",
			"token       = HMAC-SHA-256(key = demux_key, token_input) truncated to 8 bytes",
			"nonce       = nonce_salt(4) || counter(8 BE)                 total 12 bytes",
			"aad         = token, exactly as it appears on the wire",
			"inner       = payload_len(2 BE) || payload || pad(zero bytes)",
			"message     = token || ChaCha20-Poly1305(key, nonce, inner, aad)",
			"The receiver precomputes a forward window of expected tokens and looks the arriving token up; a consumed token is erased, which IS the replay filter.",
			"Note the inner header is 2 bytes here and 3 in a handshake message: transport has no flags byte.",
		},
	}
	for _, tc := range []struct {
		name    string
		counter uint64
		payload string
		pad     int
	}{
		{"counter_0", 0, "winn3 kat payload", 0},
		{"counter_1", 1, "winn3 kat payload", 0},
		{"counter_42_padded", 42, "abc", 20},
		{"empty_payload", 7, "", 0},
	} {
		tokIn := katDemuxInput(tc.counter)
		tok := katTruncMAC(dk, tokIn, DemuxTokenSize)
		nonce := append(append([]byte{}, salt...), binary.BigEndian.AppendUint64(nil, tc.counter)...)
		inner := binary.BigEndian.AppendUint16(nil, uint16(len(tc.payload)))
		inner = append(inner, tc.payload...)
		inner = append(inner, make([]byte, tc.pad)...)
		a, err := chacha20poly1305.New(key)
		if err != nil {
			t.Fatal(err)
		}
		msg := append(append([]byte{}, tok...), a.Seal(nil, nonce, inner, tok)...)
		g.Cases = append(g.Cases, katCase{
			Name: tc.name,
			In: []katField{
				kh("demux_key", dk), kh("aead_key", key), kh("nonce_salt", salt),
				ki("counter", int64(tc.counter)), ks("payload", tc.payload), ki("pad_len", int64(tc.pad)),
			},
			Out: []katField{
				kh("token_input", tokIn), kh("demux_token", tok),
				kh("nonce", nonce), kh("aad", tok), kh("inner_plaintext", inner),
				kh("message", msg), ki("message_len", int64(len(msg))),
			},
		})
	}
	g.Cases = append(g.Cases, katCase{
		Name: "overhead",
		Out: []katField{
			ki("demux_token_bytes", DemuxTokenSize),
			ki("inner_length_bytes", transportHeaderSize),
			ki("aead_tag_bytes", AEADTagSize),
			ki("total_overhead", int64(TransportOverhead())),
		},
	})
	return g
}

// 9. Ratchets.
func katRatchetGroup(t *testing.T) katGroup {
	t.Helper()
	w := katWalkInitiation(t)
	r := katWalkResponse(t, w)
	g := katGroup{
		ID:   "ratchets",
		What: "The two in-band epoch ratchets. Both are a mixSecret followed by re-running the same three derives at E+1.",
		Derivation: []string{
			"post-quantum: ck <- mixSecret(ml_kem_768_shared_secret, pq_ratchet); epoch <- epoch + 1",
			"rekey:        ck <- mixSecret(x25519_shared_secret,     rekey_ratchet); epoch <- epoch + 1",
			"h is NOT touched by either ratchet. Only ck advances.",
			"The message counter restarts at zero in every epoch, and the receive window is rebuilt from the new demux key.",
			"Neither ratchet has a wire format of its own: the frames that carry them are ordinary transport frames (see the frames group).",
		},
	}
	pqSecret := bytes.Repeat([]byte{0x3D}, 32)
	ck6 := katMixSecret(r.ck5, pqSecret, labelPQ)
	g.Cases = append(g.Cases, katCase{
		Name: "pq_ratchet_epoch1",
		In:   []katField{kh("ck", r.ck5), kh("shared_secret", pqSecret)},
		Out: []katField{
			ks("info", labelPQ+" | "+labelChainNext),
			kh("ck_next", ck6),
			kh("epoch1_i2r_key", katHKDFExpand(ck6, epochInfo(1, dirI2R, "key"), KeySize)),
			kh("epoch1_i2r_salt", katHKDFExpand(ck6, epochInfo(1, dirI2R, "salt"), nonceSaltSize)),
			kh("epoch1_i2r_demux", katHKDFExpand(ck6, epochInfo(1, dirI2R, "demux"), KeySize)),
		},
		Note: "ML-KEM-768 shared secrets are 32 bytes; a fixed byte pattern is used here so the vector does not depend on a KEM implementation.",
	})
	rkSecret := bytes.Repeat([]byte{0x8E}, 32)
	ck7 := katMixSecret(r.ck5, rkSecret, labelRekey)
	g.Cases = append(g.Cases, katCase{
		Name: "rekey_ratchet_epoch1",
		In:   []katField{kh("ck", r.ck5), kh("shared_secret", rkSecret)},
		Out: []katField{
			ks("info", labelRekey+" | "+labelChainNext),
			kh("ck_next", ck7),
			kh("epoch1_r2i_key", katHKDFExpand(ck7, epochInfo(1, dirR2I, "key"), KeySize)),
		},
	})
	return g
}

// 10. Frames.
func katFrameGroup(t *testing.T) katGroup {
	t.Helper()
	g := katGroup{
		ID:   "frames",
		What: "The TLV inside a transport message's plaintext payload.",
		Derivation: []string{
			"frame = type(1) || length(2 BE) || value",
			"Type 0 is RESERVED and never valid, so a zero-filled buffer never parses as a frame stream.",
			"Parsing is STRICT: a trailing partial frame, a zero type, or a length running past the buffer discards the whole message. Leniency would be a parsing differential between implementations, and a parsing differential is a fingerprint.",
			"Frames are concatenated with no separator and no count. The stream ends when the buffer does.",
		},
	}
	for name, ft := range map[string]FrameType{
		"data": FrameData, "pad": FramePad, "ping": FramePing, "pong": FramePong,
		"pq_ek": FramePQEK, "pq_ct": FramePQCT,
		"rekey_init": FrameRekeyInit, "rekey_ack": FrameRekeyAck, "close": FrameClose,
	} {
		g.Cases = append(g.Cases, katCase{
			Name: "type_" + name,
			Out:  []katField{ki("value", int64(ft))},
		})
	}
	// map iteration is random; sort by the emitted type so the file is stable.
	sortCasesByIntOut(g.Cases)

	enc, err := AppendFrame(nil, FrameData, []byte("hello"))
	if err != nil {
		t.Fatal(err)
	}
	enc, err = AppendFrame(enc, FramePad, make([]byte, 4))
	if err != nil {
		t.Fatal(err)
	}
	g.Cases = append(g.Cases, katCase{
		Name: "encode_two_frames",
		In:   []katField{ks("frame1", "DATA:\"hello\""), ks("frame2", "PAD:4 zero bytes")},
		Out:  []katField{kh("encoded", enc)},
	})
	return g
}

// 11. Elligator2.
func katElligatorGroup(t *testing.T) katGroup {
	t.Helper()
	g := katGroup{
		ID: "elligator2",
		What: "The v1.1 ephemeral codec: an on-wire ephemeral indistinguishable from random bytes with NO shared secret. " +
			"Opt-in; both ends must be configured for it, because nothing on this datapath is negotiated.",
		Derivation: []string{
			"Curve25519 in Montgomery form: v^2 = u^3 + A u^2 + u, A = 486662, p = 2^255 - 19, and the map's non-square Z = 2.",
			"Field elements are encoded LITTLE-ENDIAN in 32 bytes, as X25519 requires.",
			"FORWARD (wire -> X25519 public key). Total: every 32-byte string names a point, so there is no input a decoder rejects and therefore no oracle in it.",
			"  r  = little_endian(wire) with bits 254 and 255 CLEARED",
			"  w  = 1 + Z*r^2                            (never zero, because -1/Z is a non-residue)",
			"  x1 = -A * w^-1",
			"  u  = x1        if g(x1) is a quadratic residue, where g(x) = x^3 + A x^2 + x",
			"  u  = -x1 - A   otherwise",
			"INVERSE (public key -> wire). Defined for about half of all points; fails otherwise, and the caller redraws.",
			"  fails if u = 0 or u = -A",
			"  branch 0:  r^2 = -u / (Z * (u + A))          (u was produced by the x2 case)",
			"  branch 1:  r^2 = -(u + A) / (Z * u)          (u was produced by the x1 case)",
			"  fails if that value is not a residue; note the two branches succeed together or fail together, because their product is 1/Z^2.",
			"  r = sqrt(r^2), canonicalised to r <= (p-1)/2, then bits 254 and 255 are filled with SENDER RANDOMNESS.",
			"KEY GENERATION. Per attempt: read 32 bytes for the scalar, then 1 byte of tweak.",
			"  tweak bits 0-2: which of the eight points of E[8] to ADD to the public key",
			"  tweak bit  3:   which branch of the inverse map to use",
			"  tweak bits 6-7: copied into bits 254 and 255 of the representative",
			"  If the inverse map fails, discard everything and draw again. Expected 2 attempts.",
			"WHY THE TORSION IS ADDED. A representative decodes to a curve point and anyone can decode one. A plain X25519 public key is always in the prime-order subgroup; the point behind a random 32-byte string is so about one time in eight. Without a random 8-torsion component, ONE scalar multiplication per packet distinguishes an ephemeral from random bytes with no key at all. Adding T of order dividing 8 is free because every peer clamps: 8k(P+T) = 8kP, so the shared secret is unchanged.",
			"RESIDUAL BIAS: the 9 field values in ((p-1)/2, 2^254) can never occur, i.e. about 2^-250 of the space.",
			"The wire width is 32 bytes, unchanged, so no length in this protocol moves.",
		},
	}
	g.Cases = append(g.Cases, katCase{
		Name: "parameters",
		Out: []katField{
			kd("p", ellP), kd("A", ellA), kd("Z", ellZ), kd("half_p", ellHalfP),
			kd("sqrt_minus_one", ellSqrtM1),
		},
	})

	tab := ellTorsion()
	for i := 0; i < 8; i++ {
		out := []katField{ki("index", int64(i))}
		if tab[i].inf {
			out = append(out, ks("point", "identity"))
		} else {
			out = append(out, kd("u", tab[i].u), kd("v", tab[i].v), kh("u_wire", ellToWire(tab[i].u)))
		}
		g.Cases = append(g.Cases, katCase{Name: "torsion_" + strconv.Itoa(i), Out: out})
	}

	for _, tc := range []struct{ name, wire string }{
		{"map_zero", "0000000000000000000000000000000000000000000000000000000000000000"},
		{"map_one", "0100000000000000000000000000000000000000000000000000000000000000"},
		{"map_top_bits_only", "00000000000000000000000000000000000000000000000000000000000000c0"},
		{"map_all_ff", "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"},
		{"map_kat_pattern", "5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a"},
	} {
		wire := mustHex(t, tc.wire)
		g.Cases = append(g.Cases, katCase{
			Name: tc.name,
			In:   []katField{kh("wire", wire)},
			Out:  []katField{kh("x25519_public", elligatorMap(wire))},
		})
	}

	// Inverse map, against a pinned public key, both branches.
	scalar := mustSeed("winn3-kat-elligator-scalar")
	pub := katPublic(t, scalar)
	for branch := 0; branch < 2; branch++ {
		c := katCase{
			Name: "unmap_branch_" + strconv.Itoa(branch),
			In:   []katField{kh("x25519_public", pub), ki("branch", int64(branch))},
		}
		rep, ok := elligatorUnmap(ellFromWire(pub), branch)
		if !ok {
			c.Out = []katField{ks("result", "no representative")}
		} else {
			c.Out = []katField{
				ks("result", "ok"), kd("representative", rep), kh("representative_wire", ellToWire(rep)),
				kh("maps_back_to", elligatorMap(ellToWire(rep))),
			}
		}
		g.Cases = append(g.Cases, c)
	}

	// A degenerate case worth pinning: u = 0 has no representative, and the
	// all-zero wire is what maps TO it.
	g.Cases = append(g.Cases, katCase{
		Name: "unmap_zero_has_no_representative",
		In:   []katField{kh("x25519_public", make([]byte, KeySize))},
		Out:  []katField{ks("result", "no representative")},
		Note: "The all-zero wire maps forward to u = 0. Nothing in the codec rejects it — rejecting inputs is what would make it an oracle — so the refusal comes from X25519's all-zero shared-secret check, one layer up.",
	})

	// Deterministic key generation from a pinned reader.
	kg := Elligator2Codec.(EphemeralKeygen)
	priv, wire, err := kg.GenerateEphemeral(newDetReader("winn3-kat-elligator"))
	if err != nil {
		t.Fatal(err)
	}
	g.Cases = append(g.Cases, katCase{
		Name: "keygen_pinned_reader",
		In:   []katField{ks("reader_seed", "winn3-kat-elligator"), ks("reader", "SHA-256(seed || counter_8_BE) blocks, counter from 0")},
		Out: []katField{
			kh("scalar", priv),
			kh("clean_x25519_public", katPublic(t, priv)),
			kh("representative", wire),
			kh("decoded_public", elligatorMap(wire)),
		},
		Note: "decoded_public differs from clean_x25519_public by an element of E[8]. That is deliberate; both give the same X25519 shared secret against any clamped peer scalar.",
	})
	return g
}

// --- walkthrough helpers -----------------------------------------------------

type katInitWalk struct {
	cliPriv, cliPub, gwPriv, gwPub, psk     []byte
	ephPriv, ephPub                         []byte
	admKey, gwID, payload                   []byte
	h0, h1, h2, h3, h4                      []byte
	es, ss, ck1, ck2, ck3, k1, k2           []byte
	cstat, inner, cpay, body, tag, wks, msg []byte
}

// katWalkInitiation recomputes the pinned initiation from first principles,
// step by step, using only the restated primitives above.
//
// It is deliberately NOT a call into Initiator.WriteInitiation. Two independent
// spellings of the same schedule, required to agree byte for byte, is what
// turns "the vectors match" into evidence; a generator that called the
// implementation would produce a file that agreed with itself by construction
// and would say nothing about whether the derivation prose is right.
func katWalkInitiation(t *testing.T) katInitWalk {
	t.Helper()
	var w katInitWalk
	w.cliPriv = mustSeed("winn3-kat-client-static")
	w.gwPriv = mustSeed("winn3-kat-gateway-static")
	w.cliPub = katPublic(t, w.cliPriv)
	w.gwPub = katPublic(t, w.gwPriv)
	w.psk = mustSeed("winn3-kat-psk")
	w.admKey = mustSeed("winn3-kat-admission")
	w.gwID = []byte(vecGatewayIDText)
	w.payload = []byte("kat")

	// The pinned client reader; with padTo = 0 the first draw is the ephemeral.
	w.ephPriv = make([]byte, KeySize)
	if _, err := newDetReader("winn3-kat-client-rand").Read(w.ephPriv); err != nil {
		t.Fatal(err)
	}
	w.ephPub = katPublic(t, w.ephPriv)

	h := sha256.Sum256([]byte(protocolLabel))
	w.h0 = h[:]
	ck := append([]byte(nil), w.h0...)
	w.h1 = katMixHash(w.h0, w.gwPub)
	w.h2 = katMixHash(w.h1, w.ephPub)

	w.es = katX25519(t, w.ephPriv, w.gwPub)
	w.ck1 = katMixSecret(ck, w.es, labelDHEphStatic)
	w.k1 = katHKDFExpand(w.ck1, labelStageStatic, KeySize)
	w.cstat = katSeal(w.k1, w.h2, w.cliPub)
	w.h3 = katMixHash(w.h2, w.cstat)

	w.ss = katX25519(t, w.cliPriv, w.gwPub)
	w.ck2 = katMixSecret(w.ck1, w.ss, labelDHStaticStatic)
	w.ck3 = katMixSecret(w.ck2, w.psk, labelPSK)
	w.k2 = katHKDFExpand(w.ck3, labelStagePayload, KeySize)

	w.inner = append([]byte{0x00}, binary.BigEndian.AppendUint16(nil, uint16(len(w.payload)))...)
	w.inner = append(w.inner, w.payload...)
	w.cpay = katSeal(w.k2, w.h3, w.inner)
	w.h4 = katMixHash(w.h3, w.cpay)

	w.body = append(append(append([]byte{}, w.ephPub...), w.cstat...), w.cpay...)
	w.tag = katTruncMAC(w.admKey,
		katAdmissionTagInput(w.gwID, DefaultTagSize, vecBucket, w.body), DefaultTagSize)
	w.wks = katHKDFExpand(katHKDFExtract(w.admKey, w.tag), labelAdmitWhtn, len(w.body))
	w.msg = append(append([]byte{}, w.tag...), katXOR(w.body, w.wks)...)
	return w
}

type katRespWalk struct {
	ephPriv, ephPub, payload         []byte
	tagKey, whitenKey                []byte
	h5, h6, ee, se, ck4, ck5, k3     []byte
	inner, cpay, body, tag, wks, msg []byte
}

func katWalkResponse(t *testing.T, w katInitWalk) katRespWalk {
	t.Helper()
	var r katRespWalk
	r.payload = []byte("ok")
	r.ephPriv = make([]byte, KeySize)
	if _, err := newDetReader("winn3-kat-gateway-rand").Read(r.ephPriv); err != nil {
		t.Fatal(err)
	}
	r.ephPub = katPublic(t, r.ephPriv)

	r.tagKey = katHKDFExpand(w.ck3, labelRespTag, KeySize)
	r.whitenKey = katHKDFExpand(w.ck3, labelRespWhite, KeySize)

	r.h5 = katMixHash(w.h4, r.ephPub)
	r.ee = katX25519(t, r.ephPriv, w.ephPub)
	r.ck4 = katMixSecret(w.ck3, r.ee, labelDHEphEph)
	r.se = katX25519(t, r.ephPriv, w.cliPub)
	r.ck5 = katMixSecret(r.ck4, r.se, labelDHStaticEph)
	r.k3 = katHKDFExpand(r.ck5, labelStageResponse, KeySize)

	r.inner = append([]byte{0x00}, binary.BigEndian.AppendUint16(nil, uint16(len(r.payload)))...)
	r.inner = append(r.inner, r.payload...)
	r.cpay = katSeal(r.k3, r.h5, r.inner)
	r.h6 = katMixHash(r.h5, r.cpay)

	r.body = append(append([]byte{}, r.ephPub...), r.cpay...)
	r.tag = katTruncMAC(r.tagKey, katResponseTagInput(DefaultTagSize, r.body), DefaultTagSize)
	r.wks = katHKDFExpand(katHKDFExtract(r.whitenKey, r.tag), labelRespWhite, len(r.body))
	r.msg = append(append([]byte{}, r.tag...), katXOR(r.body, r.wks)...)
	return r
}

func mustSeedPub(t *testing.T, seed string) []byte {
	t.Helper()
	return katPublic(t, mustSeed(seed))
}

func timeUnix(secs int64) time.Time    { return time.Unix(secs, 0).UTC() }
func durSeconds(n int64) time.Duration { return time.Duration(n) * time.Second }

func sortCasesByIntOut(cases []katCase) {
	for i := 1; i < len(cases); i++ {
		for j := i; j > 0; j-- {
			a, _ := strconv.Atoi(cases[j-1].Out[0].Value)
			b, _ := strconv.Atoi(cases[j].Out[0].Value)
			if a <= b {
				break
			}
			cases[j-1], cases[j] = cases[j], cases[j-1]
		}
	}
}

// --- the tests ---------------------------------------------------------------

// TestCrossImplementationVectorsAgreeWithTheImplementation is the load-bearing
// half: every value in the file was recomputed from the RESTATED primitives
// above, and here the same values are demanded of the shipping code paths.
//
// If this passes and TestCrossImplementationVectorsMatchTheFile also passes,
// then the file, the prose derivation and the implementation are all saying the
// same thing.
func TestCrossImplementationVectorsAgreeWithTheImplementation(t *testing.T) {
	w := katWalkInitiation(t)
	r := katWalkResponse(t, w)

	ini, resp := katParties(t)
	msg1, err := ini.WriteInitiation([]byte("kat"), 0)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(msg1, w.msg) {
		t.Fatalf("the independently walked initiation does not match the implementation:\n"+
			" walk %x\n code %x", w.msg, msg1)
	}
	rh, err := resp.ReadInitiation(msg1)
	if err != nil {
		t.Fatal(err)
	}
	msg2, gwSess, err := rh.WriteResponse([]byte("ok"), 0)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(msg2, r.msg) {
		t.Fatalf("the independently walked response does not match the implementation:\n"+
			" walk %x\n code %x", r.msg, msg2)
	}
	cliSess, _, err := ini.ReadResponse(msg2)
	if err != nil {
		t.Fatal(err)
	}

	// The chain state, which is what a second implementation must land on.
	if !bytes.Equal(cliSess.ch.ck[:], r.ck5) {
		t.Errorf("final chaining key:\n walk %x\n code %x", r.ck5, cliSess.ch.ck[:])
	}
	if !bytes.Equal(cliSess.ch.h[:], r.h6) {
		t.Errorf("final transcript hash:\n walk %x\n code %x", r.h6, cliSess.ch.h[:])
	}

	// Traffic keys and the first transport message.
	wantDemux := katHKDFExpand(r.ck5, epochInfo(0, dirI2R, "demux"), KeySize)
	if !bytes.Equal(cliSess.sendDemux[:], wantDemux) {
		t.Errorf("epoch-0 i2r demux key:\n walk %x\n code %x", wantDemux, cliSess.sendDemux[:])
	}
	wantSalt := katHKDFExpand(r.ck5, epochInfo(0, dirI2R, "salt"), nonceSaltSize)
	if !bytes.Equal(cliSess.sendSalt[:], wantSalt) {
		t.Errorf("epoch-0 i2r nonce salt:\n walk %x\n code %x", wantSalt, cliSess.sendSalt[:])
	}

	key := katHKDFExpand(r.ck5, epochInfo(0, dirI2R, "key"), KeySize)
	tok := katTruncMAC(wantDemux, katDemuxInput(0), DemuxTokenSize)
	nonce := append(append([]byte{}, wantSalt...), binary.BigEndian.AppendUint64(nil, 0)...)
	inner := binary.BigEndian.AppendUint16(nil, uint16(len("winn3 kat payload")))
	inner = append(inner, "winn3 kat payload"...)
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		t.Fatal(err)
	}
	want := append(append([]byte{}, tok...), aead.Seal(nil, nonce, inner, tok)...)

	got, err := cliSess.Seal([]byte("winn3 kat payload"), 0)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("first transport message:\n walk %x\n code %x", want, got)
	}
	if _, err := gwSess.Open(got); err != nil {
		t.Errorf("the walked transport message does not open at the other end: %v", err)
	}

	// The ratchet, through the public API rather than through the walk.
	pqSecret := bytes.Repeat([]byte{0x3D}, 32)
	if err := cliSess.MixPQ(pqSecret); err != nil {
		t.Fatal(err)
	}
	wantCK6 := katMixSecret(r.ck5, pqSecret, labelPQ)
	if !bytes.Equal(cliSess.ch.ck[:], wantCK6) {
		t.Errorf("chaining key after the PQ ratchet:\n walk %x\n code %x", wantCK6, cliSess.ch.ck[:])
	}
}

// TestCrossImplementationVectorsMatchTheFile keeps the checked-in artifact
// honest. The file is what a second implementer receives; if it can drift away
// from the code without anything failing, it is worse than no file at all.
func TestCrossImplementationVectorsMatchTheFile(t *testing.T) {
	want := buildKATFile(t)
	encoded, err := json.MarshalIndent(want, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	encoded = append(encoded, '\n')

	if os.Getenv("WINN3_WRITE_KAT") != "" {
		if err := os.MkdirAll(filepath.Dir(katFilePath), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(katFilePath, encoded, 0o644); err != nil {
			t.Fatal(err)
		}
		t.Logf("wrote %d bytes to %s", len(encoded), katFilePath)
		return
	}

	onDisk, err := os.ReadFile(katFilePath)
	if err != nil {
		t.Fatalf("%s is missing; regenerate with WINN3_WRITE_KAT=1: %v", katFilePath, err)
	}
	if !bytes.Equal(onDisk, encoded) {
		t.Fatalf("%s no longer matches the implementation.\n"+
			"If the protocol changed deliberately, regenerate with:\n"+
			"    WINN3_WRITE_KAT=1 go test ./winn3/core/ -run TestCrossImplementationVectors\n"+
			"and treat the diff as a WIRE BREAK until proven otherwise. (%d bytes on disk, %d expected)",
			katFilePath, len(onDisk), len(encoded))
	}
}

// TestCrossImplementationVectorFileIsSelfContained is a guard on the artifact's
// usefulness rather than on its correctness.
//
// The whole point of these vectors is that a second implementer never has to
// open the Go. A group with no derivation, or a case with no output, silently
// fails that promise while still passing every other test in this file.
func TestCrossImplementationVectorFileIsSelfContained(t *testing.T) {
	raw, err := os.ReadFile(katFilePath)
	if err != nil {
		t.Fatal(err)
	}
	var f katFile
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatal(err)
	}
	if len(f.Groups) < 11 {
		t.Fatalf("only %d groups", len(f.Groups))
	}
	seen := map[string]bool{}
	total := 0
	for _, g := range f.Groups {
		if seen[g.ID] {
			t.Errorf("duplicate group id %q", g.ID)
		}
		seen[g.ID] = true
		if g.What == "" {
			t.Errorf("group %q has no description", g.ID)
		}
		if len(g.Derivation) == 0 && g.ID != "labels" {
			t.Errorf("group %q has no derivation; a reader would have to read the Go", g.ID)
		}
		if len(g.Cases) == 0 {
			t.Errorf("group %q has no cases", g.ID)
		}
		for _, c := range g.Cases {
			total++
			if c.Name == "" {
				t.Errorf("group %q has an unnamed case", g.ID)
			}
			if len(c.Out) == 0 {
				t.Errorf("group %q case %q has no expected output", g.ID, c.Name)
			}
			for _, fl := range append(append([]katField{}, c.In...), c.Out...) {
				if fl.Name == "" || fl.Type == "" {
					t.Errorf("group %q case %q has an unnamed or untyped field", g.ID, c.Name)
				}
				if fl.Type == "hex" {
					if _, err := hex.DecodeString(fl.Value); err != nil {
						t.Errorf("group %q case %q field %q is not hex", g.ID, c.Name, fl.Name)
					}
				}
			}
		}
	}
	// Every group a second implementation needs in order, from primitives up.
	for _, want := range []string{
		"labels", "chain", "admission", "freshness_bucket",
		"handshake_initiation", "handshake_response",
		"traffic_keys", "transport", "ratchets", "frames", "elligator2",
	} {
		if !seen[want] {
			t.Errorf("the vector set is missing the %q group", want)
		}
	}
	if total < 60 {
		t.Errorf("only %d cases; that is thin for a set meant to be built from", total)
	}
}
