package gateway

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"sync"

	"winsvpn.local/winnprotocol/winn3/core"
)

// Token is one demux token: the entire visible header of a Winn3 transport
// message, and the only thing a gateway has to route on.
type Token [core.DemuxTokenSize]byte

// labelDemux is the domain-separation label core uses for the demux PRF. It is
// duplicated here rather than imported because core does not export it, and it
// is pinned by a known-answer test so that a change on either side is a test
// failure rather than a silent interoperability break.
//
// The construction is, exactly:
//
//	token = HMAC-SHA256(demuxKey, labelDemux || be64(counter))[:8]
const labelDemux = "winn3 demux v1"

// DeriveToken computes the demux token for a counter under a direction's demux
// key.
//
// This is the gateway's copy of a derivation that core performs privately. See
// the note on labelDemux: the duplication is deliberate and pinned.
func DeriveToken(key *[core.KeySize]byte, counter uint64) Token {
	var ctr [8]byte
	binary.BigEndian.PutUint64(ctr[:], counter)
	mac := hmac.New(sha256.New, key[:])
	mac.Write([]byte(labelDemux))
	mac.Write(ctr[:])
	sum := mac.Sum(nil)
	var t Token
	copy(t[:], sum[:core.DemuxTokenSize])
	return t
}

// TokenSource yields a session's receive-direction demux tokens by counter.
//
// Production wants KeyedSource, built from core.Session.RecvDemuxKey. It is
// still an interface because a caller may have the sequence from somewhere other
// than the key — the integration tests harvest it off real ciphertexts, which is
// how the duplicated labelDemux constant below is checked against real Seal
// output rather than only against its own known-answer vectors.
//
// Implementations must be deterministic, pure, and safe for concurrent use: the
// table calls TokenAt for the same counter more than once (once to insert, once
// to erase) and requires the same answer both times.
type TokenSource interface {
	TokenAt(counter uint64) Token
}

// blockSize is SHA-256's compression block, and therefore HMAC's key padding.
const blockSize = 64

// keyedSourceKeyFitsHMACBlock is the compile-time assertion NewKeyedSource's
// comment refers to. TokenAt xors the key into ipad/opad and never hash-extends;
// crypto/hmac (used by DeriveToken) would hash a longer key first. A KeySize
// above the block would make every token silently disagree, which is a
// gateway-wide routing outage, not a loud construction error.
var _ [blockSize - core.KeySize]byte

// KeyedSource is the production TokenSource: it derives tokens from the
// receive-direction demux key.
//
// It precomputes HMAC's two padded key blocks and then does the two hashes on
// the stack, which makes TokenAt allocation-free. That is not micro-optimism:
// the table calls TokenAt twice for every datagram that opens — once to erase
// the consumed token, once to publish the new one at the high edge — and
// `hmac.New` allocates eight objects per call. Left as it was, every packet
// from every real client would have put sixteen allocations on the gateway's
// hot path, and a full window's precomputation would have cost four thousand.
//
// DeriveToken remains as the obvious implementation, and a test requires the
// two to agree over a long run of counters, so the fast path cannot drift from
// the construction core actually uses.
type KeyedSource struct {
	// mu makes KeyedSource honour the TokenSource concurrency contract: TokenAt
	// reads the pads and Wipe zeroes them, so they must not race. The read lock
	// is the cheap end of a RW lock and adds no allocation to the hot path.
	mu   sync.RWMutex
	ipad [blockSize]byte
	opad [blockSize]byte
}

// NewKeyedSource copies the key, so the caller may zero its own copy.
func NewKeyedSource(key *[core.KeySize]byte) *KeyedSource {
	s := &KeyedSource{}
	// The demux key must fit in one SHA-256 block. HMAC's "hash the key if it
	// is too long" branch is therefore unreachable here; keyedSourceKeyFitsHMACBlock
	// is the compile-time assertion that keeps that true.
	var padded [blockSize]byte
	copy(padded[:], key[:])
	for i := 0; i < blockSize; i++ {
		s.ipad[i] = padded[i] ^ 0x36
		s.opad[i] = padded[i] ^ 0x5c
	}
	return s
}

// Wipe zeroises the HMAC pads derived from the demux key. The tokens this
// source already published are on the wire and are not secrets; the key
// that names the rest of the epoch is.
func (s *KeyedSource) Wipe() {
	if s == nil {
		return
	}
	s.mu.Lock()
	s.ipad = [blockSize]byte{}
	s.opad = [blockSize]byte{}
	s.mu.Unlock()
}

// TokenAt implements TokenSource. It allocates nothing.
func (s *KeyedSource) TokenAt(counter uint64) Token {
	s.mu.RLock()
	var inner [blockSize + len(labelDemux) + 8]byte
	copy(inner[:blockSize], s.ipad[:])
	copy(inner[blockSize:], labelDemux)
	binary.BigEndian.PutUint64(inner[blockSize+len(labelDemux):], counter)
	ih := sha256.Sum256(inner[:])

	var outer [blockSize + sha256.Size]byte
	copy(outer[:blockSize], s.opad[:])
	copy(outer[blockSize:], ih[:])
	oh := sha256.Sum256(outer[:])
	s.mu.RUnlock()

	var t Token
	copy(t[:], oh[:core.DemuxTokenSize])
	return t
}

// Opener is the crypto half of a session, as the table needs it.
//
// *core.Session satisfies this. The table deliberately depends on nothing else:
// it routes, and the session decides. In particular the table never learns
// whether an opened message was data, padding or a rekey — that is the session
// driver's business.
type Opener interface {
	// Open authenticates and decrypts one whole transport message, demux token
	// included. It must return an error, and must not mutate its own state, for
	// any message it does not accept.
	Open(msg []byte) ([]byte, error)
}

// OpenerAt is Opener widened by the one thing the table already knows and Open
// makes the session work out again: the counter.
//
// Resolving a token to (session, counter) is the entire job of the index above,
// and until this interface existed the table threw the counter half of that
// answer away. core.Session then rediscovered it from a private per-session map
// holding the same forward window — 37.5 bytes per token, measured, against one
// byte per counter for the replay filter that actually needs to be there. At
// ten thousand sessions the duplicate was 352 MiB.
//
// An Opener that also implements OpenerAt is driven through OpenAt, and its
// session may then be configured with core.CallerOwnsTokenWindow so that the
// duplicate window is never built. *core.Session satisfies both interfaces in
// either configuration, so the choice is the session config's, not the table's,
// and the table cannot get it wrong in the dangerous direction: a session whose
// index is caller-owned is never asked to look a token up it no longer has.
//
// # What the counter is, and what the table must never do with it
//
// The counter is a hint about WHERE TO LOOK. It is not a claim that the message
// is genuine, and an implementation is entitled to treat it as adversarial: the
// AEAD alone accepts or rejects, and a message that fails to open must consume
// nothing.
//
// The table therefore does NOT re-derive the token from the counter and compare
// it with the token on the wire before calling OpenAt. That check would cost an
// HMAC on the hot path and prove nothing the AEAD is not already proving, and —
// the reason it is forbidden rather than merely wasteful — it would make a
// non-AEAD equality test part of an accept decision, which is the named non-goal
// in core/doc.go. TestTheTableDerivesNoTokenToDecideAnAccept pins its absence.
type OpenerAt interface {
	// OpenAt authenticates and decrypts one whole transport message, demux token
	// included, whose counter the caller has already resolved. It must return an
	// error, and must not mutate its own state, for any message it does not
	// accept — including a message offered at a counter that is not the one that
	// produced it, which is what an index collision hands it.
	OpenAt(msg []byte, counter uint64) ([]byte, error)
}
