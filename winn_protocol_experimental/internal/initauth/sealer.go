package initauth

// The client half: a net.PacketConn decorator that authenticates every outgoing
// handshake initiation by writing the tag over the S1 prefix the AmneziaWG
// engine already filled with random bytes.
//
// # Why this is a PacketConn decorator and not a change to amneziawg-go
//
// Because of where the five platforms meet. ../../datapath/carrier.go records
// the rule: the HOST opens the transport socket, the host protects it
// (VpnService.protect on Android), and only then is it handed over — and the
// carrier, once given one, refuses to open another. Android, Linux and Windows
// reach this module as a subprocess through ../../datapath/duplex; iOS and
// macOS reach it through the C ABI in ../../cdatapath.
//
// So a decorator on the supplied socket is a single Go change that lands on all
// five platforms with no host work, no new entitlement, no new signing surface
// and no second socket to protect. Forking amneziawg-go instead would be five
// platform ports of the same idea, two of them into engines this repository
// does not build.
//
// # Why it never fails a connection
//
// A Sealer that cannot seal is not an error state. A legacy node configured
// with S1 = 0 has no room for an authenticator, and a client that refused to
// connect to it would be a self-inflicted outage across the fleet. NewSealer
// reports that case as ErrProfileCannotSeal and the caller is expected to use
// the bare socket — which is exactly today's behaviour and is indistinguishable
// on the wire from today's behaviour.
//
// The same reasoning runs the other way and is the reason this can ship first:
// a sealed prefix is uniform random bytes in a field nobody reads, so a sealing
// client talking to a gateway that is not checking behaves identically to a
// non-sealing one. Client-before-server is safe here. It was not safe for the
// firewall gate, where the server had to move first.

import (
	"fmt"
	"net"
	"sync"
	"time"
)

// SealerConfig constructs a Sealer.
type SealerConfig struct {
	// Key is the shared secret. Only one: a client seals with the current key
	// and a gate verifies against several, which is what makes a rotation
	// overlap rather than a cliff.
	Key []byte

	// Profile must match the AmneziaWG obfuscation configuration this client
	// was served. A mismatch is not detectable on the wire — it presents as a
	// handshake that never completes — so it must come from the same served
	// configuration that produced the engine's own s1/h1 arguments.
	Profile Profile

	Options Options

	// Now is injectable for tests. Nil means time.Now.
	Now func() time.Time
}

// Sealer decorates a net.PacketConn. It is safe for concurrent use.
type Sealer struct {
	net.PacketConn

	key     []byte
	profile Profile
	opts    Options
	now     func() time.Time

	mu     sync.Mutex
	buf    []byte
	sealed uint64
	passed uint64
	failed uint64
}

// SealerStats are local diagnostics. They are never sent anywhere.
//
// They exist because of a real gap recorded in
// docs/handoff/SPA_ALTERNATIVE_INITIATION_ASSESSMENT_20260805.md §6.2: a gate
// that never answers means the server cannot tell a client anything, so the
// client must tell itself. Sealed == 0 on a connection that will not come up is
// the difference between "the authenticator is not being applied" and every
// other reason a tunnel fails.
type SealerStats struct {
	// Sealed counts initiations that were authenticated on the way out.
	Sealed uint64

	// Passed counts datagrams forwarded untouched — junk, transport data,
	// everything that is not an initiation.
	Passed uint64

	// Failed counts initiations that were shaped correctly but could not be
	// sealed. This should be zero; a nonzero value means the configuration
	// changed underneath a live Sealer.
	Failed uint64
}

// NewSealer wraps inner.
//
// It returns an error wrapping ErrProfileCannotSeal when the profile leaves no
// room for an authenticator. Callers MUST treat that as "seal disabled" and use
// the bare socket. They must not treat it as a connection failure.
func NewSealer(inner net.PacketConn, cfg SealerConfig) (*Sealer, error) {
	if inner == nil {
		return nil, fmt.Errorf("winn initauth: a packet conn is required")
	}
	if err := cfg.Profile.Validate(); err != nil {
		return nil, err
	}
	if err := checkKeys([][]byte{cfg.Key}); err != nil {
		return nil, err
	}
	if _, _, err := cfg.Options.resolve(); err != nil {
		return nil, err
	}
	now := cfg.Now
	if now == nil {
		now = time.Now
	}
	return &Sealer{
		PacketConn: inner,
		key:        append([]byte(nil), cfg.Key...),
		profile:    cfg.Profile,
		opts:       cfg.Options,
		now:        now,
		buf:        make([]byte, cfg.Profile.InitiationSize()),
	}, nil
}

// Stats reads the local diagnostics.
func (s *Sealer) Stats() SealerStats {
	s.mu.Lock()
	defer s.mu.Unlock()
	return SealerStats{Sealed: s.sealed, Passed: s.passed, Failed: s.failed}
}

// WriteTo seals a handshake initiation and forwards everything else untouched.
//
// The caller's buffer is never modified. AmneziaWG reuses its send buffers, and
// sealing in place would rewrite bytes the engine may still be holding — an
// aliasing bug that would present as an intermittent handshake failure, which is
// the hardest possible thing to diagnose through a gate that never answers.
//
// The datagram's LENGTH is unchanged, which is the whole point: an observer
// counting bytes or matching sizes sees the same 164-byte initiation it saw
// before, at the same moment, on the same flow.
func (s *Sealer) WriteTo(p []byte, addr net.Addr) (int, error) {
	if !s.profile.IsInitiationShaped(p) {
		s.mu.Lock()
		s.passed++
		s.mu.Unlock()
		return s.PacketConn.WriteTo(p, addr)
	}

	s.mu.Lock()
	if len(s.buf) != len(p) {
		s.buf = make([]byte, len(p))
	}
	copy(s.buf, p)
	err := Seal(s.buf, s.key, s.profile, s.now(), s.opts)
	if err != nil {
		s.failed++
		s.mu.Unlock()
		// Fail open, and loudly in the local counter. An unsealed initiation
		// reaches a gate in observe mode unharmed and a gate in require mode
		// not at all; a dropped initiation reaches nobody either way. There is
		// no configuration in which refusing to send is the better of the two.
		return s.PacketConn.WriteTo(p, addr)
	}
	out := make([]byte, len(s.buf))
	copy(out, s.buf)
	s.sealed++
	s.mu.Unlock()

	n, werr := s.PacketConn.WriteTo(out, addr)
	if n > len(p) {
		n = len(p)
	}
	return n, werr
}

// SealDatagram authenticates one initiation in a caller-owned buffer, for hosts
// that do not route their datagrams through a net.PacketConn — a relay that
// owns its own buffers, or a test rig.
//
// It returns ErrNotAnInitiation for anything that is not initiation-shaped, so
// the caller can send it unchanged.
func (s *Sealer) SealDatagram(datagram []byte) error {
	return Seal(datagram, s.key, s.profile, s.now(), s.opts)
}
