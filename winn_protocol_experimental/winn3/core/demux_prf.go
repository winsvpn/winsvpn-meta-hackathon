package core

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"hash"
)

// demuxPRF is confined to one existing direction lock. Its hash state is secret.
// Dropping it has the same GC erasure limitation as the existing AEAD objects.
type demuxPRF struct {
	mac   hash.Hash
	input [len(labelDemux) + 8]byte
	sum   [sha256.Size]byte
}

func newDemuxPRF(key *[KeySize]byte) *demuxPRF {
	p := &demuxPRF{mac: hmac.New(sha256.New, key[:])}
	copy(p.input[:], labelDemux)
	// HMAC Reset caches the SHA-256 ipad/opad states on this Go toolchain.
	p.mac.Reset()
	return p
}

func (p *demuxPRF) token(counter uint64) (out [DemuxTokenSize]byte) {
	binary.BigEndian.PutUint64(p.input[len(labelDemux):], counter)
	p.mac.Reset()
	_, _ = p.mac.Write(p.input[:])
	sum := p.mac.Sum(p.sum[:0])
	copy(out[:], sum[:DemuxTokenSize])
	return out
}
