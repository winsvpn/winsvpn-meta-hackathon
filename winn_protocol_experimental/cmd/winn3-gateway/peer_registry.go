package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

// peerRegistry is the control-plane-issued binding between an authenticated
// Winn3 client static key and the one inner IPv4 address that key may use.
// The file is deliberately public material only. It contains no private key,
// admission secret, account number, device id, or customer metadata. The one
// policy word an entry may carry, tier, is a service class (free or premium)
// bound to the authenticated key, not an identity: the hub decides it from its
// own account state and the gateway learns nothing more about the customer.
//
// The hub replaces the file atomically. Active forwarding checks for updates
// once per second and checks expiration on every packet in both directions.
// A new handshake always requests a fresh snapshot.
//
// # Why the freshness clock is an atomic and not a field under refreshMu
//
// innerForPeer is on the per-packet path in BOTH directions. The uplink calls
// it from gatewayForwardDevice.WritePacket once per inner packet, and the
// downlink calls it from forwardTable.lookup once per inner packet, on all of
// sharedGatewayTun's queue goroutines at once. The shape this replaced took
// refreshMu, an EXCLUSIVE mutex, before it even read the clock. At a gigabit,
// which is 91,041 packets per second per direction at this plan floor's
// 1373-byte inner MTU, that put roughly 182,000 exclusive acquisitions per
// second through one lock and collapsed the kernel's multi-queue tun back into
// one serialized path.
//
// checkDue and failed are written under refreshMu together with lastCheck and
// refreshErr, and read with no lock at all, so the steady state costs two
// atomic loads and one RWMutex read lock. The once-per-second os.Stat still
// happens, still under refreshMu, and still exactly once per interval.
type peerRegistry struct {
	path     string
	prefix   netip.Prefix
	reserved map[netip.Addr]struct{}

	mu       sync.RWMutex
	byKey    map[[32]byte]peerBinding
	freeMbps int
	budgets  map[[32]byte]*peerBandwidth
	byAddr   map[netip.Addr][32]byte
	notAfter map[[32]byte]int64

	refreshMu  sync.Mutex
	lastCheck  time.Time
	lastFile   os.FileInfo
	refreshErr error

	// checkDue mirrors lastCheck.Add(registryFreshness) as one atomic word and
	// failed mirrors refreshErr != nil. Both are published by
	// markCheckedLocked, which every path that writes lastCheck or refreshErr
	// must end in, or the datapath reads a clock that has stopped.
	checkDue atomic.Int64
	failed   atomic.Bool

	// admit, when set, is consulted by authorize after the registry check: it
	// reports whether the key may open one more session on this gateway (the
	// per-key session cap, cmd/winn3-gateway session_reclaim.go). It runs
	// inside core.ReadInitiation, under the handshaking driver's lock, so it
	// must take no lock that is ever held while a driver lock is taken.
	admit func(peer []byte) bool
}

// registryFreshness is how long a published snapshot may answer lookups before
// one of them owes the file a stat. It is the interval the type doc names.
const registryFreshness = time.Second

// markCheckedLocked republishes the freshness clock and the failure flag. The
// caller holds refreshMu.
func (r *peerRegistry) markCheckedLocked() {
	r.lastCheck = time.Now()
	r.checkDue.Store(r.lastCheck.Add(registryFreshness).UnixNano())
	r.failed.Store(r.refreshErr != nil)
}

// forceRefreshDue makes the next lookup pay for a freshness stat. It is the
// supported way to say "pretend the interval has elapsed": the datapath no
// longer reads lastCheck, so writing that field alone does nothing.
func (r *peerRegistry) forceRefreshDue() {
	r.refreshMu.Lock()
	r.lastCheck = time.Time{}
	r.refreshMu.Unlock()
	r.checkDue.Store(0)
}

type peerRegistryDocument struct {
	Version int                 `json:"version"`
	Peers   []peerRegistryEntry `json:"peers"`
}

type peerBinding struct {
	addr      netip.Addr
	bandwidth *peerBandwidth
}

type peerRegistryEntry struct {
	Tier         json.RawMessage `json:"tier,omitempty"`
	StaticPublic string          `json:"static_public"`
	InnerV4      string          `json:"inner_v4"`
	NotAfter     *int64          `json:"not_after"`
}

var errPeerNotAuthorized = errors.New("winn3 gateway peer is not authorized")

// errPeerSessionCap is authorize's refusal for a key that already holds
// maxSessionsPerKey live sessions. Silent toward the peer, like every other
// handshake refusal.
var errPeerSessionCap = errors.New("winn3 gateway peer already holds the per-key session cap")

func newPeerRegistry(path string, prefix netip.Prefix, reserved ...netip.Addr) (*peerRegistry, error) {
	return newPeerRegistryWithRate(path, prefix, 100, reserved...)
}

func newPeerRegistryWithRate(path string, prefix netip.Prefix, mbps int, reserved ...netip.Addr) (*peerRegistry, error) {
	if mbps < 0 || mbps > 100000 {
		return nil, errors.New("free Mbps must be in 0..100000")
	}
	r := &peerRegistry{path: path, prefix: prefix.Masked(), freeMbps: mbps, reserved: make(map[netip.Addr]struct{})}
	for _, addr := range reserved {
		if addr.IsValid() {
			r.reserved[addr] = struct{}{}
		}
	}
	if err := r.reload(); err != nil {
		return nil, err
	}
	return r, nil
}

// reloadIfChanged re-parses the file only when the stat identity the last
// successful load recorded no longer matches. authorize calls it instead
// of reload: authorize runs on every handshake that passes the admission
// tag, so an unconditional re-parse made each such handshake pay a full
// open, decode and index rebuild of the whole registry (measured 204_us
// and 363_KiB of allocation for a 253-entry, 32_KiB registry on a fast
// arm64 host) for an answer the published snapshot already holds. The hub
// replaces the file atomically by rename, so a replacement always changes
// the inode and is never missed; the identity compared here is the same
// one refresh already trusts for the per-packet path (SameFile, size,
// mtime, mode).
func (r *peerRegistry) reloadIfChanged() error {
	r.refreshMu.Lock()
	defer r.refreshMu.Unlock()
	info, err := os.Stat(r.path)
	if err == nil && r.refreshErr == nil && r.lastFile != nil &&
		os.SameFile(info, r.lastFile) && info.Size() == r.lastFile.Size() &&
		info.ModTime().Equal(r.lastFile.ModTime()) && info.Mode() == r.lastFile.Mode() {
		r.markCheckedLocked()
		return nil
	}
	if err == nil {
		err = r.reloadLocked()
	}
	r.finishRefreshLocked(err)
	return err
}

// reload parses a complete replacement before publishing either index. A
// malformed update therefore cannot partially authorize a peer or split the
// key and address views.
func (r *peerRegistry) reload() error {
	r.refreshMu.Lock()
	defer r.refreshMu.Unlock()
	err := r.reloadLocked()
	r.finishRefreshLocked(err)
	return err
}

func (r *peerRegistry) refresh() error {
	// Lock-free fast path. A snapshot inside its interval that was published by
	// a successful reload answers every packet with two atomic loads and no
	// mutex at all.
	if time.Now().UnixNano() < r.checkDue.Load() && !r.failed.Load() {
		return nil
	}
	r.refreshMu.Lock()
	defer r.refreshMu.Unlock()
	// Re-check under the lock. Many goroutines can lose the race above and
	// arrive together, and only the first of them owes a stat.
	if !r.lastCheck.IsZero() && time.Since(r.lastCheck) < registryFreshness {
		return r.refreshErr
	}
	info, err := os.Stat(r.path)
	if err == nil && r.refreshErr == nil && r.lastFile != nil &&
		os.SameFile(info, r.lastFile) && info.Size() == r.lastFile.Size() &&
		info.ModTime().Equal(r.lastFile.ModTime()) && info.Mode() == r.lastFile.Mode() {
		r.markCheckedLocked()
		return nil
	}
	if err == nil {
		err = r.reloadLocked()
	}
	r.finishRefreshLocked(err)
	return err
}

// The caller holds refreshMu. Clear all indexes on failure so a lookup that
// just passed refresh cannot use stale bindings after another refresh fails.
func (r *peerRegistry) finishRefreshLocked(err error) {
	r.refreshErr = err
	if err != nil {
		r.mu.Lock()
		r.byKey = nil
		r.byAddr = nil
		r.notAfter = nil
		r.mu.Unlock()
		r.lastFile = nil
	}
	r.markCheckedLocked()
}

// The caller holds refreshMu, so concurrent handshakes cannot publish an
// older snapshot after a newer one. Only complete snapshots are published.
func (r *peerRegistry) reloadLocked() error {
	file, err := os.Open(r.path)
	if err != nil {
		return fmt.Errorf("opening peer registry: %w", err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return fmt.Errorf("stat peer registry: %w", err)
	}
	const maximumRegistryBytes = 1024 * 1024
	if !info.Mode().IsRegular() || info.Size() > maximumRegistryBytes {
		return errors.New("peer registry is not a bounded regular file")
	}
	raw, err := io.ReadAll(io.LimitReader(file, maximumRegistryBytes+1))
	if err != nil {
		return fmt.Errorf("reading peer registry: %w", err)
	}
	if len(raw) > maximumRegistryBytes {
		return errors.New("peer registry exceeds the size limit")
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var doc peerRegistryDocument
	if err := dec.Decode(&doc); err != nil {
		return fmt.Errorf("decoding peer registry: %w", err)
	}
	var trailing any
	if err := dec.Decode(&trailing); !errors.Is(err, io.EOF) {
		return errors.New("decoding peer registry: trailing JSON value")
	}
	if doc.Version != 1 {
		return fmt.Errorf("peer registry version is %d, want 1", doc.Version)
	}
	byKey := make(map[[32]byte]peerBinding, len(doc.Peers))
	budgets := make(map[[32]byte]*peerBandwidth)
	byAddr := make(map[netip.Addr][32]byte, len(doc.Peers))
	notAfter := make(map[[32]byte]int64, len(doc.Peers))
	for i, entry := range doc.Peers {
		// The optional per-entry entitlement class. An omitted word means
		// premium, so a document the hub wrote before this field existed is
		// read exactly as it always was. Anything but free or premium
		// refuses the whole snapshot exactly as a malformed key does, and a
		// JSON null is refused rather than read as an omitted word (the raw
		// form is decoded by hand to tell the two apart).
		tier := ""
		if len(entry.Tier) > 0 {
			if bytes.Equal(entry.Tier, []byte("null")) {
				return fmt.Errorf("peer registry entry %d has a null tier", i)
			}
			if err := json.Unmarshal(entry.Tier, &tier); err != nil {
				return fmt.Errorf("peer registry entry %d has a malformed tier", i)
			}
			if tier != "free" && tier != "premium" {
				return fmt.Errorf("peer registry entry %d has a tier that is neither free nor premium", i)
			}
		}
		if entry.NotAfter == nil || *entry.NotAfter < 0 {
			return fmt.Errorf("peer registry entry %d has an invalid not_after", i)
		}
		if *entry.NotAfter != 0 && time.Now().Unix() >= *entry.NotAfter {
			continue
		}
		rawKey, err := base64.StdEncoding.Strict().DecodeString(entry.StaticPublic)
		if err != nil || len(rawKey) != 32 {
			return fmt.Errorf("peer registry entry %d has an invalid 32-byte base64 static_public", i)
		}
		var key [32]byte
		copy(key[:], rawKey)
		addr, err := netip.ParseAddr(entry.InnerV4)
		if err != nil || !addr.Is4() || addr.String() != entry.InnerV4 {
			return fmt.Errorf("peer registry entry %d has an invalid canonical inner_v4", i)
		}
		if !r.prefix.Contains(addr) || addr == r.prefix.Addr() || addr == lastAddrInPrefix(r.prefix) {
			return fmt.Errorf("peer registry entry %d inner_v4 %s is not a usable host in %s", i, addr, r.prefix)
		}
		if _, reserved := r.reserved[addr]; reserved {
			return fmt.Errorf("peer registry entry %d inner_v4 %s is reserved by the gateway", i, addr)
		}
		if _, exists := byKey[key]; exists {
			return fmt.Errorf("peer registry entry %d duplicates static_public", i)
		}
		if _, exists := byAddr[addr]; exists {
			return fmt.Errorf("peer registry entry %d duplicates inner_v4 %s", i, addr)
		}
		var budget *peerBandwidth
		if tier == "free" && r.freeMbps != 0 {
			budget = r.budgets[key]
			if budget == nil {
				budget = newPeerBandwidth(r.freeMbps)
			}
			budgets[key] = budget
		}
		byKey[key] = peerBinding{addr: addr, bandwidth: budget}
		byAddr[addr] = key
		notAfter[key] = *entry.NotAfter
	}
	r.mu.Lock()
	r.budgets = budgets
	r.byKey = byKey
	r.byAddr = byAddr
	r.notAfter = notAfter
	r.mu.Unlock()
	r.lastFile = info
	return nil
}

// authorize is the core handshake authorization callback. Reloading here makes
// atomic hub updates visible to the next handshake without granting the service
// write access to its registry. The reload is stat-gated (reloadIfChanged):
// an atomically replaced file is parsed before the decision, and an
// unchanged file costs one stat instead of a full re-parse per handshake.
func (r *peerRegistry) authorize(peer []byte) error {
	if err := r.reloadIfChanged(); err != nil {
		fmt.Fprintln(os.Stderr, "winn3-gateway: peer registry reload failed")
		return err
	}
	if _, ok := r.innerForPeer(peer); !ok {
		r.mu.RLock()
		loaded := len(r.byKey)
		r.mu.RUnlock()
		return fmt.Errorf("%w: %s holds %d bindings", errPeerNotAuthorized, r.path, loaded)
	}
	if r.admit != nil && !r.admit(peer) {
		return errPeerSessionCap
	}
	return nil
}

func (r *peerRegistry) innerForPeer(peer []byte) (netip.Addr, bool) {
	binding, ok := r.policyForPeer(peer)
	return binding.addr, ok
}

func (r *peerRegistry) policyForPeer(peer []byte) (peerBinding, bool) {
	if len(peer) != 32 {
		return peerBinding{}, false
	}
	if time.Now().UnixNano() >= r.checkDue.Load() || r.failed.Load() {
		if r.refresh() != nil {
			return peerBinding{}, false
		}
	}
	var candidate [32]byte
	copy(candidate[:], peer)
	r.mu.RLock()
	defer r.mu.RUnlock()
	binding, allowed := r.byKey[candidate]
	if !allowed {
		return peerBinding{}, false
	}
	expires, present := r.notAfter[candidate]
	if !present || (expires != 0 && time.Now().Unix() >= expires) {
		return peerBinding{}, false
	}
	return binding, true
}
