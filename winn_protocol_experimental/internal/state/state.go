package state

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"winsvpn.local/winnprotocol/internal/pqauth"
	"winsvpn.local/winnprotocol/internal/protocol"
	"winsvpn.local/winnprotocol/internal/securefile"
)

const (
	stateVersion      = 2
	envelopeFormat    = "winn-state-aes256gcm/v2"
	requestRetention  = 24 * time.Hour
	minimumKeyTTL     = time.Minute
	stateAssociatedAD = "winn-protocol-controller-state/v2"
)

var (
	ErrRevoked            = errors.New("device is revoked")
	ErrReplayConflict     = errors.New("request ID replay conflict")
	ErrGenerationConflict = errors.New("generation conflict")
	ErrRotationPending    = errors.New("another rotation is pending")
)

type GenerationError struct {
	Current uint64
}

func (e *GenerationError) Error() string {
	return fmt.Sprintf("%s: controller generation is %d", ErrGenerationConflict, e.Current)
}

func (e *GenerationError) Unwrap() error {
	return ErrGenerationConflict
}

type PendingError struct {
	RequestID string
}

func (e *PendingError) Error() string {
	return fmt.Sprintf("%s: request %s", ErrRotationPending, e.RequestID)
}

func (e *PendingError) Unwrap() error {
	return ErrRotationPending
}

type Store struct {
	mu            sync.Mutex
	leaseMu       sync.Mutex
	leases        map[[32]byte]*fileTunnelLease
	path          string
	key           [32]byte
	ttl           time.Duration
	now           func() time.Time
	random        io.Reader
	state         diskState
	controllerID  string
	signer        *pqauth.Signer
	lock          *fileLock
	closed        bool
	closedState   atomic.Bool
	reconcileHook func()
	releaseVerify func(*fileTunnelLease) error
}

type diskState struct {
	Version        int                      `json:"version"`
	Peers          map[string]peerRecord    `json:"peers"`
	Requests       map[string]requestRecord `json:"requests"`
	RevokedDevices map[string]bool          `json:"revoked_devices"`
}

type peerRecord struct {
	DeviceID       string `json:"device_id"`
	PeerPublicKey  string `json:"peer_public_key"`
	Suite          string `json:"suite"`
	Generation     uint64 `json:"generation"`
	KeyID          string `json:"key_id"`
	PresharedKey   string `json:"preshared_key"`
	IssuedAt       string `json:"issued_at"`
	ExpiresAt      string `json:"expires_at"`
	PendingRequest string `json:"pending_request,omitempty"`
}

type requestRecord struct {
	DeviceID  string                 `json:"device_id"`
	Digest    string                 `json:"digest"`
	Response  protocol.RekeyResponse `json:"response"`
	CreatedAt string                 `json:"created_at"`
	Committed bool                   `json:"committed"`
}

type envelope struct {
	Format     string `json:"format"`
	Nonce      string `json:"nonce"`
	Ciphertext string `json:"ciphertext"`
}

type Prepared struct {
	Response   protocol.RekeyResponse
	PSK        []byte
	Idempotent bool
	Committed  bool
}

type Controller interface {
	Prepare(context.Context, protocol.RekeyRequest) (Prepared, error)
	Commit(context.Context, string) error
	Close() error
}

// TunnelLease is an opaque, request-scoped ownership proof. Its value is
// intentionally not serializable and must never be logged.
type TunnelLease interface {
	Validate(context.Context) error
}

type CommitDisposition uint8

const (
	CommitIndeterminate CommitDisposition = iota
	CommitUncommitted
	CommitCommitted
)

type CommitSnapshot struct {
	Disposition   CommitDisposition
	Response      protocol.RekeyResponse
	PSK           []byte
	RequestDigest [32]byte
	SnapshotHash  [32]byte
}

type TunnelTransaction interface {
	Lease() TunnelLease
	Prepare(context.Context, protocol.RekeyRequest) (Prepared, error)
	Commit(context.Context, string) error
	ReconcileCommitOutcome(context.Context, protocol.RekeyRequest) (CommitSnapshot, error)
	Release(context.Context) error
}

type TunnelTransactionSource interface {
	BeginTunnelTransaction(context.Context, string, string) (TunnelTransaction, error)
}

var ErrReconciliationRequired = errors.New("controller reconciliation required")

type fileTunnelLease struct {
	store  *Store
	digest [32]byte
	token  [32]byte
	state  uint8
}

type fileTunnelTransaction struct {
	lease         *fileTunnelLease
	request       *protocol.RekeyRequest
	requestDigest [32]byte
	phase         uint8
	reconciles    uint8
	busy          atomic.Bool
}

const (
	tunnelPhaseNew uint8 = iota
	tunnelPhasePrepareAttempted
	tunnelPhasePrepared
	tunnelPhaseCommitAttempted
	tunnelPhaseInvalid
	tunnelPhaseReleased
	tunnelPhasePoisoned
)

type AdministrativeController interface {
	Controller
	Revoke(context.Context, string) error
	AbortPending(context.Context, string, string, string) error
	Snapshot(context.Context) (Snapshot, error)
}

type Snapshot struct {
	Peers          []PeerSnapshot `json:"peers"`
	RevokedDevices []string       `json:"revoked_devices"`
}

type PeerSnapshot struct {
	DeviceID       string `json:"device_id"`
	PeerPublicKey  string `json:"peer_public_key"`
	Suite          string `json:"suite"`
	Generation     uint64 `json:"generation"`
	KeyID          string `json:"key_id"`
	ExpiresAt      string `json:"expires_at"`
	PendingRequest string `json:"pending_request,omitempty"`
}

func Open(path, keyPath string, ttl time.Duration, controllerID string, signer *pqauth.Signer) (*Store, error) {
	return openFileStore(path, keyPath, ttl, controllerID, signer, false)
}

func OpenAdministrative(path, keyPath string, ttl time.Duration, controllerID string) (*Store, error) {
	return openFileStore(path, keyPath, ttl, controllerID, nil, true)
}

func openFileStore(
	path string,
	keyPath string,
	ttl time.Duration,
	controllerID string,
	signer *pqauth.Signer,
	administrativeOnly bool,
) (*Store, error) {
	if ttl < minimumKeyTTL || ttl > protocol.MaxKeyLifetime {
		return nil, fmt.Errorf("key TTL must be between %s and %s", minimumKeyTTL, protocol.MaxKeyLifetime)
	}
	if !protocol.ValidDeviceID(controllerID) {
		return nil, errors.New("invalid controller ID")
	}
	if signer == nil && !administrativeOnly {
		return nil, errors.New("controller PQ response signer is required")
	}
	keyData, err := securefile.ReadPrivateLimited(keyPath, 1024)
	if err != nil {
		return nil, fmt.Errorf("read state key: %w", err)
	}
	defer clear(keyData)
	if len(keyData) != 32 {
		return nil, fmt.Errorf("state key length is %d, want 32", len(keyData))
	}
	store := &Store{
		path:         path,
		ttl:          ttl,
		now:          time.Now,
		random:       rand.Reader,
		state:        newDiskState(),
		controllerID: controllerID,
		signer:       signer,
		leases:       make(map[[32]byte]*fileTunnelLease),
	}
	copy(store.key[:], keyData)
	lock, err := acquireFileLock(path + ".lock")
	if err != nil {
		clear(store.key[:])
		return nil, fmt.Errorf("lock controller state: %w", err)
	}
	store.lock = lock
	if err := store.load(); err != nil {
		_ = store.lock.release()
		clear(store.key[:])
		return nil, err
	}
	return store, nil
}

func tunnelDigest(controllerID, deviceID, peerPublicKey string) [32]byte {
	h := sha256.New()
	_, _ = h.Write([]byte("winn-rekey-tunnel-lease/v1"))
	_, _ = h.Write([]byte{0})
	_, _ = h.Write([]byte(controllerID))
	_, _ = h.Write([]byte{0})
	_, _ = h.Write([]byte(deviceID))
	_, _ = h.Write([]byte{0})
	_, _ = h.Write([]byte(peerPublicKey))
	var result [32]byte
	copy(result[:], h.Sum(nil))
	return result
}

func (s *Store) BeginTunnelTransaction(
	ctx context.Context,
	deviceID string,
	peerPublicKey string,
) (TunnelTransaction, error) {
	if ctx == nil {
		return nil, errors.New("tunnel transaction context is required")
	}
	if !protocol.ValidDeviceID(deviceID) {
		return nil, errors.New("invalid device ID")
	}
	if err := protocol.ValidatePeerPublicKey(peerPublicKey); err != nil {
		return nil, err
	}
	digest := tunnelDigest(s.controllerID, deviceID, peerPublicKey)
	for {
		if cause := context.Cause(ctx); cause != nil {
			return nil, cause
		}
		s.leaseMu.Lock()
		if s.closedState.Load() {
			s.leaseMu.Unlock()
			return nil, errors.New("controller state is closed")
		}
		current := s.leases[digest]
		if current == nil {
			lease := &fileTunnelLease{store: s, digest: digest}
			if _, err := io.ReadFull(rand.Reader, lease.token[:]); err != nil {
				s.leaseMu.Unlock()
				return nil, fmt.Errorf("generate tunnel lease token: %w", err)
			}
			lease.state = 1
			s.leases[digest] = lease
			s.leaseMu.Unlock()
			return &fileTunnelTransaction{lease: lease}, nil
		}
		if current.state == 2 {
			s.leaseMu.Unlock()
			return nil, ErrReconciliationRequired
		}
		s.leaseMu.Unlock()
		timer := time.NewTimer(5 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil, context.Cause(ctx)
		case <-timer.C:
		}
	}
}

func (l *fileTunnelLease) Validate(ctx context.Context) error {
	if ctx == nil || context.Cause(ctx) != nil {
		if ctx == nil {
			return errors.New("lease context is required")
		}
		return context.Cause(ctx)
	}
	l.store.leaseMu.Lock()
	defer l.store.leaseMu.Unlock()
	if l.state != 1 || l.store.leases[l.digest] != l {
		return ErrReconciliationRequired
	}
	return nil
}

func (t *fileTunnelTransaction) Lease() TunnelLease { return t.lease }

func (t *fileTunnelTransaction) enter(ctx context.Context) error {
	if !t.busy.CompareAndSwap(false, true) {
		return errors.New("concurrent tunnel transaction use")
	}
	if err := t.lease.Validate(ctx); err != nil {
		t.busy.Store(false)
		return err
	}
	return nil
}

func (t *fileTunnelTransaction) leave() { t.busy.Store(false) }

func (t *fileTunnelTransaction) Prepare(
	ctx context.Context,
	req protocol.RekeyRequest,
) (Prepared, error) {
	if err := t.enter(ctx); err != nil {
		return Prepared{}, err
	}
	defer t.leave()
	if t.phase != tunnelPhaseNew || t.request != nil {
		t.phase = tunnelPhaseInvalid
		return Prepared{}, errors.New("repeated or invalid tunnel Prepare transition")
	}
	if tunnelDigest(req.ControllerID, req.DeviceID, req.PeerPublicKey) != t.lease.digest {
		t.phase = tunnelPhaseInvalid
		return Prepared{}, errors.New("request is not bound to tunnel transaction")
	}
	requestDigest, err := protocol.RequestDigest(req)
	if err != nil {
		t.phase = tunnelPhaseInvalid
		return Prepared{}, err
	}
	t.phase = tunnelPhasePrepareAttempted
	prepared, err := t.lease.store.Prepare(ctx, req)
	if err == nil {
		copyReq := req
		t.request = &copyReq
		t.requestDigest = requestDigest
		if validateErr := t.lease.Validate(ctx); validateErr != nil {
			return Prepared{}, validateErr
		}
		t.phase = tunnelPhasePrepared
	}
	return prepared, err
}

func (t *fileTunnelTransaction) Commit(ctx context.Context, requestID string) error {
	if err := t.enter(ctx); err != nil {
		return err
	}
	defer t.leave()
	if t.phase != tunnelPhasePrepared || t.request == nil ||
		t.request.RequestID != requestID {
		t.phase = tunnelPhaseInvalid
		return errors.New("commit request is not bound to tunnel transaction")
	}
	t.phase = tunnelPhaseCommitAttempted
	err := t.lease.store.Commit(ctx, requestID)
	if validateErr := t.lease.Validate(ctx); validateErr != nil {
		return validateErr
	}
	return err
}

func (t *fileTunnelTransaction) ReconcileCommitOutcome(
	ctx context.Context,
	req protocol.RekeyRequest,
) (CommitSnapshot, error) {
	if err := t.enter(ctx); err != nil {
		return CommitSnapshot{}, err
	}
	defer t.leave()
	requestDigest, digestErr := protocol.RequestDigest(req)
	if t.phase != tunnelPhaseCommitAttempted || t.reconciles >= 2 ||
		digestErr != nil || t.request == nil ||
		t.request.RequestID != req.RequestID ||
		requestDigest != t.requestDigest ||
		tunnelDigest(req.ControllerID, req.DeviceID, req.PeerPublicKey) != t.lease.digest {
		t.phase = tunnelPhaseInvalid
		return CommitSnapshot{}, errors.New("reconciliation request is not bound to transaction")
	}
	t.reconciles++
	snapshot, err := t.lease.store.reconcileFileLocked(ctx, req, t.lease)
	if validateErr := t.lease.Validate(ctx); validateErr != nil {
		clear(snapshot.PSK)
		return CommitSnapshot{}, validateErr
	}
	return snapshot, err
}

func (t *fileTunnelTransaction) Release(ctx context.Context) error {
	if !t.busy.CompareAndSwap(false, true) {
		return errors.New("concurrent tunnel transaction use")
	}
	defer t.busy.Store(false)
	if t.phase == tunnelPhaseReleased || t.phase == tunnelPhasePoisoned {
		return errors.New("repeated tunnel release")
	}
	s := t.lease.store
	s.leaseMu.Lock()
	defer s.leaseMu.Unlock()
	releaseErr := error(nil)
	if s.releaseVerify != nil {
		releaseErr = s.releaseVerify(t.lease)
	}
	if ctx == nil || context.Cause(ctx) != nil || releaseErr != nil ||
		t.lease.state != 1 || s.leases[t.lease.digest] != t.lease {
		t.lease.state = 2
		t.phase = tunnelPhasePoisoned
		s.leases[t.lease.digest] = t.lease
		return ErrReconciliationRequired
	}
	delete(s.leases, t.lease.digest)
	t.lease.state = 3
	t.phase = tunnelPhaseReleased
	clear(t.lease.token[:])
	return nil
}

func (s *Store) Prepare(_ context.Context, req protocol.RekeyRequest) (Prepared, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return Prepared{}, errors.New("controller state is closed")
	}
	if s.signer == nil {
		return Prepared{}, errors.New("administrative controller state cannot prepare rotations")
	}
	if err := protocol.ValidateRequest(req); err != nil {
		return Prepared{}, fmt.Errorf("invalid rekey request: %w", err)
	}
	if s.state.RevokedDevices[req.DeviceID] {
		return Prepared{}, ErrRevoked
	}
	if req.ControllerID != s.controllerID {
		return Prepared{}, errors.New("request is for a different controller")
	}
	if req.AuthAlgorithm != s.signer.Algorithm() {
		return Prepared{}, errors.New("request suite requires a different controller PQ signer")
	}
	digest, err := protocol.RequestDigest(req)
	if err != nil {
		return Prepared{}, err
	}
	digestHex := hex.EncodeToString(digest[:])
	if existing, ok := s.state.Requests[req.RequestID]; ok {
		if existing.DeviceID != req.DeviceID || existing.Digest != digestHex {
			return Prepared{}, ErrReplayConflict
		}
		psk, err := decodePSK(existing.Response.PresharedKey)
		if err != nil {
			return Prepared{}, fmt.Errorf("stored response is corrupt: %w", err)
		}
		return Prepared{
			Response:   existing.Response,
			PSK:        psk,
			Idempotent: true,
			Committed:  existing.Committed,
		}, nil
	}

	peerKey := peerMapKey(req.DeviceID, req.PeerPublicKey)
	peer := s.state.Peers[peerKey]
	if peer.PendingRequest != "" {
		return Prepared{}, &PendingError{RequestID: peer.PendingRequest}
	}
	if req.CurrentGeneration != peer.Generation {
		return Prepared{}, &GenerationError{Current: peer.Generation}
	}
	if req.CurrentGeneration >= protocol.MaxGeneration {
		return Prepared{}, errors.New("generation exhausted")
	}

	psk := make([]byte, 32)
	if _, err := io.ReadFull(s.random, psk); err != nil {
		return Prepared{}, fmt.Errorf("generate AWG PSK: %w", err)
	}
	var nonzero byte
	for _, value := range psk {
		nonzero |= value
	}
	if nonzero == 0 {
		clear(psk)
		return Prepared{}, errors.New("random source returned an invalid all-zero PSK")
	}
	now := s.now().UTC()
	generation := peer.Generation + 1
	response := protocol.RekeyResponse{
		Version:       protocol.Version,
		Suite:         req.Suite,
		ControllerID:  s.controllerID,
		DeviceID:      req.DeviceID,
		PeerPublicKey: req.PeerPublicKey,
		RequestID:     req.RequestID,
		Nonce:         req.Nonce,
		Generation:    generation,
		KeyID:         protocol.KeyID(s.controllerID, req.Suite, req.DeviceID, req.PeerPublicKey, generation, psk),
		PresharedKey:  base64.StdEncoding.EncodeToString(psk),
		IssuedAt:      now.Format(time.RFC3339Nano),
		ExpiresAt:     now.Add(s.ttl).Format(time.RFC3339Nano),
		Capabilities:  protocol.RequiredCapabilities(req.Suite),
	}
	if err := pqauth.SignResponse(&response, s.signer); err != nil {
		clear(psk)
		return Prepared{}, fmt.Errorf("sign response with controller ML-DSA key: %w", err)
	}
	next := cloneDiskState(s.state)
	next.Requests[req.RequestID] = requestRecord{
		DeviceID:  req.DeviceID,
		Digest:    digestHex,
		Response:  response,
		CreatedAt: now.Format(time.RFC3339Nano),
	}
	peer.DeviceID = req.DeviceID
	peer.PeerPublicKey = req.PeerPublicKey
	peer.PendingRequest = req.RequestID
	next.Peers[peerKey] = peer
	pruneRequests(next, now)
	if err := s.saveLocked(next); err != nil {
		clear(psk)
		return Prepared{}, err
	}
	s.state = next
	return Prepared{Response: response, PSK: psk}, nil
}

func (s *Store) Commit(_ context.Context, requestID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return errors.New("controller state is closed")
	}
	record, ok := s.state.Requests[requestID]
	if !ok {
		return errors.New("unknown request ID")
	}
	if record.Committed {
		return nil
	}
	peerKey := peerMapKey(record.Response.DeviceID, record.Response.PeerPublicKey)
	next := cloneDiskState(s.state)
	peer := next.Peers[peerKey]
	if peer.PendingRequest != requestID {
		return errors.New("pending request binding mismatch")
	}
	peer.Suite = record.Response.Suite
	peer.Generation = record.Response.Generation
	peer.KeyID = record.Response.KeyID
	peer.PresharedKey = record.Response.PresharedKey
	peer.IssuedAt = record.Response.IssuedAt
	peer.ExpiresAt = record.Response.ExpiresAt
	peer.PendingRequest = ""
	next.Peers[peerKey] = peer
	record.Committed = true
	next.Requests[requestID] = record
	if err := s.saveLocked(next); err != nil {
		return err
	}
	s.state = next
	return nil
}

func (s *Store) Revoke(_ context.Context, deviceID string) error {
	if !protocol.ValidDeviceID(deviceID) {
		return errors.New("invalid device ID")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return errors.New("controller state is closed")
	}
	next := cloneDiskState(s.state)
	next.RevokedDevices[deviceID] = true
	if err := s.saveLocked(next); err != nil {
		return err
	}
	s.state = next
	return nil
}

func (s *Store) AbortPending(_ context.Context, deviceID, peerPublicKey, requestID string) error {
	if !protocol.ValidDeviceID(deviceID) {
		return errors.New("invalid device ID")
	}
	if err := protocol.ValidatePeerPublicKey(peerPublicKey); err != nil {
		return err
	}
	if requestID == "" {
		return errors.New("request ID is required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return errors.New("controller state is closed")
	}
	peerKey := peerMapKey(deviceID, peerPublicKey)
	peer, ok := s.state.Peers[peerKey]
	if !ok || peer.PendingRequest == "" {
		return errors.New("peer has no pending rotation")
	}
	if peer.PendingRequest != requestID {
		return errors.New("pending request binding mismatch")
	}
	next := cloneDiskState(s.state)
	peer.PendingRequest = ""
	next.Peers[peerKey] = peer
	delete(next.Requests, requestID)
	if err := s.saveLocked(next); err != nil {
		return err
	}
	s.state = next
	return nil
}

func (s *Store) Snapshot(_ context.Context) (Snapshot, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return Snapshot{}, errors.New("controller state is closed")
	}
	result := Snapshot{}
	for _, peer := range s.state.Peers {
		result.Peers = append(result.Peers, PeerSnapshot{
			DeviceID:       peer.DeviceID,
			PeerPublicKey:  peer.PeerPublicKey,
			Suite:          peer.Suite,
			Generation:     peer.Generation,
			KeyID:          peer.KeyID,
			ExpiresAt:      peer.ExpiresAt,
			PendingRequest: peer.PendingRequest,
		})
	}
	for deviceID, revoked := range s.state.RevokedDevices {
		if revoked {
			result.RevokedDevices = append(result.RevokedDevices, deviceID)
		}
	}
	return result, nil
}

func (s *Store) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	s.closedState.Store(true)
	s.leaseMu.Lock()
	for _, lease := range s.leases {
		lease.state = 2
	}
	s.leaseMu.Unlock()
	clear(s.key[:])
	if s.lock == nil {
		return nil
	}
	err := s.lock.release()
	s.lock = nil
	return err
}

func (s *Store) load() error {
	encrypted, err := securefile.ReadPrivateLimited(s.path, 128<<20)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("read encrypted state: %w", err)
	}
	decoded, err := s.decodeState(encrypted)
	if err != nil {
		return err
	}
	s.state = decoded
	return nil
}

func (s *Store) decodeState(encrypted []byte) (diskState, error) {
	var container envelope
	decoder := json.NewDecoder(bytes.NewReader(encrypted))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&container); err != nil {
		return diskState{}, fmt.Errorf("decode state envelope: %w", err)
	}
	if err := requireJSONEOF(decoder); err != nil {
		return diskState{}, fmt.Errorf("decode state envelope: %w", err)
	}
	if container.Format != envelopeFormat {
		return diskState{}, fmt.Errorf("unsupported state envelope %q", container.Format)
	}
	nonce, err := base64.StdEncoding.Strict().DecodeString(container.Nonce)
	if err != nil {
		return diskState{}, fmt.Errorf("decode state nonce: %w", err)
	}
	ciphertext, err := base64.StdEncoding.Strict().DecodeString(container.Ciphertext)
	if err != nil {
		return diskState{}, fmt.Errorf("decode state ciphertext: %w", err)
	}
	aead, err := s.aead()
	if err != nil {
		return diskState{}, err
	}
	if len(nonce) != aead.NonceSize() {
		return diskState{}, errors.New("invalid state nonce length")
	}
	plaintext, err := aead.Open(nil, nonce, ciphertext, []byte(stateAssociatedAD))
	if err != nil {
		return diskState{}, errors.New("decrypt controller state: authentication failed")
	}
	defer clear(plaintext)
	var decoded diskState
	stateDecoder := json.NewDecoder(bytes.NewReader(plaintext))
	stateDecoder.DisallowUnknownFields()
	if err := stateDecoder.Decode(&decoded); err != nil {
		return diskState{}, fmt.Errorf("decode controller state: %w", err)
	}
	if err := requireJSONEOF(stateDecoder); err != nil {
		return diskState{}, fmt.Errorf("decode controller state: %w", err)
	}
	if decoded.Version != stateVersion {
		return diskState{}, fmt.Errorf("unsupported controller state version %d", decoded.Version)
	}
	if decoded.Peers == nil || decoded.Requests == nil || decoded.RevokedDevices == nil {
		return diskState{}, errors.New("controller state has missing maps")
	}
	return decoded, nil
}

func (s *Store) reconcileFileLocked(
	ctx context.Context,
	req protocol.RekeyRequest,
	lease *fileTunnelLease,
) (CommitSnapshot, error) {
	if cause := context.Cause(ctx); cause != nil {
		return CommitSnapshot{}, cause
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return CommitSnapshot{}, errors.New("controller state is closed")
	}
	if err := lease.Validate(ctx); err != nil {
		return CommitSnapshot{}, err
	}
	file, encrypted, openedIdentity, err := securefile.OpenPrivateLimited(
		s.path, 128<<20,
	)
	if err != nil {
		return CommitSnapshot{}, fmt.Errorf("read authoritative state: %w", err)
	}
	closed := false
	defer func() {
		if !closed {
			_ = file.Close()
		}
	}()
	decoded, err := s.decodeState(encrypted)
	clear(encrypted)
	if err != nil {
		return CommitSnapshot{}, err
	}
	if s.reconcileHook != nil {
		s.reconcileHook()
	}
	record, ok := decoded.Requests[req.RequestID]
	if !ok || record.DeviceID != req.DeviceID {
		return CommitSnapshot{}, errors.New("authoritative request binding is missing")
	}
	digest, err := protocol.RequestDigest(req)
	if err != nil || record.Digest != hex.EncodeToString(digest[:]) {
		return CommitSnapshot{}, errors.New("authoritative request digest mismatch")
	}
	psk, err := decodePSK(record.Response.PresharedKey)
	if err != nil {
		return CommitSnapshot{}, err
	}
	peer := decoded.Peers[peerMapKey(req.DeviceID, req.PeerPublicKey)]
	disposition := CommitIndeterminate
	if record.Committed &&
		peer.PendingRequest == "" &&
		peer.Generation == record.Response.Generation &&
		peer.KeyID == record.Response.KeyID &&
		peer.PresharedKey == record.Response.PresharedKey {
		disposition = CommitCommitted
	} else if !record.Committed &&
		peer.PendingRequest == req.RequestID &&
		peer.Generation == req.CurrentGeneration {
		disposition = CommitUncommitted
	} else {
		clear(psk)
		return CommitSnapshot{}, errors.New("authoritative state relation is indeterminate")
	}
	if err := file.Sync(); err != nil {
		clear(psk)
		return CommitSnapshot{}, fmt.Errorf("sync authoritative state descriptor: %w", err)
	}
	descriptorAfter, err := file.Stat()
	if err != nil || !os.SameFile(openedIdentity, descriptorAfter) {
		clear(psk)
		return CommitSnapshot{}, errors.New("opened state descriptor identity changed during reconciliation")
	}
	pathAfter, err := os.Lstat(s.path)
	if err != nil || !pathAfter.Mode().IsRegular() ||
		pathAfter.Mode()&os.ModeSymlink != 0 ||
		!os.SameFile(openedIdentity, pathAfter) {
		clear(psk)
		return CommitSnapshot{}, errors.New("state file identity changed during reconciliation")
	}
	if err := securefile.SyncParent(s.path); err != nil {
		clear(psk)
		return CommitSnapshot{}, err
	}
	pathFinal, err := os.Lstat(s.path)
	if err != nil || !os.SameFile(openedIdentity, pathFinal) {
		clear(psk)
		return CommitSnapshot{}, errors.New("state file identity changed after directory sync")
	}
	if err := lease.Validate(ctx); err != nil {
		clear(psk)
		return CommitSnapshot{}, err
	}
	if err := file.Close(); err != nil {
		clear(psk)
		return CommitSnapshot{}, fmt.Errorf("close authoritative state descriptor: %w", err)
	}
	closed = true
	s.state = decoded
	snapshotBytes, err := json.Marshal(struct {
		Record requestRecord
		Peer   peerRecord
	}{record, peer})
	if err != nil {
		clear(psk)
		return CommitSnapshot{}, err
	}
	snapshotHash := sha256.Sum256(snapshotBytes)
	clear(snapshotBytes)
	return CommitSnapshot{
		Disposition:   disposition,
		Response:      record.Response,
		PSK:           psk,
		RequestDigest: digest,
		SnapshotHash:  snapshotHash,
	}, nil
}

func (s *Store) saveLocked(next diskState) error {
	plaintext, err := json.Marshal(next)
	if err != nil {
		return err
	}
	defer clear(plaintext)
	aead, err := s.aead()
	if err != nil {
		return err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(s.random, nonce); err != nil {
		return err
	}
	ciphertext := aead.Seal(nil, nonce, plaintext, []byte(stateAssociatedAD))
	container := envelope{
		Format:     envelopeFormat,
		Nonce:      base64.StdEncoding.EncodeToString(nonce),
		Ciphertext: base64.StdEncoding.EncodeToString(ciphertext),
	}
	encoded, err := json.Marshal(container)
	if err != nil {
		return err
	}
	encoded = append(encoded, '\n')
	return securefile.AtomicWrite(s.path, encoded, 0o600)
}

func (s *Store) aead() (cipher.AEAD, error) {
	block, err := aes.NewCipher(s.key[:])
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func pruneRequests(next diskState, now time.Time) {
	for requestID, record := range next.Requests {
		if !record.Committed {
			continue
		}
		createdAt, err := time.Parse(time.RFC3339Nano, record.CreatedAt)
		if err == nil && now.Sub(createdAt) > requestRetention {
			delete(next.Requests, requestID)
		}
	}
}

func cloneDiskState(current diskState) diskState {
	next := newDiskState()
	for key, peer := range current.Peers {
		next.Peers[key] = peer
	}
	for key, request := range current.Requests {
		request.Response.Capabilities = append([]string(nil), request.Response.Capabilities...)
		next.Requests[key] = request
	}
	for deviceID, revoked := range current.RevokedDevices {
		next.RevokedDevices[deviceID] = revoked
	}
	return next
}

func newDiskState() diskState {
	return diskState{
		Version:        stateVersion,
		Peers:          make(map[string]peerRecord),
		Requests:       make(map[string]requestRecord),
		RevokedDevices: make(map[string]bool),
	}
}

func peerMapKey(deviceID, peerPublicKey string) string {
	digest := sha256.Sum256([]byte(deviceID + "\x00" + peerPublicKey))
	return hex.EncodeToString(digest[:])
}

func decodePSK(value string) ([]byte, error) {
	psk, err := base64.StdEncoding.Strict().DecodeString(value)
	if err != nil || len(psk) != 32 {
		return nil, errors.New("invalid PSK encoding")
	}
	return psk, nil
}

func requireJSONEOF(decoder *json.Decoder) error {
	var extra any
	err := decoder.Decode(&extra)
	if errors.Is(err, io.EOF) {
		return nil
	}
	if err == nil {
		return errors.New("extra JSON value")
	}
	return err
}
