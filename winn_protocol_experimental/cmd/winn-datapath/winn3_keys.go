package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"winsvpn.local/winnprotocol/internal/securefile"
	"winsvpn.local/winnprotocol/winn3/core"
	"winsvpn.local/winnprotocol/winn3/dualsign"
	"winsvpn.local/winnprotocol/winn3/hostqueue"
	"winsvpn.local/winnprotocol/winn3/session"
)

// winn3KeyDocumentMaxBytes bounds the -winn3-keys JSON document. Paths and
// scalars only; a legitimate document is a few hundred bytes.
const winn3KeyDocumentMaxBytes = 64 << 10

// winn3KeyFileMaxBytes bounds every private file named by the key document,
// including hex-encoded dual-auth public keys (ML-DSA-65 hex is 3904 bytes).
const winn3KeyFileMaxBytes = 8 << 10

// The winn/3 key document, named by -winn3-keys.
//
// # Why this is a PATH and not part of the Create frame
//
// This is the one document in the -winn3 seam that reaches trust. Everything in
// the Create frame is a runtime parameter the host is entitled to choose; this
// names the device's static private key, the gateway's static public key and the
// admission secret. datapath/carrier.go already records the rule for the winn/1
// carrier profile — an authenticated configuration has no business crossing a
// channel whose payload is peer-supplied by construction — and key material is
// strictly worse than a carrier configuration.
//
// A path is different in kind: this process opens the file itself, under its own
// uid, and the decision about what to trust is made here rather than asserted by
// whoever wrote the frame.
//
// IT CONTAINS NO KEY MATERIAL, only paths. That is the rule LinuxWinnCarrierProfile
// and winn3Profile already follow, and it is what keeps a host that forwards a
// document from ever holding a key.
//
// # Why it is not winn3Profile
//
// winn3Profile is the DESKTOP document: it also carries the dialled carrier, the
// inner assignment, the device backend and the migration plan, because in that
// mode there is no Create frame and the profile is the whole configuration. In
// frame mode every one of those fields comes from the host at create time, and
// a profile that carried them too would be a second opinion about the same
// facts. Two documents that must always agree are two documents that eventually
// will not.
//
// So this document holds exactly what must not cross the frame, and nothing
// else.

// winn3KeysVersion is the only version this build accepts.
const winn3KeysVersion = "winn3-keys/1"

var errWinn3Keys = errors.New("winn3 key document")

func winn3RefuseKeys(format string, args ...any) error {
	return fmt.Errorf("%w: %s", errWinn3Keys, fmt.Sprintf(format, args...))
}

// winn3Keys is the document -winn3-keys names.
type winn3Keys struct {
	Version string `json:"version"`

	// Role is "client" or "gateway". A host is always the client; the gateway
	// value exists so this binary can serve the lab's responding half without a
	// second command, which is what the loopback end-to-end proof needs.
	Role string `json:"role"`

	// GatewayID binds the admission tag to one gateway, so an initiation
	// captured at gateway A cannot be replayed at gateway B while both are
	// mid-rotation on a shared admission key. Authenticated, never transmitted.
	GatewayID string `json:"gateway_id"`

	// StaticPath is this end's static X25519 private key: 32 raw bytes, or 64
	// hex characters with an optional trailing newline.
	StaticPath string `json:"static_path"`

	// GatewayStaticPath is the gateway's static X25519 public key, same two
	// encodings. Client only.
	GatewayStaticPath string `json:"gateway_static_path"`

	// DualAuthEd25519PubPath and DualAuthMLDSA65PubPath name the files holding
	// the gateway's dual-signature attestation public keys (hex). Both must be
	// set together; both empty means a legacy session that carries no
	// attestation (docs/DUAL_SIGNATURE_SPEC.md).
	DualAuthEd25519PubPath string `json:"dual_auth_ed25519_pub_path"`
	DualAuthMLDSA65PubPath string `json:"dual_auth_mldsa65_pub_path"`

	// AdmissionPath names the file holding the gateway's admission secret.
	//
	// ONE field although the secret is used twice — as the admission key the
	// initiation's tag is derived from, and as the key the encrypted length
	// layer of a stream carrier is derived from. They are the same secret, and
	// two fields that must always hold the same value are two fields that will
	// eventually not.
	AdmissionPath string `json:"admission_path"`

	// OuterSocketExclusion is the host's own description of the exclusion it
	// installed. It is NOT parsed and NOT acted on; it is required to be
	// non-empty before a create document may set allow_own_socket, so that a
	// host cannot claim it without having written down what it did, and it is
	// echoed in the status document so the claim sits next to the counters.
	//
	// It is empty for the normal mobile case, where the host protects the
	// socket and hands the descriptor over instead.
	OuterSocketExclusion string `json:"outer_socket_exclusion"`

	// FastPQ allows DATA under epoch-0 keys. False is StrictPQ and is the
	// default: harvest-now-decrypt-later is a live threat for this user
	// population, so the round trip is worth it.
	FastPQ bool `json:"fast_pq"`

	// RekeyAfterMessages lowers the send-volume rekey trigger. Zero means
	// core.RekeyAfterMessages.
	//
	// It is a MONOTONE knob: a value above the protocol default is refused, so
	// this document can make the ratchet turn more often and can never make it
	// turn less often. A knob that could be raised would be a way to weaken
	// forward secrecy from a configuration file, which is not a trade an
	// operator should be able to make by editing JSON — and a knob that can only
	// tighten is one an end-to-end test can use to walk a real session across a
	// real ratchet in seconds instead of after 2^28 messages.
	RekeyAfterMessages uint64 `json:"rekey_after_messages"`
}

// winn3ClientTokenWindow is the client's gateway-to-client receive token window
// W. It bounds the run of consecutive lost gateway messages a session survives:
// at most W-1 on a clean stream or after an old loss, but only W/2-1 when an
// earlier message was lost recently (the low edge stays pinned at it). At the
// 1024 default a burst of about 7 to 15 ms at 700 Mbps stranded the receive
// direction permanently (measured 2026-09-22). At the maximum, 65536, that is
// 32767 to 65535 messages, about 0.5 to 1 s at that rate, for about 2.4 MB and
// 65536 PRF evaluations per epoch install (6.8 ms on an M5 Max). It is
// receiver-local; nothing on the wire changes.
const winn3ClientTokenWindow = core.MaxTokenWindow

// loadWinn3Keys reads and validates the document at path.
func loadWinn3Keys(path string) (winn3Keys, error) {
	raw, err := securefile.ReadPrivateLimited(path, winn3KeyDocumentMaxBytes)
	if err != nil {
		return winn3Keys{}, fmt.Errorf("read winn3 key document: %w", err)
	}
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.DisallowUnknownFields()
	var keys winn3Keys
	if err := decoder.Decode(&keys); err != nil {
		return winn3Keys{}, fmt.Errorf(
			"decode winn3 key document %q: %w", path, err)
	}
	if err := keys.validate(); err != nil {
		return winn3Keys{}, err
	}
	return keys, nil
}

func (k winn3Keys) validate() error {
	if k.Version != winn3KeysVersion {
		return winn3RefuseKeys("version is %q, this build speaks %q",
			k.Version, winn3KeysVersion)
	}
	if k.Role != winn3RoleClient && k.Role != winn3RoleGateway {
		return winn3RefuseKeys("role is %q; use %q or %q",
			k.Role, winn3RoleClient, winn3RoleGateway)
	}
	edPath := strings.TrimSpace(k.DualAuthEd25519PubPath)
	mlPath := strings.TrimSpace(k.DualAuthMLDSA65PubPath)
	if (edPath == "") != (mlPath == "") {
		return winn3RefuseKeys(
			"dual_auth_ed25519_pub_path and dual_auth_mldsa65_pub_path must be set together")
	}
	if strings.TrimSpace(k.GatewayID) == "" {
		return winn3RefuseKeys(
			"gateway_id is empty: without it an initiation captured at one " +
				"gateway replays at another that shares the admission key")
	}
	if strings.TrimSpace(k.StaticPath) == "" {
		return winn3RefuseKeys("static_path is empty")
	}
	if strings.TrimSpace(k.AdmissionPath) == "" {
		return winn3RefuseKeys("admission_path is empty")
	}
	if k.RekeyAfterMessages > core.RekeyAfterMessages {
		return winn3RefuseKeys(
			"rekey_after_messages is %d and the protocol default is %d: this "+
				"field may only make the ratchet turn MORE often. Raising it "+
				"would weaken forward secrecy from a configuration file",
			k.RekeyAfterMessages, core.RekeyAfterMessages)
	}
	switch k.Role {
	case winn3RoleClient:
		if strings.TrimSpace(k.GatewayStaticPath) == "" {
			return winn3RefuseKeys(
				"gateway_static_path is empty: a client authenticates the " +
					"gateway by its static key and there is no anonymous mode")
		}
	case winn3RoleGateway:
		if strings.TrimSpace(k.GatewayStaticPath) != "" {
			return winn3RefuseKeys(
				"gateway_static_path is set on a gateway; it is the client's field")
		}
	}
	return nil
}

// exclusionDeclared reports whether allow_own_socket may be honoured.
func (k winn3Keys) exclusionDeclared() bool {
	return strings.TrimSpace(k.OuterSocketExclusion) != ""
}

// winn3KeyMaterial is the contents of every file a winn3Keys document names,
// read once per tunnel generation and validated.
//
// # Why a frame host reads the files exactly once
//
// The Android host's custody contract (WinnV3Keys.destroy, run right after
// CreateAck) is that the engine "has acknowledged Create and loaded them into
// its private process memory": every file this document names is then
// truncated to a zero-length tombstone. A round built after the first that went
// back to the paths therefore read 0 bytes and ended the tunnel terminally
// (measured on an S26, 2026-09-23: "static_path: 0 bytes; expected 32 raw bytes
// or 64 hex characters" on the first post-promotion rebuild). The material is
// the recovery copy the host was promised; every round still builds its own
// session.Config, key objects and slices from it, so no round inherits a
// session, a key object or an attestation from the one that died.
//
// # Ownership and what clearing means
//
// Every buffer this process allocates to hold a byte of the files, raw or
// decoded, is recorded in owned at the moment it is acquired, as its FULL
// allocation (a TrimRight view would otherwise leave the tail of the
// allocation behind). wipe zeroes all of them. The frame host holds exactly one
// material per tunnel generation and wipes it once no successor round can be
// built: on Stop (before the bounded wait for the supervisor), on the
// supervisor's end, and on every refusal in open.
//
// This is BEST-EFFORT clearing of identified application-owned buffers. It is
// not a guarantee that no copy exists anywhere in the process:
//
//   - crypto/ecdh keeps its own copy of the static scalar inside the
//     *ecdh.PrivateKey for as long as the round's session lives, and the
//     garbage collector frees, but does not zero, that object afterwards;
//   - the securefile reader's own intermediate buffers, the Go runtime's
//     stack and heap moves, and the kernel's page cache are outside this
//     process's reach;
//   - abrupt process death (SIGKILL, the Android low-memory killer, a crash)
//     runs no cleanup at all. The pages are returned to the kernel, which
//     zeroes them before reuse by another process. A replacement engine cannot
//     inherit this memory, and the host's tombstones hold nothing, so a
//     restarted engine needs fresh provisioning from the host.
type winn3KeyMaterial struct {
	owned winn3OwnedSecrets

	// Views into owned. Nil after wipe.
	static        []byte
	gatewayStatic []byte // client only
	admission     []byte
	// dualAuthED25519 and dualAuthMLDSA65 are both nil for a legacy session
	// that carries no attestation, and both set otherwise. They are public
	// keys, owned and cleared only for uniformity.
	dualAuthED25519 []byte
	dualAuthMLDSA65 []byte
}

// winn3SecretAcquiredHook, when set, is told of every buffer a
// winn3OwnedSecrets takes ownership of, with the field it holds. Tests only:
// it is how a test keeps a reference to a buffer this code allocated and later
// checks it was zeroed. Nil in every production path.
var winn3SecretAcquiredHook func(field string, buffer []byte)

// winn3OwnedSecrets is a set of application-owned buffers that one owner
// clears. The zero value is empty and ready to use.
type winn3OwnedSecrets struct {
	buffers [][]byte
}

// own records b's whole allocation and returns b unchanged.
func (o *winn3OwnedSecrets) own(field string, b []byte) []byte {
	if b == nil {
		return nil
	}
	full := b[:cap(b)]
	o.buffers = append(o.buffers, full)
	if winn3SecretAcquiredHook != nil {
		winn3SecretAcquiredHook(field, full)
	}
	return b
}

// clearAll zeroes every owned buffer and forgets them. Idempotent.
func (o *winn3OwnedSecrets) clearAll() {
	for _, b := range o.buffers {
		clear(b)
	}
	o.buffers = nil
}

// wipe zeroes the material. Idempotent.
func (m *winn3KeyMaterial) wipe() {
	m.owned.clearAll()
	*m = winn3KeyMaterial{}
}

// errWinn3KeyMaterialReleased refuses a round asked for after the tunnel
// generation's key material was wiped.
var errWinn3KeyMaterialReleased = errors.New(
	"winn3 key material was released: this tunnel builds no further round")

// readMaterial reads and validates every file the document names. It refuses
// in the same order and with the same messages sessionConfig always has, and
// on any refusal it clears every buffer it had already acquired.
func (k winn3Keys) readMaterial() (m winn3KeyMaterial, err error) {
	defer func() {
		if err != nil {
			m.wipe()
		}
	}()
	staticRaw, err := readPrivateKeyFile(k.StaticPath, "static_path")
	if err != nil {
		return m, err
	}
	m.owned.own("static_path", staticRaw)
	static, err := hostqueue.DecodeKeyBytes(staticRaw, "static_path")
	if err != nil {
		return m, err
	}
	m.static = m.owned.own("static_path", static)
	if _, err := core.NewStaticKey(m.static); err != nil {
		return m, fmt.Errorf("static_path: %w", err)
	}
	admission, err := readPrivateKeyFile(k.AdmissionPath, "admission_path")
	if err != nil {
		return m, err
	}
	m.owned.own("admission_path", admission)
	m.admission = bytes.TrimRight(admission, "\r\n")
	if k.Role != winn3RoleClient {
		return m, nil
	}
	gatewayRaw, err := readPrivateKeyFile(k.GatewayStaticPath, "gateway_static_path")
	if err != nil {
		return m, err
	}
	m.owned.own("gateway_static_path", gatewayRaw)
	gateway, err := hostqueue.DecodeKeyBytes(gatewayRaw, "gateway_static_path")
	if err != nil {
		return m, err
	}
	m.gatewayStatic = m.owned.own("gateway_static_path", gateway)
	if _, err := core.NewPublicKey(m.gatewayStatic); err != nil {
		return m, fmt.Errorf("gateway_static_path: %w", err)
	}
	// hostqueue.ApplyDualAuthPublics's rules, with the raw buffers owned.
	edPath := strings.TrimSpace(k.DualAuthEd25519PubPath)
	mlPath := strings.TrimSpace(k.DualAuthMLDSA65PubPath)
	if (edPath == "") != (mlPath == "") {
		return m, fmt.Errorf(
			"dual_auth_ed25519_pub_path and dual_auth_mldsa65_pub_path must be set together")
	}
	if edPath == "" {
		return m, nil
	}
	for _, pub := range []struct {
		path, field string
		size        int
		into        *[]byte
	}{
		{edPath, "dual_auth_ed25519_pub_path", dualsign.Ed25519PublicKeySize, &m.dualAuthED25519},
		{mlPath, "dual_auth_mldsa65_pub_path", dualsign.MLDSA65PublicKeySize, &m.dualAuthMLDSA65},
	} {
		raw, err := readPrivateKeyFile(pub.path, pub.field)
		if err != nil {
			return m, err
		}
		m.owned.own(pub.field, raw)
		decoded, err := hostqueue.DecodeDualAuthPublic(raw, pub.size, pub.field)
		if err != nil {
			return m, err
		}
		*pub.into = m.owned.own(pub.field, decoded)
	}
	return m, nil
}

// sessionConfig assembles the session configuration and returns the admission
// secret alongside it, because a stream carrier's length layer needs the same
// bytes and reading the file twice is a second chance to read a different file.
//
// The material it reads is temporary and is cleared before it returns; the
// configuration and the admission slice it returns are independent copies the
// caller owns.
func (k winn3Keys) sessionConfig() (session.Config, []byte, error) {
	m, err := k.readMaterial()
	if err != nil {
		return session.Config{}, nil, err
	}
	defer m.wipe()
	cfg, admission, _, err := k.sessionConfigFrom(&m)
	return cfg, admission, err
}

// sessionConfigFrom builds a fresh session configuration from material read
// earlier. Every secret slice it hands the session is a copy recorded in the
// returned winn3OwnedSecrets, which the caller owns: a frame round clears it
// when the round closes, and any failure here has already cleared it. The copy
// of the static scalar is cleared before returning, because
// ecdh.NewPrivateKey keeps its own.
func (k winn3Keys) sessionConfigFrom(m *winn3KeyMaterial) (
	cfg session.Config, admission []byte, secrets winn3OwnedSecrets, err error,
) {
	defer func() {
		if err != nil {
			secrets.clearAll()
			cfg, admission = session.Config{}, nil
		}
	}()
	if m.static == nil {
		return cfg, nil, secrets, errWinn3KeyMaterialReleased
	}
	staticCopy := secrets.own("round:static_path", bytes.Clone(m.static))
	staticKey, err := core.NewStaticKey(staticCopy)
	clear(staticCopy)
	if err != nil {
		return cfg, nil, secrets, fmt.Errorf("static_path: %w", err)
	}
	admission = secrets.own("round:admission_path", bytes.Clone(m.admission))

	cfg = session.Config{
		Core: core.Config{
			Gateway: core.GatewayParams{
				AdmissionKeys: [][]byte{admission},
				GatewayID:     []byte(k.GatewayID),
			},
		},
		Static: staticKey,
		// PadBucket is the design's default and PadNone is the zero value, so
		// leaving this unset would silently ship the unshaped one.
		Padding: core.PadBucket,
		FastPQ:  k.FastPQ,
		// Zero here means session.Config fills it from core.RekeyAfterMessages,
		// so the default path is untouched.
		RekeyAfterMessages: k.RekeyAfterMessages,
		SendQueue:          65536,
	}
	switch k.Role {
	case winn3RoleClient:
		cfg.Core.TokenWindow = winn3ClientTokenWindow
		gatewayStatic, err := core.NewPublicKey(bytes.Clone(m.gatewayStatic))
		if err != nil {
			return cfg, nil, secrets, fmt.Errorf("gateway_static_path: %w", err)
		}
		cfg.GatewayStatic = gatewayStatic
		if (m.dualAuthED25519 == nil) != (m.dualAuthMLDSA65 == nil) {
			return cfg, nil, secrets, winn3RefuseKeys(
				"dual_auth_ed25519_pub_path and dual_auth_mldsa65_pub_path must be set together")
		}
		if m.dualAuthED25519 != nil {
			cfg.DualAuth = session.DualAuthConfig{
				Expected: true,
				Ed25519Public: secrets.own("round:dual_auth_ed25519_pub_path",
					bytes.Clone(m.dualAuthED25519)),
				MLDSA65Public: secrets.own("round:dual_auth_mldsa65_pub_path",
					bytes.Clone(m.dualAuthMLDSA65)),
			}
		}
	case winn3RoleGateway:
		// The core refuses a responder with no Accept, deliberately, because
		// "authenticated" and "authorised" are different questions. This role
		// exists to serve the lab's responding half, so the honest thing is an
		// admit-all that says so rather than a stub that looks like policy.
		cfg.Accept = func([]byte) error { return nil }
	}
	return cfg, admission, secrets, nil
}

// describeForLog renders the document with no path and no secret in it.
func (k winn3Keys) describeForLog() string {
	var b strings.Builder
	b.WriteString("winn3 keys version=")
	b.WriteString(k.Version)
	b.WriteString(" role=")
	b.WriteString(k.Role)
	fmt.Fprintf(&b, " exclusion_declared=%t fast_pq=%t rekey_lowered=%t",
		k.exclusionDeclared(), k.FastPQ, k.RekeyAfterMessages != 0)
	return b.String()
}

func readPrivateKeyFile(path, field string) ([]byte, error) {
	return hostqueue.ReadPrivateKeyFile(path, field)
}

func applyDualAuthPublics(cfg *session.Config, edPath, mlPath string) error {
	return hostqueue.ApplyDualAuthPublics(cfg, edPath, mlPath)
}

func readDualAuthPublic(path string, want int, field string) ([]byte, error) {
	return hostqueue.ReadDualAuthPublic(path, want, field)
}

// winn3ReadKeyFile reads a 32-byte X25519 key in either accepted encoding.
//
// Raw or hex, because the two provisioning paths in this tree disagree and
// making the host convert would put key material through a shell.
func winn3ReadKeyFile(path, field string) ([]byte, error) {
	return hostqueue.ReadKeyFile(path, field)
}
