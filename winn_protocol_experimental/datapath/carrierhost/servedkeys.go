package carrierhost

// Served carrier-profile keys: the ONE place the platform hosts get their key
// lists from.
//
// # Why this file exists
//
// Four hosts build the carrier profile document Profile describes, in four
// languages:
//
//	android/app/src/main/kotlin/org/winsvpn/app/WinnCarrierProfile.kt
//	apple/WinsTunnelCore/WinsWinnCarrierProfile.swift
//	lib/winn_protocol_dispatch.dart
//	linux/runner/linux_winn_host.cc
//
// Each one used to carry its own hand-typed copy of the key list. All four
// copies were correct and all four were identical, which is exactly why the
// drift was invisible when the spa_* fields were added to Profile: the fields
// existed in the schema, every host's allowlist silently excluded them, and a
// profile carrying single-packet-authorization parameters was stripped before
// it ever reached the engine. Nothing failed; the feature was simply
// unreachable from every platform at once.
//
// A shared list cannot be linked across Kotlin, Swift, Dart and C++, so it is
// GENERATED into each of them from the declarations below by
// cmd/winn-carrier-keys, and servedkeys_test.go fails if any generated file has
// drifted from this one. That is the cross-language form of the same guarantee
// WinsWinnSeamObservability.publishedStatusKeys already gives the two Swift
// host bridges: one author, many readers, and no way for a reader to fall
// behind unnoticed.
//
// # Served versus device-local
//
// Profile has two kinds of field and only one of them belongs here.
//
// SERVED fields are public transport parameters the control plane chooses and
// hands to the client in protocol_params: a URI template, an address, a suite
// name, identifiers, a digest, and the SPA freshness scalars. They travel over
// the wire and they carry no secret.
//
// DEVICE-LOCAL fields are paths. controller_pins_path, root_ca_path,
// ech_config_list_path, device_seed_path, client_cert_path, client_key_path and
// spa_key_path all name a file on the device, resolved by each host against its
// own private credential directory. A control plane must never be able to
// choose one: naming a path is naming which file the engine opens, and a served
// path would let whoever answered the config request point the engine at a file
// of their choosing. They are therefore deliberately absent from
// ServedProfileKeys, and servedkeys_test.go asserts that absence rather than
// leaving it to a reader to notice.
//
// spa_key_path is the one that most invites the mistake, because the SPA key is
// a deployment-scoped shared secret rather than a per-device identity, so it
// reads like configuration. It is not. It is a credential, it is referenced by
// path exactly like the other six, and neither it nor its contents may appear
// in a served config, in profile JSON as a value, or in any log line.

// SPAServedProfileKeys are the single-packet-authorization parameters a control
// plane may serve. They are ordered as they appear in Profile.
//
// spa_key_path is NOT here. See the note above.
//
// Every one of these is inert unless spa_mode is SPAModeRequired, and Profile
// REFUSES a document that sets any of them to a NON-EMPTY value without the
// mode (ErrSPAFieldWithoutMode). Every host therefore OMITS them entirely when
// SPA is off.
//
// Be exact about why, because the stronger claim is FALSE and was asserted here
// until it was probed against ParseProfile. normalizeSPA's stray sweep tests
// strings.TrimSpace(field) != "" for the strings and != 0 for the scalars, so
// "spa_mode": "off", "spa_target": "", "spa_key_path": "" and a zero
// spa_packet_size are indistinguishable from absent and all PARSE FINE. An
// emitter that wrote the keys empty would NOT break non-SPA carrier sessions.
// The two real reasons to omit are:
//
//  1. Omission is unambiguous. A document with no spa_ substring in it cannot
//     be misread, and a test can assert exactly that over the whole document
//     without having to model which empty values normalizeSPA forgives.
//  2. The failure that does exist is one-sided and easy to walk into. A
//     NON-EMPTY stray — the shape a half-finished migration, a copied config or
//     a "sensible default" actually produces — is a hard refusal of the whole
//     profile. A host that never writes these keys unless SPA is really on
//     cannot reach that state; a host that writes them unconditionally is one
//     non-empty default away from refusing every non-SPA session.
var SPAServedProfileKeys = []string{
	"spa_mode",
	"spa_target",
	"spa_packet_size",
	"spa_bucket_window_seconds",
	"spa_max_skew_seconds",
}

// ServedProfileKeys are every protocol_params / [winn] section key that
// describes a carrier profile, in Profile's own field order.
//
// The first eleven are the set every host carried before SPA existed, unchanged
// and in the same order, so a generated file can be diffed against the list it
// replaced. The last five are SPAServedProfileKeys.
var ServedProfileKeys = append([]string{
	"masque_template",
	"public_target",
	"server_name",
	"suite",
	"controller_id",
	"device_id",
	"device_pq_algorithm",
	"manifest_digest",
	"sequence_epoch",
	"max_inner_datagram",
	"privacy_profile",
}, SPAServedProfileKeys...)

// RequiredServedProfileKeys are the served keys with no safe default. A carrier
// session missing any of them is refused rather than started with a guess.
//
// No spa_* key is required, and that is the whole compatibility story for this
// change: a config that names none of them describes exactly the session it
// described before the fields existed. SPA is opt-in per served config, so
// adding the capability to a client cannot alter what any existing config does.
var RequiredServedProfileKeys = []string{
	"masque_template",
	"public_target",
	"server_name",
	"suite",
	"controller_id",
	"device_id",
	"device_pq_algorithm",
	"manifest_digest",
}

// DeviceLocalProfileKeys are the Profile fields that name a file on the device.
// A host fills each of these in itself; none may ever be served. Listed so
// servedkeys_test.go can assert the two sets are disjoint and that together
// they account for every credential-bearing field in Profile.
var DeviceLocalProfileKeys = []string{
	"controller_pins_path",
	"root_ca_path",
	"ech_config_list_path",
	"device_seed_path",
	"client_cert_path",
	"client_key_path",
	"spa_key_path",
}

// SPAKeyCredentialFileName is the name every host gives the SPA key file inside
// its own private credential directory, alongside the six that were already
// there (controller_pins.json, winn_root_ca.pem, ech_config_list.bin,
// device_mldsa_seed.bin, client_cert.pem, client_key.pem).
//
// One file name across every platform so provisioning tooling needs one name,
// which is the rule the existing six already follow.
//
// The format is knock.LoadKeysFromFile's: one hex-encoded key per line, and
// EXACTLY ONE line for a client. wrapSPA refuses a multi-key client file rather
// than guessing, because during a rotation the wrong guess is silent.
const SPAKeyCredentialFileName = "spa_knock_key.hex"
