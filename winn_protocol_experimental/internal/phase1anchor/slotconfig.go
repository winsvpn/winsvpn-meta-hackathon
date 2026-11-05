package phase1anchor

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
)

// The frozen provider configuration a pin writes into an anchor slot — ONE
// definition, three consumers, for the same reason SlotArtifactNames is one
// definition.
//
// This record states the terms a slot was produced under: which two providers,
// under which signing keys, chained to which predecessors, against which frozen
// known-hosts file. It existed as two independently maintained struct
// declarations — one in the pin tool, one in the formal verifier — and the
// controller that ADOPTS an interrupted run's slot validated it not at all: it
// required the file to be present and never read it.
//
// That is the batch-meta.env shape again. The controller could adopt an
// incumbent produced under a different provider set, a different key, or a
// different predecessor link, chain every later anchor onto it, and only then
// hand the finished matrix to a verifier that refuses it — with the provider
// signatures already irreversible.

// SlotConfigSchema is the only accepted schema token for a slot configuration.
const SlotConfigSchema = "winn-phase1-anchor-pending-config/v1"

// SlotConfig is the sealed provider configuration inside one anchor slot.
type SlotConfig struct {
	Schema           string `json:"schema"`
	KnownHostsDigest string `json:"known_hosts_sha256"`
	ProviderOneID    string `json:"provider_one_id"`
	ProviderOneHost  string `json:"provider_one_host"`
	ProviderOneKeyID string `json:"provider_one_key_id"`
	ProviderOnePrior string `json:"provider_one_previous_receipt"`
	ProviderTwoID    string `json:"provider_two_id"`
	ProviderTwoHost  string `json:"provider_two_host"`
	ProviderTwoKeyID string `json:"provider_two_key_id"`
	ProviderTwoPrior string `json:"provider_two_previous_receipt"`
}

// SlotConfigExpectation is what a consumer independently knows to be true,
// carried explicitly rather than read back out of the document being checked.
//
// A slot that names its own provider identities and is verified against those
// same names authenticates nothing. Every field here comes from the consumer's
// own frozen trust set and run configuration.
type SlotConfigExpectation struct {
	ProviderOneID    string
	ProviderTwoID    string
	ProviderOneKeyID string
	ProviderTwoKeyID string
	PreviousOne      string
	PreviousTwo      string

	// KnownHostsDigest is required to match exactly when it is set, and BOTH
	// consumers set it.
	//
	// The controller holds the frozen known-hosts bytes and hashes them. The
	// external verifier hashes the archived anchors/known_hosts and requires it
	// to equal the digest the matrix's own signed state binds, then threads that
	// authenticated value in here. Neither side settles for a shape check: a
	// configuration naming any well-formed 64-hex digest would otherwise be
	// indistinguishable from one naming the right one, while the correct answer
	// was already in hand.
	//
	// It stays optional in the type because a consumer that genuinely lacks the
	// value must not be forced to invent one — but a consumer leaving it empty
	// is asserting it has no authenticated digest at all, which is a strong
	// claim and should be justified where it is made.
	KnownHostsDigest string

	// ProviderOneHost and ProviderTwoHost are required to match EXACTLY when
	// they are set — byte equality, with no normalisation and no partial match.
	//
	// The asymmetry here is the same as KnownHostsDigest's, and it needs
	// stating rather than leaving for a future reader to reconstruct:
	//
	//   * The CONTROLLER knows both addresses independently — they are its own
	//     -anchor-provider-*-host arguments, and the pin tool it invoked
	//     emitted exactly those values. It therefore supplies them and requires
	//     equality. Without that, a sealed configuration naming any two
	//     distinct non-empty strings satisfies the distinctness check below,
	//     and the controller cannot tell a correct configuration from a
	//     plausible-looking wrong one.
	//
	//   * The external VERIFIER has no host pin to compare against, and leaves
	//     these empty. For that consumer the recorded hosts are UNVERIFIED
	//     PROVENANCE METADATA, and they remain so unless a future signed schema
	//     binds them explicitly.
	//
	//     No weaker authentication path substitutes for that, and it is worth
	//     saying so plainly because the opposite is an easy thing to assume: a
	//     receipt authenticates a provider key's possession of a REQUEST. It
	//     says nothing whatsoever about the separate, unsigned host strings
	//     recorded beside it. Nothing an auditor holds ties a receipt to an
	//     address, so a verifier treating these as verified facts would be
	//     asserting something its inputs cannot support.
	//
	//     They are still required to be structurally valid IP addresses below.
	//     A string that cannot be an address at all is malformed no matter who
	//     is reading it; that check is about well-formedness, and it is not and
	//     must not be mistaken for authentication.
	ProviderOneHost string
	ProviderTwoHost string
}

// Canonical returns the exact byte encoding a slot configuration is sealed as,
// excluding the terminating newline the writer appends.
func (config SlotConfig) Canonical() ([]byte, error) {
	return json.Marshal(config)
}

// SealedBytes is Canonical plus the single terminating newline, which is the
// complete on-disk form. Consumers compare against this rather than against a
// trimmed value: Canonical hashes a re-marshal, so a document padded with
// whitespace or carrying duplicate object keys is semantically equal and
// byte-different, and it is the BYTES that were sealed.
func (config SlotConfig) SealedBytes() ([]byte, error) {
	canonical, err := config.Canonical()
	if err != nil {
		return nil, err
	}
	return append(canonical, '\n'), nil
}

// DecodeSlotConfig parses a sealed slot configuration strictly: unknown fields
// are refused, and a trailing second JSON value is refused rather than ignored.
func DecodeSlotConfig(data []byte) (SlotConfig, error) {
	var config SlotConfig
	if err := decodeStrict(data, &config); err != nil {
		return SlotConfig{}, err
	}
	return config, nil
}

// RequireCanonicalSlotConfig decodes a sealed slot configuration and requires
// its bytes to be exactly the canonical sealed encoding.
func RequireCanonicalSlotConfig(data []byte) (SlotConfig, error) {
	config, err := DecodeSlotConfig(data)
	if err != nil {
		return SlotConfig{}, err
	}
	sealed, err := config.SealedBytes()
	if err != nil {
		return SlotConfig{}, err
	}
	if !bytes.Equal(data, sealed) {
		return SlotConfig{}, errors.New(
			"anchor slot configuration bytes are not the canonical sealed " +
				"encoding",
		)
	}
	return config, nil
}

// Verify requires a sealed configuration to describe exactly the run the
// consumer believes it is in.
func (config SlotConfig) Verify(want SlotConfigExpectation) error {
	if config.Schema != SlotConfigSchema {
		return fmt.Errorf(
			"anchor slot configuration schema is %q, want %q",
			config.Schema, SlotConfigSchema,
		)
	}
	if config.ProviderOneID != want.ProviderOneID ||
		config.ProviderTwoID != want.ProviderTwoID {
		return errors.New(
			"the anchor slot was produced for a different provider pair",
		)
	}
	if config.ProviderOneKeyID != want.ProviderOneKeyID ||
		config.ProviderTwoKeyID != want.ProviderTwoKeyID {
		return errors.New(
			"the anchor slot was produced under different provider signing keys",
		)
	}
	if config.ProviderOnePrior != want.PreviousOne ||
		config.ProviderTwoPrior != want.PreviousTwo {
		return errors.New(
			"the anchor slot chains to different predecessor receipts",
		)
	}
	if config.ProviderOneHost == "" || config.ProviderTwoHost == "" {
		return errors.New("an anchor provider host is missing")
	}
	// The producer contract is literal IP addresses — winn-phase1-anchor-pin
	// refuses anything else, so a sealed configuration recording a name was
	// never written by it. Well-formedness is checkable by every consumer, and
	// this is not authentication: it rules out values that cannot be addresses,
	// nothing more.
	for _, host := range []string{
		config.ProviderOneHost, config.ProviderTwoHost,
	} {
		if _, err := netip.ParseAddr(host); err != nil {
			return fmt.Errorf(
				"the anchor slot records provider host %q, which is not an IP "+
					"address; the anchor transport contacts literal addresses "+
					"so that no name resolution stands between a caller and "+
					"the provider it believes it reached", host,
			)
		}
	}
	// Two providers reachable at one address are one witness wearing two
	// names, which is the entire property dual anchoring buys.
	//
	// String inequality is not enough. The pin CLI already refuses
	// 127.0.0.1 and ::ffff:127.0.0.1 as one machine; Verify used to compare
	// the host strings and would have accepted that pair on sealed evidence.
	// The auditor would then have been weaker than the producer — the same
	// writer-versus-verifier split this package exists to close. Distinctness
	// is decided after both values have parsed, so an unparseable pair still
	// fails as "not an IP address" rather than as "same host".
	if !ProviderHostsAreDistinct(
		config.ProviderOneHost, config.ProviderTwoHost,
	) {
		return errors.New(
			"both anchor providers were contacted at the same host, so their " +
				"receipts are not independent",
		)
	}
	// Exact string equality when the consumer holds the addresses. This is
	// deliberately not the same comparison as ProviderHostsAreDistinct: the
	// controller passed these exact argument strings to the pin tool and
	// requires the sealed file to record them byte-for-byte. Distinctness
	// asks whether two hosts are one machine; this asks whether they are
	// the hosts this run configured.
	if want.ProviderOneHost != "" &&
		config.ProviderOneHost != want.ProviderOneHost {
		return fmt.Errorf(
			"the anchor slot names first provider host %q, this run uses %q",
			config.ProviderOneHost, want.ProviderOneHost,
		)
	}
	if want.ProviderTwoHost != "" &&
		config.ProviderTwoHost != want.ProviderTwoHost {
		return fmt.Errorf(
			"the anchor slot names second provider host %q, this run uses %q",
			config.ProviderTwoHost, want.ProviderTwoHost,
		)
	}
	if !ValidDigest(config.KnownHostsDigest) {
		return errors.New(
			"the anchor slot known-hosts digest is not a canonical digest",
		)
	}
	if want.KnownHostsDigest != "" &&
		config.KnownHostsDigest != want.KnownHostsDigest {
		return errors.New(
			"the anchor slot was produced against a different frozen " +
				"known-hosts file",
		)
	}
	return nil
}

// ProviderHostsAreDistinct reports whether two provider host strings name
// different machines. Both values must be literal IP addresses; unparseable
// input is not distinct. String inequality is not enough: 127.0.0.1 and
// ::ffff:127.0.0.1 parse as the same address, and two receipts from one host
// are not two anchors.
func ProviderHostsAreDistinct(one, two string) bool {
	first, firstErr := netip.ParseAddr(one)
	second, secondErr := netip.ParseAddr(two)
	if firstErr != nil || secondErr != nil {
		return false
	}
	return first.Unmap() != second.Unmap()
}
