package phase1anchor

import "errors"

// The committed anchor slot's artifact set — ONE definition, three consumers.
//
// A slot is written by cmd/winn-phase1-anchor-pin, adopted by
// cmd/winn-phase1-controller-close when it resumes an interrupted run, and
// required by cmd/winn-phase1-matrix-verify when an auditor checks the chain.
// Each of those used to carry its own list of filenames.
//
// That is precisely how the batch-meta.env P0 happened: the verifier's exact-set
// check required a file the pin tool never wrote, both sides were individually
// tested and agreed with themselves, and nothing compared them. Three
// enumerations of "what a slot contains" cannot be kept in agreement by review,
// because agreeing is not what any single one of them is tested for.
//
// So there is one list. A new artifact is added here, and every consumer moves
// together or fails to compile.

const (
	// SlotProviderConfigName records the frozen provider identities, key IDs,
	// hosts, known-hosts digest and predecessor links the pin ran under.
	SlotProviderConfigName = "provider-config.json"
	// SlotRequestName is the canonical request both providers signed.
	SlotRequestName = "request.json"
	// SlotProviderOneReceiptName and SlotProviderTwoReceiptName are the two
	// independent provider receipts over that request.
	SlotProviderOneReceiptName = "provider-one.receipt.json"
	SlotProviderTwoReceiptName = "provider-two.receipt.json"
	// SlotDigestSuffix names the sidecar digest written beside a sealed
	// artifact.
	SlotDigestSuffix = ".sha256"
)

// SlotArtifactNames returns the exact set of files one committed anchor slot
// holds, in a stable order.
//
// "Exact" is load-bearing on both sides. A subset match would let a slot missing
// a receipt be adopted as complete; a superset match would let anything extra
// ride along inside a directory whose whole purpose is to be a fixed, verified
// artifact. Consumers compare set equality, never containment.
func SlotArtifactNames() []string {
	return []string{
		SlotProviderConfigName,
		SlotProviderOneReceiptName,
		SlotProviderOneReceiptName + SlotDigestSuffix,
		SlotProviderTwoReceiptName,
		SlotProviderTwoReceiptName + SlotDigestSuffix,
		SlotRequestName,
		SlotRequestName + SlotDigestSuffix,
	}
}

// SidecarDigestBytes returns the exact on-disk form of a slot's *.sha256
// sidecar: the canonical lowercase digest and one terminating newline, nothing
// else.
//
// One definition, because the writer and the readers disagreed. The pin tool
// wrote exactly this and compared exact bytes on resume, while the formal
// verifier read the same file through strings.TrimSpace — so a sealed sidecar
// padded with leading spaces, tabs or blank lines was refused by the producer
// and accepted by the auditor. That is a byte-canonical evidence guarantee that
// was not byte-canonical on the side whose job is to check it, and it is the
// same writer-versus-verifier divergence that produced the batch-meta.env P0.
func SidecarDigestBytes(digest string) []byte {
	return []byte(digest + "\n")
}

// ParseSidecarDigest requires a sidecar to be EXACTLY SidecarDigestBytes of a
// canonical digest, and returns that digest.
//
// No trimming. Whitespace tolerance sounds harmless and is not: it makes the
// sealed bytes ambiguous, so two auditors reading the same evidence with
// slightly different tolerances can disagree about whether it is intact, and a
// tamperer gains a class of edits that changes the file without changing the
// verdict.
func ParseSidecarDigest(data []byte) (string, error) {
	if len(data) == 0 || data[len(data)-1] != '\n' {
		return "", errors.New(
			"anchor slot digest sidecar does not end in exactly one newline",
		)
	}
	value := string(data[:len(data)-1])
	if !ValidDigest(value) {
		return "", errors.New(
			"anchor slot digest sidecar is not exactly one canonical " +
				"lowercase 64-hex digest followed by a single newline",
		)
	}
	return value, nil
}

// SlotArtifactSet is SlotArtifactNames as a set, for callers that compare
// directory listings against it.
func SlotArtifactSet() map[string]struct{} {
	names := SlotArtifactNames()
	set := make(map[string]struct{}, len(names))
	for _, name := range names {
		set[name] = struct{}{}
	}
	return set
}
