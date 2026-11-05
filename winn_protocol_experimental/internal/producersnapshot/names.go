package producersnapshot

// The producer-side artifact names this digest covers.
//
// Restated here rather than imported from the controller command, because this
// package is what the formal verifier uses to recompute the digest — it cannot
// depend on the tool that produces it. A change to either side has to be a
// deliberate edit in both, which is the same rule the verifier already applies
// to the carrier schema token.
const (
	producerMarker = "PRODUCER_CLOSED_PENDING"
	pendingSuffix  = ".closed-pending"
	pendingArchive = ".closed-pending.tar.gz"
	manifestName   = "evidence-manifest.sha256"
	auditLogName   = "carrier-audit.jsonl"
)

// lowerHex reports whether value is a canonical lowercase 64-character hex
// digest.
func lowerHex(value string) bool {
	if len(value) != 64 {
		return false
	}
	for index := 0; index < len(value); index++ {
		character := value[index]
		if (character < '0' || character > '9') &&
			(character < 'a' || character > 'f') {
			return false
		}
	}
	return true
}
