package main

import "testing"

// The positive control: the unmutated framing must be conformant. If a golden
// byte or a rule drifts, this is where it is first seen.
func TestRunSelfTestPasses(t *testing.T) {
	if err := runSelfTest(); err != nil {
		t.Fatalf("runSelfTest() failed on pristine framing: %v", err)
	}
}

// The negative control: the golden check must actually SEE a break. Mutating a
// single golden byte must turn the pass into a failure, or the "PASS" means
// nothing. Restored in a defer so it can never leak into a sibling test.
func TestGoldenCheckSeesMutation(t *testing.T) {
	saved := append([]byte{}, goldenCreateFrame...)
	defer func() { copy(goldenCreateFrame, saved) }()

	goldenCreateFrame[7] = 0x03 // opcode kCreate -> an arbitrary other opcode
	if err := checkGoldenEncoding(); err == nil {
		t.Fatalf("checkGoldenEncoding() passed with a mutated golden vector")
	}
}

// A rejection must also have teeth: the reader must refuse a specific corrupt
// frame rather than the whole rejection group passing vacuously.
func TestRejectionOfWrongDirection(t *testing.T) {
	raw, err := encodeFrame(opInbound, []byte{0x45, 0x00})
	if err != nil {
		t.Fatalf("encode inbound: %v", err)
	}
	reader := &frameReader{acceptEngineToHost: true}
	reader.append(raw)
	var op uint16
	var payload []byte
	if reader.next(&op, &payload) != statusInvalid {
		t.Fatalf("host reader accepted a host->engine opcode")
	}
}
