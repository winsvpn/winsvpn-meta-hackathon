package privacytoken

import "testing"

func FuzzDecodeTokenHeader(fuzzer *testing.F) {
	fuzzer.Add("")
	fuzzer.Add("e30")
	fuzzer.Add("%%%%")
	fuzzer.Fuzz(func(t *testing.T, encoded string) {
		token, err := DecodeTokenHeader(encoded)
		if err == nil &&
			(token.PreparedMessage == "" || token.Signature == "") {
			t.Fatal("accepted an empty privacy token field")
		}
	})
}
