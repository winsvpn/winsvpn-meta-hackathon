package carrierauth

import (
	"net/http"
	"testing"
)

func FuzzSignatureHeader(fuzzer *testing.F) {
	fuzzer.Add("AA")
	fuzzer.Add("")
	fuzzer.Add("%%%%")
	fuzzer.Fuzz(func(t *testing.T, value string) {
		header := make(http.Header)
		header.Set(HeaderSignature, value)
		signature, err := signatureHeader(header)
		if err == nil && len(signature) == 0 {
			t.Fatal("empty signature was accepted")
		}
	})
}
