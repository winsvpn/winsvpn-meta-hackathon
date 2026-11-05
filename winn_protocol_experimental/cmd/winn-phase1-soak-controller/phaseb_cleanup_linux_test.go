//go:build linux

package main

import (
	"strings"
	"testing"
)

func TestReceiptEventValidationTracksPhaseAParser(t *testing.T) {
	cases := map[string][]byte{
		"terminal single line": []byte("populated 0\n"),
		"terminal multiline":   []byte("populated 0\nfrozen 0\n"),
		"terminal reordered":   []byte("frozen 0\npopulated 0\n"),
		"populated":            []byte("populated 1\nfrozen 0\n"),
		"missing":              []byte("frozen 0\n"),
		"duplicate":            []byte("populated 0\npopulated 0\n"),
		"invalid value":        []byte("populated false\n"),
		"spacing":              []byte("populated  0\n"),
		"unterminated":         []byte("populated 0"),
		"invalid UTF-8": {
			'p', 'o', 'p', 'u', 'l', 'a', 't', 'e', 'd', ' ', '0', 0xff, '\n',
		},
		"oversized": []byte(
			strings.Repeat("frozen 0\n", 456) + "populated 0\n",
		),
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			populated, phaseAErr := parseCgroupEvents(raw)
			phaseBErr := validateTerminalCgroupEvents(string(raw))
			wantAccepted := phaseAErr == nil && !populated
			if (phaseBErr == nil) != wantAccepted {
				t.Fatalf(
					"Phase A populated=%t err=%v; Phase B err=%v",
					populated, phaseAErr, phaseBErr,
				)
			}
		})
	}
}
