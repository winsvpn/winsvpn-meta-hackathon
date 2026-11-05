package main

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

// jsonUnmarshalStrict refuses unknown fields and trailing JSON.
//
// A vector file with a misspelled key would otherwise decode to a zero value
// and be compared against silently — which is the exact class of silent success
// this suite exists to remove, arriving through its own front door.
//
// Trailing JSON is refused for the same reason ParseHostReport refuses it: a
// decoder that stops after the first value would compare only the first object
// and silently ignore a second.
func jsonUnmarshalStrict(raw []byte, dst any) error {
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return err
	}
	var extra json.RawMessage
	if err := dec.Decode(&extra); err != io.EOF {
		if err == nil {
			return fmt.Errorf("vector file has trailing JSON after the object")
		}
		return fmt.Errorf("vector file has trailing JSON after the object: %w", err)
	}
	return nil
}
