package main

import (
	"fmt"
	"io"
)

// runFeatures prints the optional control-plane behaviours this binary
// supports, one word per line, for `winn3-gateway -mode features`. The node
// register script runs it bounded, reports the words it knows to the hub
// inside the existing winn3_gateway report, and the hub publishes
// feature-gated documents only to nodes whose report carries the feature. A
// binary from before this mode exists simply fails or prints nothing, which
// the register script reads as "no features": an old node keeps receiving
// today's documents, and no deploy order can publish a field the node's
// decoder would refuse.
//
// peer-registry-tier: the peer registry decoder accepts the optional
// per-entry "tier" word (free or premium) in a version 1 document. A binary
// without it refuses a document that names the field, which is why the hub
// writes the word only for a node whose report carries this feature.
func runFeatures(out io.Writer) error {
	for _, feature := range []string{"peer-registry-tier"} {
		if _, err := fmt.Fprintln(out, feature); err != nil {
			return err
		}
	}
	return nil
}
