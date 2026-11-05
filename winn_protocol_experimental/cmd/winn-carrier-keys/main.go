// Command winn-carrier-keys generates the carrier-profile key lists every
// platform host needs, from the single Go declaration in
// datapath/carrierhost/servedkeys.go, and -carve emits a standalone winn3
// carrier identity key-bundle fixture.
//
// # Why generate instead of hand-typing
//
// Four hosts in four languages need the same list of served carrier-profile
// keys, and no shared constant can be linked across Kotlin, Swift, Dart and
// C++. Before this command existed each host carried its own copy. All four
// copies agreed, which is precisely why nobody noticed when carrierhost.Profile
// grew the spa_* fields and all four copies silently excluded them: the
// capability was in the schema and unreachable from every platform at once.
//
// A hand-maintained copy is only as good as whoever remembers to update it. A
// generated one plus a drift test is a property of the build, and
// carrierhost.TestGeneratedPlatformKeyFilesAreCurrent fails the ordinary
// `go test ./...` run if any generated file has fallen behind. That test is the
// reason this command does not need to be wired into four separate build
// systems.
//
// # Carving a winn3 key bundle
//
// -carve derives a deterministic set of winn3 carrier X25519 identity key
// pairs from a single seed and writes a PUBLIC-ONLY bundle fixture. The
// committed fixture under winn3/conform/testdata is the reproduction target;
// winn3/carrier.TestCommittedCarveFixtureMatchesDerivation fails if it
// drifts. The bundle deliberately contains no private scalar and no seed —
// only the public halves and fingerprints plus a digest of the seed.
//
// Usage:
//
//	winn-carrier-keys -root /path/to/wins_vpn          # write the platform files
//	winn-carrier-keys -root /path/to/wins_vpn -check    # exit 1 if stale
//	winn-carrier-keys -carve <dir>                      # write a public key bundle
//	winn-carrier-keys -carve <dir> -carve-seed <hex>    # deterministic bundle
//	winn-carrier-keys -carve <dir> -carve-seed <hex> -carve-check  # verify file
//
// -root defaults to the repository root inferred from this source file's
// location, so both forms usually need no flag at all.
package main

import (
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"winsvpn.local/winnprotocol/datapath/carrierhost"
	"winsvpn.local/winnprotocol/winn3/carrier"
)

// carveBundleFileName is the public-only bundle a carve writes. It holds no
// private material; see winn3/carrier for why the private halves never land in
// it.
const carveBundleFileName = "winn3_carrier_keybundle.json"

func main() {
	root := flag.String("root", "", "repository root; inferred when empty")
	check := flag.Bool("check", false,
		"do not write; exit non-zero if any generated file is stale")
	carveOut := flag.String("carve", "", "carve a winn3 carrier key bundle into this directory")
	carveSeed := flag.String("carve-seed", "",
		"32-byte hex seed for a deterministic carve (default: fresh random)")
	carveRoles := flag.String("carve-roles", "",
		"comma-separated roles to carve (default: gateway+client for one host)")
	carveCheck := flag.Bool("carve-check", false,
		"with -carve: do not write; exit non-zero if the existing bundle is stale")
	flag.Parse()

	if *carveOut != "" {
		os.Exit(runCarve(*carveOut, *carveSeed, *carveRoles, *carveCheck))
	}

	resolved, err := carrierhost.ResolveRepositoryRoot(*root)
	if err != nil {
		fmt.Fprintf(os.Stderr, "winn-carrier-keys: %v\n", err)
		os.Exit(2)
	}

	stale := 0
	for _, file := range carrierhost.GeneratedPlatformKeyFiles() {
		path := filepath.Join(resolved, file.Path)
		want := file.Content
		got, readErr := os.ReadFile(path)
		current := readErr == nil && string(got) == want

		if *check {
			if !current {
				stale++
				if readErr != nil {
					fmt.Fprintf(os.Stderr,
						"winn-carrier-keys: %s is missing: %v\n", file.Path, readErr)
				} else {
					fmt.Fprintf(os.Stderr,
						"winn-carrier-keys: %s is STALE\n", file.Path)
				}
			}
			continue
		}

		if current {
			fmt.Printf("unchanged %s\n", file.Path)
			continue
		}
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			fmt.Fprintf(os.Stderr, "winn-carrier-keys: %v\n", err)
			os.Exit(2)
		}
		if err := os.WriteFile(path, []byte(want), 0o644); err != nil {
			fmt.Fprintf(os.Stderr, "winn-carrier-keys: %v\n", err)
			os.Exit(2)
		}
		fmt.Printf("wrote     %s\n", file.Path)
	}

	if stale > 0 {
		fmt.Fprintf(os.Stderr,
			"winn-carrier-keys: %d generated file(s) are stale; regenerate with\n"+
				"  go run ./cmd/winn-carrier-keys\n", stale)
		os.Exit(1)
	}
}

// runCarve derives the winn3 carrier key bundle and either writes it or
// verifies an existing one. It returns the process exit code.
func runCarve(outDir, seedHex, rolesFlag string, verify bool) int {
	roles := carrier.DefaultCarveRoles
	if strings.TrimSpace(rolesFlag) != "" {
		roles = strings.Split(rolesFlag, ",")
		for i := range roles {
			roles[i] = strings.TrimSpace(roles[i])
		}
	}

	seed, err := carveSeedBytes(seedHex)
	if err != nil {
		fmt.Fprintf(os.Stderr, "winn-carrier-keys: %v\n", err)
		return 2
	}

	bundle, err := carrier.Carve(seed, roles)
	if err != nil {
		fmt.Fprintf(os.Stderr, "winn-carrier-keys: %v\n", err)
		return 2
	}
	raw, err := carrier.MarshalBundle(bundle)
	if err != nil {
		fmt.Fprintf(os.Stderr, "winn-carrier-keys: %v\n", err)
		return 2
	}

	path := filepath.Join(outDir, carveBundleFileName)
	if verify {
		return verifyCarve(path, raw)
	}

	if err := os.MkdirAll(outDir, 0o755); err != nil {
		fmt.Fprintf(os.Stderr, "winn-carrier-keys: %v\n", err)
		return 2
	}
	if err := os.WriteFile(path, raw, 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "winn-carrier-keys: %v\n", err)
		return 2
	}

	// The bundle holds the PUBLIC halves. Print only fingerprints, never a
	// private material, and never the raw seed (which would let an onlooker
	// re-derive the private halves).
	fmt.Printf("wrote     %s (public-only)\n", path)
	for _, k := range bundle.Keys {
		fmt.Printf("  %-24s fingerprint=%s\n", k.Role, k.Fingerprint)
	}
	return 0
}

func verifyCarve(path string, want []byte) int {
	got, err := os.ReadFile(path)
	if err != nil {
		fmt.Fprintf(os.Stderr,
			"winn-carrier-keys: %s is missing: %v\n", path, err)
		return 1
	}
	if string(got) != string(want) {
		fmt.Fprintf(os.Stderr,
			"winn-carrier-keys: %s is STALE; regenerate with -carve\n", path)
		return 1
	}
	fmt.Printf("verified  %s\n", path)
	return 0
}

// carveSeedBytes turns -carve-seed into a 32-byte seed. An empty flag draws
// from the CSPRNG. The seed is never printed by this command.
func carveSeedBytes(hexSeed string) ([]byte, error) {
	if strings.TrimSpace(hexSeed) == "" {
		seed := make([]byte, 32)
		if _, err := io.ReadFull(rand.Reader, seed); err != nil {
			return nil, fmt.Errorf("could not draw a seed: %v", err)
		}
		return seed, nil
	}
	seed, err := hex.DecodeString(strings.TrimSpace(hexSeed))
	if err != nil {
		return nil, fmt.Errorf("-carve-seed is not hex: %v", err)
	}
	if len(seed) != 32 {
		return nil, fmt.Errorf("-carve-seed is %d bytes, need 32", len(seed))
	}
	return seed, nil
}
