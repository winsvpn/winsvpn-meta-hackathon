// Command winn-ech-keygen generates PRODUCTION ECH key material for a Winn v3
// gateway.
//
// Why this exists. cmd/winn3-gateway's runServe calls startCover
// unconditionally, and startCover loads -ech-keys, so a gateway cannot start
// without an ECH key file. The only generator in the tree was
// internal/pki.GenerateLab, which hardcodes the public name
// "public.winn.invalid" — a reserved TLD. echconfig.Generate has always taken a
// publicName parameter; nothing called it with a real one.
//
// That is not cosmetic. The generated key file sets SendAsRetry, so the public
// name can leave the server in an ECH retry_config in response to a GREASE
// probe. A reserved-TLD public name there tells a prober the endpoint is
// improvised, which is the opposite of what cover is for.
//
// The public name must be the SAME innocuous domain as the cover certificate
// and its DNS A record. A prober must see one coherent origin: outer SNI =
// cover certificate name = a name that resolves and serves something dull. A
// mismatch between any two of those is itself the fingerprint.
//
// This tool deliberately does NOT obtain the cover certificate. That is
// scripts/obtain_cover_cert.sh, which drives certbot for a real DV certificate
// — pass it --unit winn3-gateway, because it defaults to winn-carrier-server
// and predates the v3 gateway.
//
// Usage:
//
//	winn-ech-keygen -public-name cdn.example.com -out /etc/winn/credentials
//
// writes, refusing to overwrite either:
//
//	<out>/ech-server-keys.json   0600  -> gateway -ech-keys
//	<out>/ech-config-list.bin    0644  -> the public ECH config list
//
// Per-node rotation (Round GK OI-GK-3 step 1, 2026-09-26):
//
//	winn-ech-keygen -add-to /etc/winn/credentials/ech-keys.json -out <tmpfs dir>
//
// writes the same two files, but ech-server-keys.json holds TWO entries: a new
// key generated here (send_as_retry) followed by the existing key
// (send_as_retry cleared), so a peer holding either config still gets ECH
// accepted. The public name defaults to the existing entry's. The existing file
// is only read. ech-config-list.bin holds the new config only.
//
//	winn-ech-keygen -describe <ech key file>
//
// prints the PUBLIC fields of every entry and never a private key.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"winsvpn.local/winnprotocol/internal/echconfig"
	"winsvpn.local/winnprotocol/internal/securefile"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "winn-ech-keygen: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	var publicName, outDir, addTo, describe string
	var configID uint
	flag.StringVar(&publicName, "public-name", "", "ECH public name: the innocuous cover domain, matching the cover certificate and its DNS record. Required unless -add-to supplies it.")
	flag.StringVar(&outDir, "out", "", "directory to write ech-server-keys.json and ech-config-list.bin into. Required.")
	flag.UintVar(&configID, "config-id", 0, "ECH config ID 1-255; 0 (the default) draws one at random")
	flag.StringVar(&addTo, "add-to", "", "existing single-entry ECH key file (read only): write a two-entry file, new key first with send_as_retry, existing key second")
	flag.StringVar(&describe, "describe", "", "print the public fields of an ECH key file and exit")
	flag.Parse()

	if describe != "" {
		if publicName != "" || outDir != "" || addTo != "" || configID != 0 {
			return errors.New("-describe takes no other flag")
		}
		return describeKeyFile(describe)
	}
	if outDir == "" || (publicName == "" && addTo == "") {
		flag.Usage()
		return errors.New("-out and one of -public-name or -add-to are required")
	}
	if configID > 255 {
		return fmt.Errorf("-config-id %d is out of range (0-255)", configID)
	}
	var existing echconfig.KeyFile
	if addTo != "" {
		loaded, err := echconfig.LoadKeyFile(addTo)
		if err != nil {
			return fmt.Errorf("-add-to %s: %w", addTo, err)
		}
		existing = loaded
		if publicName == "" {
			current, err := echconfig.Describe(existing)
			if err != nil {
				return fmt.Errorf("-add-to %s: %w", addTo, err)
			}
			publicName = current[0].PublicName
		}
	}
	// A reserved or obviously non-public name defeats the purpose. echconfig
	// validates DNS syntax; it cannot know whether the name is plausible, so
	// refuse the two we KNOW are wrong rather than pretending to judge the rest.
	if publicName == "public.winn.invalid" {
		return errors.New("public.winn.invalid is the LAB name from internal/pki.GenerateLab; " +
			"it is a reserved TLD and identifies the endpoint as improvised. Use the real cover domain")
	}
	if suffixIsReserved(publicName) {
		return fmt.Errorf("%q ends in a reserved TLD (.invalid/.local/.test/.example/.localhost); "+
			"a prober that sees it in an ECH retry_config learns the endpoint is not a real origin", publicName)
	}

	keysPath := filepath.Join(outDir, "ech-server-keys.json")
	listPath := filepath.Join(outDir, "ech-config-list.bin")
	// Refuse to overwrite. Silently replacing a live gateway's ECH keys would
	// break every client mid-session with no record of what the old key was.
	for _, p := range []string{keysPath, listPath} {
		if _, err := os.Stat(p); err == nil {
			return fmt.Errorf("%s already exists; refusing to overwrite live ECH material", p)
		} else if !errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("stat %s: %w", p, err)
		}
	}

	var configList []byte
	var keyFile echconfig.KeyFile
	var err error
	if addTo != "" {
		configList, keyFile, err = echconfig.Rotate(existing, publicName, byte(configID))
	} else {
		configList, keyFile, err = echconfig.Generate(publicName, byte(configID))
	}
	if err != nil {
		return fmt.Errorf("generate: %w", err)
	}
	summary, err := echconfig.Describe(keyFile)
	if err != nil {
		clear(configList)
		return fmt.Errorf("describe: %w", err)
	}
	listDigest := sha256.Sum256(configList)
	keyData, err := echconfig.EncodeKeyFile(keyFile)
	if err != nil {
		clear(configList)
		return fmt.Errorf("encode key file: %w", err)
	}
	// Same ordering and the same clear() discipline as internal/pki: the key
	// material is wiped from this process's memory as soon as it is on disk.
	// AtomicWriteNew (link(2)) is required here, not AtomicWrite (rename(2)):
	// the Stat loop above is a best-effort pre-check, but only link refuses to
	// replace an existing destination atomically, so concurrent invocations
	// cannot silently overwrite each other's live key material.
	if err := securefile.AtomicWriteNew(listPath, configList, 0o644); err != nil {
		clear(configList)
		clear(keyData)
		return fmt.Errorf("write %s: %w", listPath, err)
	}
	clear(configList)
	if err := securefile.AtomicWriteNew(keysPath, keyData, 0o600); err != nil {
		clear(keyData)
		// Avoid leaving an orphaned public list with no matching private key:
		// the list was just created by this invocation (Stat above confirmed
		// neither file existed), so best-effort remove it so the next retry
		// does not see "already exists" for half a credential set.
		_ = os.Remove(listPath)
		return fmt.Errorf("write %s: %w", keysPath, err)
	}
	clear(keyData)

	fmt.Printf("wrote %s (0600)\nwrote %s (0644)\n", keysPath, listPath)
	fmt.Printf("public name: %s\n", publicName)
	fmt.Printf("entries: %d\n", len(summary))
	fmt.Printf("ech_public_key_sha256 %s\n", summary[0].PublicKeySHA256)
	fmt.Printf("ech_config_list_sha256 %s\n", hex.EncodeToString(listDigest[:]))
	if addTo != "" {
		fmt.Println("The existing key is kept as entry 2 without send_as_retry. Install the new")
		fmt.Println("file in place of the old one and restart the gateway to load it.")
		return nil
	}
	fmt.Println("Set WINN3_GATEWAY_ECH_KEYS to the ech-server-keys.json path before --install.")
	fmt.Println("The cover certificate must name the SAME domain; obtain it with")
	fmt.Println("  scripts/obtain_cover_cert.sh --unit winn3-gateway --domain " + publicName)
	return nil
}

// describeKeyFile prints only public fields. The private key never reaches
// stdout: EntryInfo has no field that could carry it.
func describeKeyFile(path string) error {
	file, err := echconfig.LoadKeyFile(path)
	if err != nil {
		return fmt.Errorf("-describe %s: %w", path, err)
	}
	entries, err := echconfig.Describe(file)
	if err != nil {
		return fmt.Errorf("-describe %s: %w", path, err)
	}
	list, err := echconfig.RetryConfigList(file)
	if err != nil {
		return fmt.Errorf("-describe %s: %w", path, err)
	}
	listDigest := sha256.Sum256(list)
	fmt.Printf("entries %d\n", len(entries))
	for index, entry := range entries {
		fmt.Printf("entry %d config_id=%d public_name=%s send_as_retry=%t public_key_sha256=%s config_sha256=%s\n",
			index, entry.ConfigID, entry.PublicName, entry.SendAsRetry, entry.PublicKeySHA256, entry.ConfigSHA256)
	}
	fmt.Printf("ech_public_key_sha256 %s\n", entries[0].PublicKeySHA256)
	fmt.Printf("retry_config_list_sha256 %s\n", hex.EncodeToString(listDigest[:]))
	return nil
}

// suffixIsReserved reports names under RFC 2606 / RFC 6761 special-use TLDs.
// These never resolve publicly, so one appearing in an ECH retry_config marks
// the endpoint as improvised rather than a real origin.
func suffixIsReserved(name string) bool {
	lower := strings.ToLower(name)
	for _, suffix := range []string{".invalid", ".local", ".test", ".example", ".localhost"} {
		if strings.EqualFold(name, strings.TrimPrefix(suffix, ".")) {
			return true
		}
		if strings.HasSuffix(lower, suffix) {
			return true
		}
	}
	return false
}
