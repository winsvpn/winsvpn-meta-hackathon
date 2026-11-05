package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"winsvpn.local/winnprotocol/internal/phase1anchor"
	"winsvpn.local/winnprotocol/internal/securefile"
)

type provider struct {
	id            string
	host          string
	publicKeyPath string
	// public is the decoded key, read once by run and never reopened.
	public         ed25519.PublicKey
	previousDigest string
	receiptName    string
}

type temporaryError struct {
	err error
}

func (current temporaryError) Error() string {
	return current.err.Error()
}

func main() {
	pendingDirectory := flag.String(
		"pending-directory", "", "private immutable pin-pending directory",
	)
	requestPath := flag.String(
		"request", "", "candidate canonical request JSON",
	)
	sshBinary := flag.String("ssh-binary", "/usr/bin/ssh", "SSH binary")
	sshKey := flag.String("ssh-key", "", "dedicated forced-command SSH key")
	knownHosts := flag.String(
		"known-hosts", "", "frozen provider SSH host keys",
	)
	timeout := flag.Duration(
		"timeout", 20*time.Second, "per-provider transport timeout",
	)
	first := provider{}
	second := provider{}
	flag.StringVar(&first.id, "provider-one-id", "", "first provider ID")
	flag.StringVar(&first.host, "provider-one-host", "", "first SSH host")
	flag.StringVar(
		&first.publicKeyPath,
		"provider-one-public-key", "", "first receipt public key",
	)
	flag.StringVar(
		&first.previousDigest,
		"provider-one-previous-receipt", "", "first previous receipt digest",
	)
	flag.StringVar(&second.id, "provider-two-id", "", "second provider ID")
	flag.StringVar(&second.host, "provider-two-host", "", "second SSH host")
	flag.StringVar(
		&second.publicKeyPath,
		"provider-two-public-key", "", "second receipt public key",
	)
	flag.StringVar(
		&second.previousDigest,
		"provider-two-previous-receipt", "", "second previous receipt digest",
	)
	flag.Parse()
	if flag.NArg() != 0 || *pendingDirectory == "" ||
		*requestPath == "" || *sshKey == "" ||
		*knownHosts == "" || first.id == "" || second.id == "" ||
		first.id == second.id || first.host == "" ||
		second.host == "" || first.host == second.host ||
		first.publicKeyPath == "" || second.publicKeyPath == "" ||
		!parsedHostsAreDistinct(first.host, second.host) ||
		*timeout < time.Second || *timeout > 2*time.Minute {
		fatal(errors.New("complete, distinct dual-provider pin configuration is required"))
	}
	// Previous-receipt digests, validated BEFORE any provider is contacted.
	//
	// The CLI validation above checked every other field and skipped these two
	// entirely, so a malformed predecessor — most obviously an empty genesis
	// link — travelled all the way to two external providers and failed on
	// their side. Every such round trip is a step in an irreversible chain
	// spent to learn something decidable locally.
	//
	// The request has not been read yet at this point, so the ordinal is not
	// known here; what is checked is canonical shape, with the ordinal-specific
	// genesis rule applied in run() once the request is loaded.
	for name, value := range map[string]string{
		"-provider-one-previous-receipt": first.previousDigest,
		"-provider-two-previous-receipt": second.previousDigest,
	} {
		if !phase1anchor.ValidDigest(value) {
			fatal(fmt.Errorf(
				"%s is %q, want a canonical lowercase 64-hex digest (the "+
					"genesis link is %s, not an empty string)",
				name, value, phase1anchor.ZeroDigest,
			))
		}
	}
	first.receiptName = phase1anchor.SlotProviderOneReceiptName
	second.receiptName = phase1anchor.SlotProviderTwoReceiptName
	if err := run(
		*pendingDirectory,
		*requestPath,
		*sshBinary,
		*sshKey,
		*knownHosts,
		*timeout,
		first,
		second,
	); err != nil {
		var temporary temporaryError
		if errors.As(err, &temporary) {
			fmt.Fprintln(os.Stderr, "ANCHOR_PIN_TEMPORARY:", err)
			os.Exit(75)
		}
		fatal(err)
	}
}

func run(
	pendingDirectory string,
	requestPath string,
	sshBinary string,
	sshKey string,
	knownHosts string,
	timeout time.Duration,
	providers ...provider,
) error {
	if err := ensurePrivateDirectory(pendingDirectory); err != nil {
		return err
	}
	if len(providers) != 2 {
		return errors.New("exactly two providers are required")
	}
	// Each provider key is decoded EXACTLY ONCE, here, and the decoded value
	// travels in memory from this point on. pinProvider used to reopen
	// current.publicKeyPath, which is a second read of the same inherited
	// descriptor — the same shared-offset and identity problems as the
	// known-hosts double read, applied to the credential that decides whether a
	// receipt is genuine.
	firstPublic, err := readPublicKey(providers[0].publicKeyPath)
	if err != nil {
		return err
	}
	providers[0].public = firstPublic
	secondPublic, err := readPublicKey(providers[1].publicKeyPath)
	if err != nil {
		return err
	}
	providers[1].public = secondPublic
	if bytes.Equal(firstPublic, secondPublic) {
		return errors.New("anchor providers must use distinct receipt keys")
	}
	// The known-hosts bytes are read ONCE, and everything downstream derives
	// from that one buffer.
	//
	// This path is normally an inherited /dev/fd name, so a second open is not
	// merely wasteful: descriptor offsets are shared, so a read to EOF followed
	// by another read finds nothing left. Computing the digest from one read
	// and the snapshot from another would also let the recorded digest and the
	// bytes the providers actually see come from different states of the same
	// descriptor.
	knownHostsBytes, err := readLimitedFile(knownHosts, 1<<20)
	if err != nil {
		return err
	}
	knownHostsSum := sha256.Sum256(knownHostsBytes)
	knownHostsDigest := hex.EncodeToString(knownHostsSum[:])
	// File-descriptor inheritance does not cross an exec boundary on its own.
	// The controller can hand this process /dev/fd/5, but Go's exec closes
	// every non-standard descriptor in a child unless ExtraFiles names it, so
	// ssh would never see fd 5 — it would try to open the pathname it was
	// given, which in that process names nothing. Passing the chain through has
	// to be explicit at each layer, which is what this snapshot does.
	knownHostsSnapshot, err := securefile.AnonymousSnapshot(knownHostsBytes)
	if err != nil {
		return fmt.Errorf("known hosts snapshot: %w", err)
	}
	defer knownHostsSnapshot.Close()
	configuration := phase1anchor.SlotConfig{
		Schema:           phase1anchor.SlotConfigSchema,
		KnownHostsDigest: knownHostsDigest,
		ProviderOneID:    providers[0].id,
		ProviderOneHost:  providers[0].host,
		ProviderOneKeyID: phase1anchor.PublicKeyID(firstPublic),
		ProviderOnePrior: providers[0].previousDigest,
		ProviderTwoID:    providers[1].id,
		ProviderTwoHost:  providers[1].host,
		ProviderTwoKeyID: phase1anchor.PublicKeyID(secondPublic),
		ProviderTwoPrior: providers[1].previousDigest,
	}
	configurationData, err := configuration.SealedBytes()
	if err != nil {
		return err
	}
	frozenConfigurationPath := filepath.Join(
		pendingDirectory, phase1anchor.SlotProviderConfigName,
	)
	if current, err := securefile.ReadPublicIntegrity(
		frozenConfigurationPath, 64<<10,
	); err == nil {
		if !bytes.Equal(current, configurationData) {
			return errors.New(
				"pin-pending provider configuration changed",
			)
		}
	} else if errors.Is(err, os.ErrNotExist) {
		if err := createExclusive(
			frozenConfigurationPath, configurationData,
		); err != nil {
			return err
		}
	} else {
		return err
	}
	requestData, err := securefile.ReadPublicIntegrity(requestPath, 64<<10)
	if err != nil {
		return err
	}
	request, err := phase1anchor.DecodeRequest(bytes.NewReader(requestData))
	if err == nil {
		// The ordinal-specific rule, applied as soon as the ordinal is known
		// and still before any provider contact: genesis must carry exactly the
		// canonical zero predecessor, and no later link may carry it.
		for name, previous := range map[string]string{
			"-provider-one-previous-receipt": providers[0].previousDigest,
			"-provider-two-previous-receipt": providers[1].previousDigest,
		} {
			if !phase1anchor.ValidPreviousDigest(previous, request.Ordinal) {
				return fmt.Errorf(
					"%s is %q, which is not valid at ordinal %d",
					name, previous, request.Ordinal,
				)
			}
		}
	}
	if err != nil {
		return err
	}
	canonical, err := request.Canonical()
	if err != nil {
		return err
	}
	canonical = append(canonical, '\n')
	frozenRequest := filepath.Join(pendingDirectory, phase1anchor.SlotRequestName)
	if current, err := securefile.ReadPublicIntegrity(
		frozenRequest, 64<<10,
	); err == nil {
		if !bytes.Equal(current, canonical) {
			return errors.New("pin-pending request conflicts with frozen request")
		}
	} else if errors.Is(err, os.ErrNotExist) {
		if err := createExclusive(frozenRequest, canonical); err != nil {
			return err
		}
	} else {
		return err
	}
	requestDigest, err := request.Digest()
	if err != nil {
		return err
	}
	requestDigestPath := filepath.Join(
		pendingDirectory, phase1anchor.SlotRequestName+phase1anchor.SlotDigestSuffix,
	)
	requestDigestContent := phase1anchor.SidecarDigestBytes(requestDigest)
	if existing, err := securefile.ReadPublicIntegrity(
		requestDigestPath, 4<<10,
	); err == nil {
		if !bytes.Equal(existing, requestDigestContent) {
			return errors.New("stored request digest is inconsistent")
		}
	} else if errors.Is(err, os.ErrNotExist) {
		if err := createExclusive(
			requestDigestPath, requestDigestContent,
		); err != nil {
			return err
		}
	} else {
		return err
	}

	for _, current := range providers {
		if err := pinProvider(
			request,
			canonical,
			pendingDirectory,
			sshBinary,
			sshKey,
			knownHostsSnapshot,
			knownHostsBytes,
			timeout,
			current,
		); err != nil {
			return err
		}
	}
	for _, current := range providers {
		receiptPath := filepath.Join(
			pendingDirectory, current.receiptName,
		)
		data, err := securefile.ReadPublicIntegrity(receiptPath, 64<<10)
		if err != nil {
			return err
		}
		receipt, err := phase1anchor.DecodeReceipt(bytes.NewReader(data))
		if err != nil {
			return err
		}
		// Re-applied to what is actually ON DISK, not just to what came back
		// over the transport. This loop also runs on the resume path, where the
		// receipt was written by an earlier attempt and pinProvider returned
		// without ever seeing the provider's bytes.
		if err := requireCanonicalReceiptBytes(data, receipt); err != nil {
			return fmt.Errorf("provider %s: %w", current.id, err)
		}
		digest, err := receipt.Digest()
		if err != nil {
			return err
		}
		digestPath := filepath.Join(
			pendingDirectory,
			current.receiptName+phase1anchor.SlotDigestSuffix,
		)
		digestContent := phase1anchor.SidecarDigestBytes(digest)
		if existing, err := securefile.ReadPublicIntegrity(
			digestPath, 4<<10,
		); err == nil {
			if !bytes.Equal(existing, digestContent) {
				return errors.New(
					"stored provider receipt digest is inconsistent",
				)
			}
		} else if errors.Is(err, os.ErrNotExist) {
			if err := createExclusive(digestPath, digestContent); err != nil {
				return err
			}
		} else {
			return err
		}
		fmt.Printf(
			"ANCHOR_PIN_OK provider=%s receipt_sha256=%s\n",
			current.id, digest,
		)
	}
	// The slot this tool just produced must be exactly the set every consumer
	// requires — checked here, at the writer, against the shared definition.
	//
	// The controller renames this directory onto the committed name and the
	// formal verifier then demands set EQUALITY. Discovering a mismatch there
	// means discovering it after two providers have signed. Discovering it here
	// costs nothing.
	if err := requireExactSlotContents(pendingDirectory); err != nil {
		return err
	}
	return nil
}

// requireExactSlotContents proves the pending directory holds precisely the
// shared artifact set: no member missing, nothing extra, and every entry a
// regular file rather than a directory, symbolic link or device node.
func requireExactSlotContents(directory string) error {
	entries, err := os.ReadDir(directory)
	if err != nil {
		return err
	}
	expected := phase1anchor.SlotArtifactSet()
	seen := make(map[string]struct{}, len(entries))
	for _, entry := range entries {
		name := entry.Name()
		if _, ok := expected[name]; !ok {
			return fmt.Errorf(
				"the pin-pending slot holds %q, which is not part of the "+
					"anchor slot artifact set; the formal verifier requires "+
					"set equality and would refuse this slot", name,
			)
		}
		if !entry.Type().IsRegular() {
			return fmt.Errorf(
				"the pin-pending slot member %q is not a regular file", name,
			)
		}
		seen[name] = struct{}{}
	}
	for _, name := range phase1anchor.SlotArtifactNames() {
		if _, ok := seen[name]; !ok {
			return fmt.Errorf(
				"the pin-pending slot is missing %q; it would be committed "+
					"incomplete and refused by the formal verifier", name,
			)
		}
	}
	return nil
}

// readLimitedFile returns a file's bytes under a bound, using the same reader
// the digest above consults so the snapshot and the recorded digest describe
// one read of one file.
func readLimitedFile(path string, maximum int64) ([]byte, error) {
	return securefile.ReadPublicIntegrity(path, maximum)
}

func pinProvider(
	request phase1anchor.Request,
	canonical []byte,
	pendingDirectory string,
	sshBinary string,
	sshKey string,
	knownHostsSnapshot *os.File,
	knownHostsBytes []byte,
	timeout time.Duration,
	current provider,
) error {
	// The key decoded once in run. No path is reopened here.
	public := current.public
	if len(public) != ed25519.PublicKeySize {
		return errors.New("provider key was not decoded before pinning")
	}
	receiptPath := filepath.Join(
		pendingDirectory, current.receiptName,
	)
	if data, err := securefile.ReadPublicIntegrity(
		receiptPath, 64<<10,
	); err == nil {
		receipt, err := phase1anchor.DecodeReceipt(bytes.NewReader(data))
		if err != nil {
			return err
		}
		return receipt.Verify(
			request, current.id, public, current.previousDigest,
		)
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	// #nosec G204 -- the executable/key/known-hosts paths are explicit
	// administrator inputs; the destination is restricted to a parsed IP and
	// every SSH option is a separate fixed argv element.
	command := exec.CommandContext(
		ctx,
		sshBinary,
		"-T",
		"-F", "/dev/null",
		"-i", sshKey,
		"-o", "BatchMode=yes",
		"-o", "IdentitiesOnly=yes",
		"-o", "StrictHostKeyChecking=yes",
		// /dev/fd/3 in the ssh child, backed by the anonymous snapshot passed
		// through ExtraFiles below. The chain is explicit at both hops:
		// controller -> anchor-pin -> ssh. Nothing here opens a pathname that
		// another process can replace or write through.
		"-o", "UserKnownHostsFile=/dev/fd/3",
		"-o", "GlobalKnownHostsFile=/dev/null",
		"-o", "ClearAllForwardings=yes",
		"-o", "PermitLocalCommand=no",
		"-o", "RequestTTY=no",
		"winn-anchor@"+current.host,
	)
	configurePinnedSSH(command)
	// The snapshot is rewound before every ssh invocation. This function runs
	// once per provider, so a descriptor left at EOF by the first call would
	// hand the second an empty known-hosts file — which ssh reports as an
	// unverifiable host key partway through an irreversible chain.
	if err := securefile.RewindSnapshot(
		knownHostsSnapshot, knownHostsBytes,
	); err != nil {
		return fmt.Errorf("known hosts snapshot: %w", err)
	}
	command.ExtraFiles = []*os.File{knownHostsSnapshot}
	command.Stdin = bytes.NewReader(canonical)
	var stderr bytes.Buffer
	command.Stderr = &stderr
	output, err := command.Output()
	if err != nil {
		if strings.Contains(stderr.String(), "ANCHOR_REJECT:") {
			return fmt.Errorf(
				"provider %s permanently rejected the request: %w",
				current.id, err,
			)
		}
		return temporaryError{err: fmt.Errorf(
			"provider %s transport unavailable: %w",
			current.id, err,
		)}
	}
	if len(output) > 64<<10 {
		return errors.New("provider receipt exceeds 64 KiB")
	}
	receipt, err := phase1anchor.DecodeReceipt(bytes.NewReader(output))
	if err != nil {
		return err
	}
	if err := receipt.Verify(
		request, current.id, public, current.previousDigest,
	); err != nil {
		return err
	}
	// The provider's bytes must ALREADY be the canonical sealed encoding.
	//
	// Verify and Digest both operate on a re-marshal, so a receipt padded with
	// whitespace, reordered, or carrying duplicate object keys verifies
	// perfectly and digests to the same value — and it is those raw bytes that
	// get sealed. The formal verifier then refuses the slot ("anchor receipt
	// bytes are not the canonical sealed encoding"), after two external
	// providers have signed and the chain can no longer be withdrawn.
	//
	// Canonicalising here instead would be worse than refusing: it would seal a
	// document no provider actually sent, and hide a provider emitting
	// non-canonical output for as long as the deviation stayed semantically
	// harmless. The deviation is the signal.
	if err := requireCanonicalReceiptBytes(output, receipt); err != nil {
		return fmt.Errorf("provider %s: %w", current.id, err)
	}
	return createExclusive(receiptPath, output)
}

// requireCanonicalReceiptBytes refuses any receipt encoding other than the
// canonical one plus a single terminating newline — the exact byte form
// cmd/winn-phase1-matrix-verify requires of a sealed slot.
func requireCanonicalReceiptBytes(
	data []byte, receipt phase1anchor.Receipt,
) error {
	canonical, err := receipt.Canonical()
	if err != nil {
		return err
	}
	if !bytes.Equal(data, append(canonical, '\n')) {
		return errors.New(
			"receipt bytes are not the canonical sealed encoding; refusing " +
				"to seal a slot the formal verifier would reject after the " +
				"signatures are irreversible",
		)
	}
	return nil
}

func readPublicKey(path string) (ed25519.PublicKey, error) {
	data, err := securefile.ReadPublicIntegrity(path, 4<<10)
	if err != nil {
		return nil, err
	}
	decoded, err := base64.StdEncoding.DecodeString(
		string(bytes.TrimSpace(data)),
	)
	if err != nil || len(decoded) != ed25519.PublicKeySize {
		return nil, errors.New("provider public key is invalid")
	}
	return ed25519.PublicKey(decoded), nil
}

func ensurePrivateDirectory(path string) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		// #nosec G301 -- 0700 is the required private pending-directory mode.
		if err := os.Mkdir(path, 0o700); err != nil {
			return err
		}
		info, err = os.Lstat(path)
	}
	if err != nil || !info.IsDir() ||
		info.Mode()&os.ModeSymlink != 0 ||
		info.Mode().Perm()&0o077 != 0 {
		return errors.New("pin-pending directory is not private and real")
	}
	return nil
}

func createExclusive(path string, content []byte) error {
	directoryPath := filepath.Dir(path)
	// #nosec G304 -- the directory is the validated private pending
	// directory and the random temporary name is created exclusively.
	file, err := os.CreateTemp(directoryPath, ".anchor-write-*")
	if err != nil {
		return err
	}
	temporary := file.Name()
	defer os.Remove(temporary)
	if err := file.Chmod(0o600); err != nil {
		return errors.Join(err, file.Close())
	}
	if _, err := file.Write(content); err != nil {
		return errors.Join(err, file.Close())
	}
	if err := file.Sync(); err != nil {
		return errors.Join(err, file.Close())
	}
	if err := file.Close(); err != nil {
		return err
	}
	if err := os.Link(temporary, path); err != nil {
		return err
	}
	if err := os.Remove(temporary); err != nil {
		return err
	}
	// #nosec G304 -- directoryPath is the validated private pending directory.
	directory, err := os.Open(directoryPath)
	if err != nil {
		return err
	}
	return errors.Join(directory.Sync(), directory.Close())
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "ANCHOR_PIN_FAIL:", err)
	os.Exit(1)
}

// parsedHostsAreDistinct reports whether two SSH destinations are different
// machines. String inequality is not enough: 127.0.0.1 and ::ffff:127.0.0.1
// parse as the same address, and two receipts from one host are not two anchors.
func parsedHostsAreDistinct(one, two string) bool {
	firstIP := net.ParseIP(one)
	secondIP := net.ParseIP(two)
	return firstIP != nil && secondIP != nil && !firstIP.Equal(secondIP)
}
