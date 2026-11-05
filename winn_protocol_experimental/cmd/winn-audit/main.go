// Command winn-audit verifies a tamper-evident audit log and operates the
// terminal checkpoint that closes one.
//
// Three roles, deliberately separated:
//
//	default          verify an audit log's HMAC chain. Needs the audit key.
//	-seal-checkpoint create the terminal checkpoint over a closed log and a
//	                 sealed manifest. Needs the finalizer seed and NOT the
//	                 audit key.
//	-verify-checkpoint
//	                 recompute every bound field and check the finalizer
//	                 signature. Needs no secret at all.
//	-detect-finalizer-leaks
//	                 scan this host for finalizer material left where the audit
//	                 writer could read it. Run BEFORE the writer starts. This
//	                 finds known mistakes; it does not prove absence.
//
// The finalizer seed belongs to the controller. It must never exist on the host
// that writes audit records: the checkpoint exists to constrain exactly that
// party, and on a host where the writer runs as root, file modes and scrubbed
// environments protect nothing — root reads any root-owned file.
//
// The separation is therefore machine-level, and it comes from provisioning:
// the seed is never transferred to the producing host, and the controller that
// holds it is a different machine with a different identity.
// -detect-finalizer-leaks is a secondary check for the obvious ways that
// discipline gets broken; a clean result is not proof of absence and must never
// be reported as one. -finalizer-keygen and -finalizer-key-id exist so the
// controller can provision the keypair and publish only its public identity.
package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"winsvpn.local/winnprotocol/internal/audit"
	"winsvpn.local/winnprotocol/internal/auditcheckpoint"
	"winsvpn.local/winnprotocol/internal/closedarchive"
	"winsvpn.local/winnprotocol/internal/securefile"
)

func main() {
	var logPath string
	var keyPath string
	var sealCheckpoint bool
	var verifyCheckpoint bool
	var keygen bool
	var printKeyID bool
	var detectLeaks bool
	var custodyScan string
	var publishArchive bool
	var archiveDestination string
	var evidenceDirectory string
	var auditLogName string
	var manifestName string
	var runID string
	var producerDigest string
	var finalizerSeed string
	var finalizerKeyID string
	flag.StringVar(&logPath, "audit-log", "", "tamper-evident JSONL audit log path")
	flag.StringVar(&keyPath, "audit-key", "", "32-byte HMAC audit key path")
	flag.BoolVar(
		&sealCheckpoint, "seal-checkpoint", false,
		"create the winn-audit-checkpoint/v1 terminal record for sealed evidence",
	)
	flag.BoolVar(
		&verifyCheckpoint, "verify-checkpoint", false,
		"verify the winn-audit-checkpoint/v1 terminal record of sealed evidence",
	)
	flag.BoolVar(
		&keygen, "finalizer-keygen", false,
		"generate a new runner-only ML-DSA-65 finalizer seed",
	)
	flag.BoolVar(
		&printKeyID, "finalizer-key-id", false,
		"print the finalizer key identity of an existing seed",
	)
	flag.BoolVar(
		&detectLeaks, "detect-finalizer-leaks", false,
		"scan this host for audit finalizer material the writer could read; "+
			"finds known mistakes, does not prove absence",
	)
	flag.BoolVar(
		&publishArchive, "publish-closed-archive", false,
		"publish the single atomic closed archive over a closed evidence directory",
	)
	flag.StringVar(
		&archiveDestination, "closed-archive", "",
		"destination path for the closed archive",
	)
	flag.StringVar(
		&custodyScan, "custody-scan", "",
		"colon-separated directories to scan; an unreadable one fails closed",
	)
	flag.StringVar(
		&evidenceDirectory, "evidence-dir", "",
		"sealed evidence directory holding the audit log and manifest",
	)
	flag.StringVar(
		&auditLogName, "audit-log-name", "carrier-audit.jsonl",
		"audit log basename inside the evidence directory",
	)
	flag.StringVar(
		&manifestName, "manifest-name", "evidence-manifest.sha256",
		"base evidence manifest basename; must not cover the checkpoint",
	)
	flag.StringVar(&runID, "run-id", "", "this run's identity")
	flag.StringVar(
		&producerDigest, "producer-digest", "",
		"required producer/source digest; must match the sealed environment",
	)
	flag.StringVar(
		&finalizerSeed, "finalizer-seed", "",
		"runner-only ML-DSA-65 finalizer seed path",
	)
	flag.StringVar(
		&finalizerKeyID, "finalizer-key-id-pin", "",
		"pinned finalizer key identity the checkpoint must be signed by",
	)
	flag.Parse()

	modes := 0
	for _, enabled := range []bool{
		sealCheckpoint, verifyCheckpoint, keygen, printKeyID, detectLeaks,
		publishArchive,
	} {
		if enabled {
			modes++
		}
	}
	if modes > 1 {
		exitError("checkpoint modes are mutually exclusive")
	}

	switch {
	case publishArchive:
		// Publication lives in Go because the three things that make it correct
		// are things a shell cannot do: a real fsync before the artifact
		// becomes visible, a single all-or-nothing publication step, and an
		// existence test that sees a dangling symlink. The shell version
		// claimed the first, used two separate link() calls for the second, and
		// used [ -e ] for the third.
		result, err := closedarchive.Publish(closedarchive.Input{
			EvidenceDirectory: evidenceDirectory,
			Destination:       archiveDestination,
		})
		if err != nil {
			exitError(err.Error())
		}
		fmt.Printf(
			"{\"status\":\"closed-archive-published\",\"path\":%q,"+
				"\"sha256\":%q,\"already_published\":%t}\n",
			result.Destination, result.SHA256, result.AlreadyPublished,
		)
	case detectLeaks:
		if err := auditcheckpoint.DetectKnownFinalizerLeaks(
			filepath.SplitList(custodyScan), os.Environ(),
		); err != nil {
			exitError(err.Error())
		}
		fmt.Println(
			`{"status":"no-known-finalizer-leaks-found",` +
				`"note":"scan of the named roots only; not proof of absence"}`,
		)
	case keygen:
		if err := generateFinalizerSeed(finalizerSeed); err != nil {
			exitError(err.Error())
		}
	case printKeyID:
		identity, err := auditcheckpoint.KeyIDFromSeedFile(finalizerSeed)
		if err != nil {
			exitError(err.Error())
		}
		fmt.Printf("{\"finalizer_key_id\":%q}\n", identity)
	case sealCheckpoint:
		if err := seal(
			evidenceDirectory, auditLogName, manifestName, runID,
			producerDigest, finalizerSeed,
		); err != nil {
			exitError(err.Error())
		}
	case verifyCheckpoint:
		if err := verify(
			evidenceDirectory, auditLogName, runID, producerDigest,
			finalizerKeyID,
		); err != nil {
			exitError(err.Error())
		}
	default:
		if logPath == "" || keyPath == "" {
			exitError("-audit-log and -audit-key are required")
		}
		if err := audit.Verify(logPath, keyPath); err != nil {
			exitError(err.Error())
		}
		fmt.Println(`{"status":"verified"}`)
	}
}

// generateFinalizerSeed writes a fresh finalizer seed and prints only its
// public identity, so the pin an auditor is given never travels with the
// secret that produces it.
func generateFinalizerSeed(path string) error {
	if path == "" {
		return errors.New("-finalizer-seed is required")
	}
	seed, err := auditcheckpoint.GenerateFinalizerSeed()
	if err != nil {
		return err
	}
	defer clear(seed)
	// Create-once. An Lstat-then-write would leave a window in which a
	// concurrent keygen silently replaces the credential every existing
	// checkpoint was signed with; O_EXCL closes it in the kernel.
	if err := securefile.AtomicWriteNew(path, seed, 0o600); err != nil {
		return fmt.Errorf(
			"refusing to create the finalizer seed: %w; an existing seed is "+
				"the credential existing checkpoints were signed with and is "+
				"never replaced automatically", err,
		)
	}
	identity, err := auditcheckpoint.KeyIDFromSeedFile(path)
	if err != nil {
		return err
	}
	fmt.Printf(
		"{\"status\":\"finalizer-seed-created\",\"finalizer_key_id\":%q}\n",
		identity,
	)
	return nil
}

// verify runs the checkpoint verification exactly as an offline auditor does.
// It needs no secret: the finalizer credential is asymmetric, so the only
// inputs are the evidence and three externally-supplied expectations. All three
// are mandatory, enforced by internal/auditcheckpoint itself rather than here,
// so reaching the library or this command directly does not relax anything.
func verify(
	evidenceDirectory, auditLogName, runID, producerDigest,
	finalizerKeyID string,
) error {
	checkpoint, err := auditcheckpoint.Verify(auditcheckpoint.VerifyInput{
		EvidenceDirectory:      evidenceDirectory,
		ExpectedFinalizerKeyID: finalizerKeyID,
		ExpectedRunID:          runID,
		ExpectedProducerDigest: producerDigest,
		AuditLogName:           auditLogName,
	})
	if err != nil {
		return err
	}
	fmt.Printf(
		"{\"status\":\"checkpoint-verified\",\"run_id\":%q,"+
			"\"record_count\":%d,\"chain_head_mac\":%q}\n",
		checkpoint.RunID, checkpoint.RecordCount, checkpoint.ChainHeadMAC,
	)
	return nil
}

func seal(
	evidenceDirectory, auditLogName, manifestName, runID,
	producerDigest, finalizerSeed string,
) error {
	if finalizerSeed == "" {
		return errors.New("-finalizer-seed is required to seal a checkpoint")
	}
	signer, err := auditcheckpoint.LoadFinalizer(finalizerSeed)
	if err != nil {
		return err
	}
	defer signer.Destroy()
	checkpoint, err := auditcheckpoint.Seal(auditcheckpoint.SealInput{
		EvidenceDirectory: evidenceDirectory,
		AuditLogName:      auditLogName,
		ManifestName:      manifestName,
		RunID:             runID,
		ProducerDigest:    producerDigest,
		Signer:            signer,
	})
	if err != nil {
		return err
	}
	fmt.Printf(
		"{\"status\":\"checkpoint-sealed\",\"run_id\":%q,\"record_count\":%d,"+
			"\"chain_head_mac\":%q,\"finalizer_key_id\":%q}\n",
		checkpoint.RunID, checkpoint.RecordCount, checkpoint.ChainHeadMAC,
		checkpoint.FinalizerKeyID,
	)
	return nil
}

func exitError(message string) {
	fmt.Fprintln(os.Stderr, "winn-audit:", message)
	os.Exit(1)
}
