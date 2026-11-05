//go:build darwin

package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"runtime"

	"golang.org/x/sys/unix"
)

func main() {
	var c config
	var fault string
	flag.StringVar(&c.Candidate, "candidate", "", "frozen candidate repo root (clean absolute path)")
	flag.StringVar(&c.Canonical, "canonical", "", "canonical root (clean absolute path)")
	flag.StringVar(&c.Manifest, "manifest", "", "accepted manifest (clean absolute path)")
	flag.StringVar(&c.Receipt, "receipt", "", "external recovery receipt (clean absolute path)")
	flag.BoolVar(&c.Execute, "execute", false, "perform guarded transaction; default is read-only")
	flag.StringVar(&c.Ack, "ack", "", "exact execution acknowledgement")
	flag.BoolVar(&c.TestMode, "test-mode", false, "enable private-tree process-death injection")
	flag.StringVar(&fault, "fault-at", "", "test-only SIGKILL mutation boundary ordinal")
	flag.Parse()
	var err error
	c.FaultAt, err = parseFault(fault)
	if err == nil {
		err = run(c)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "STOP:", err)
		os.Exit(1)
	}
}

func run(c config) error {
	if runtime.GOOS != "darwin" {
		return errors.New("terminal platform blocker: R2 is implemented only for verified Darwin descriptor-relative semantics")
	}
	if c.Candidate == "" || c.Canonical == "" || c.Manifest == "" || c.Receipt == "" {
		return errors.New("--candidate, --canonical, --manifest, and --receipt are required")
	}
	if c.Execute && c.Ack != ackText {
		return fmt.Errorf("--execute requires --ack %q", ackText)
	}
	if c.FaultAt != 0 && (!c.TestMode || len(c.Canonical) < len("/private/tmp/") ||
		c.Canonical[:len("/private/tmp/")] != "/private/tmp/") {
		return errors.New("fault injection requires --test-mode and canonical beneath /private/tmp")
	}
	t, err := newTransaction(c)
	if err != nil {
		return err
	}
	defer t.close()
	exists, err := t.ledgerExists()
	if err != nil {
		return err
	}
	if exists {
		if !c.Execute {
			return errors.New("existing ledger requires --execute with the execution acknowledgement before recovery or cleanup")
		}
		if err := t.bindExistingLedger(); err != nil {
			return err
		}
		if terminalLedger(t.log.events) {
			if err := t.verifyFinal(); err != nil {
				return fmt.Errorf("terminal-ledger idempotency verification: %w", err)
			}
			if err := t.finishSuccessCleanupIdempotent(); err != nil {
				return fmt.Errorf("terminal-ledger cleanup verification: %w", err)
			}
			fmt.Printf("PROMOTION RECOVERY PASS: source19=%s production18=%s receipt=%s\n", expectedAllSHA, expectedProdSHA, c.Receipt)
			return nil
		}
		if commitDecided(t.log.events) {
			if err := t.verifyFinal(); err != nil {
				return fmt.Errorf("commit-decided recovery final verification: %w", err)
			}
			if err := t.finishSuccessCleanup(); err != nil {
				return fmt.Errorf("commit-decided recovery cleanup: %w", err)
			}
			fmt.Printf("PROMOTION RECOVERY PASS: source19=%s production18=%s receipt=%s\n", expectedAllSHA, expectedProdSHA, c.Receipt)
			return nil
		}
		return t.recover(errors.New("restart recovery from nonterminal durable ledger"))
	}
	if err := t.preflight(); err != nil {
		return err
	}
	if !c.Execute {
		fmt.Printf("DRY-RUN PASS: source19=%s production18=%s; descriptor-pinned exact E7 state\n", expectedAllSHA, expectedProdSHA)
		return nil
	}
	if err := t.execute(); err != nil {
		return err
	}
	fmt.Printf("PROMOTION PASS: source19=%s production18=%s receipt=%s\n", expectedAllSHA, expectedProdSHA, c.Receipt)
	return nil
}

func commitDecided(es []event) bool {
	for _, e := range es {
		if e.Phase == "decision" && e.Op == "commit-decided" {
			return true
		}
	}
	return false
}

func terminalLedger(es []event) bool {
	for _, e := range es {
		if e.Phase == "terminal" {
			return true
		}
	}
	return false
}

var _ = unix.RENAME_SWAP
