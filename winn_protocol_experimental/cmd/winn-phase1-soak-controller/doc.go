// Command winn-phase1-soak-controller drives the accepted Phase 1 runner
// repeatedly for a bounded wall of time, and records what happened.
//
// # What this is not
//
// This is NOT the production Auto soak, and nothing it writes may be read as
// one. The production soak requires a real multi-gateway topology, a real
// seven-day execution, and a controller-side finalization that happens on a
// different machine. This program is the harness that would drive such a run.
// It has never driven one. Every summary it emits says so, in the artifact
// itself, so that a file found later without this comment still carries the
// disclaimer.
//
// # What it does
//
// One cycle is one invocation of the accepted Phase 1 runner, through an
// injected command contract (see CycleRunner). The controller owns scheduling,
// provenance, crash resumption, resource bounds, and evidence; it owns none of
// the measurement semantics, which stay entirely inside the runner it invokes.
//
// The injection is not a testing convenience bolted on afterwards. It is the
// only way the failure paths below can be exercised at all: a hang, a crash
// mid-cycle, a clock rollback and a duplicate controller cannot be provoked
// against the real runner without a seven-day feedback loop and a lab.
//
// # Custody separation
//
// No finalizer seed and no evidence-signing key may exist on the producing
// host. This program therefore signs nothing, seals no terminal checkpoint,
// and creates no anchor artifact. Its own crash-resume checkpoint is
// authenticated with a run-local key whose only claim is "this controller
// wrote this file"; see checkpoint.go for exactly what that does and does not
// establish. Controller finalization happens later, elsewhere, over retrieved
// evidence, and is deliberately not implemented here.
//
// # Operational surface
//
//	-preflight        run every gate, report, run no cycles
//	-dry-run          preflight plus the planned schedule, run no cycles
//	-run              the soak itself
//	-print-systemd-command
//	                  print the systemd-run invocation an operator would use
//
// The last of those prints a command. It does not execute one. This program
// never invokes systemctl or systemd-run; systemdunit.go does not import
// os/exec, and a test enforces that.
package main
