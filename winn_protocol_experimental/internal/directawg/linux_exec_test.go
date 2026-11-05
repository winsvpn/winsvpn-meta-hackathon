package directawg

import (
	"context"
	"testing"
	"time"
)

func TestExecLinuxProcessDeadlineEscalationProvesStopped(t *testing.T) {
	runner := execLinuxRunner{}
	managed, err := runner.Start(LinuxCommand{
		Path: "/bin/sh",
		Args: []string{
			"-c",
			"trap '' INT; while :; do :; done",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	process := managed.(*execLinuxProcess)
	// Give the shell time to install its SIGINT disposition so Stop must use
	// the already-expired context to escalate to SIGKILL.
	time.Sleep(20 * time.Millisecond)
	expired, cancel := context.WithCancel(context.Background())
	cancel()
	if err := process.Stop(expired); err != nil {
		t.Fatalf("Stop() after confirmed forced exit = %v", err)
	}
	select {
	case <-process.Exited():
	default:
		t.Fatal("Stop() returned without a confirmed process exit")
	}
	if err := process.Stop(context.Background()); err != nil {
		t.Fatalf("idempotent Stop() error = %v", err)
	}
}
