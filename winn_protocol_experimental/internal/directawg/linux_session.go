package directawg

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"winsvpn.local/winnprotocol/internal/connectivity"
)

type linuxTunnelSessionConfig struct {
	binding          connectivity.Binding
	status           *CLIStatusSource
	verifier         LinuxProtectedVerifier
	probe            LinuxProbeContext
	route            *linuxRouteTransaction
	policy           LinuxPolicyTransaction
	process          LinuxManagedProcess
	runner           LinuxCommandRunner
	ipBinary         string
	interfaceName    string
	stopTimeout      time.Duration
	refreshHandshake func(context.Context) error
	releasePort      func()
	releaseAddress   func()
}

type linuxTunnelSession struct {
	config linuxTunnelSessionConfig

	commitMu  sync.Mutex
	committed bool

	stateMu    sync.Mutex
	operations int
	zero       chan struct{}

	closing       context.Context
	cancelClosing context.CancelFunc
	closeOnce     sync.Once
	closeGate     chan struct{}

	policyClosed  bool
	routeClosed   bool
	linkClosed    bool
	processClosed bool
	released      bool
	fullyClosed   bool

	health     chan error
	healthOnce sync.Once
}

func newLinuxTunnelSession(
	config linuxTunnelSessionConfig,
) *linuxTunnelSession {
	zero := make(chan struct{})
	close(zero)
	// #nosec G118 -- cancellation is stored on the returned session and
	// invoked exactly once by CloseContext through closeOnce.
	closing, cancelClosing := context.WithCancel(context.Background())
	session := &linuxTunnelSession{
		config:        config,
		zero:          zero,
		closing:       closing,
		cancelClosing: cancelClosing,
		closeGate:     make(chan struct{}, 1),
		health:        make(chan error, 1),
	}
	session.closeGate <- struct{}{}
	go session.watchProcess()
	go session.watchPolicy()
	return session
}

func (session *linuxTunnelSession) Status(
	ctx context.Context,
) (Status, error) {
	operationContext, done, err := session.beginOperation(ctx)
	if err != nil {
		return Status{}, err
	}
	defer done()
	return session.config.status.Status(operationContext)
}

func (session *linuxTunnelSession) RefreshAWGHandshake(
	ctx context.Context,
	binding connectivity.Binding,
) error {
	if binding != session.config.binding {
		return errors.New("linux AWG session binding mismatch")
	}
	if session.config.refreshHandshake == nil {
		return errors.New("linux AWG handshake refresh is unavailable")
	}
	operationContext, done, err := session.beginOperation(ctx)
	if err != nil {
		return err
	}
	defer done()
	return session.config.refreshHandshake(operationContext)
}

func (session *linuxTunnelSession) VerifyProtectedDNS(
	ctx context.Context,
	binding connectivity.Binding,
) error {
	if binding != session.config.binding {
		return errors.New("linux AWG session binding mismatch")
	}
	operationContext, done, err := session.beginOperation(ctx)
	if err != nil {
		return err
	}
	defer done()
	return session.config.verifier.VerifyProtectedDNS(
		operationContext, session.config.probe,
	)
}

func (session *linuxTunnelSession) VerifyTunnelCanary(
	ctx context.Context,
	binding connectivity.Binding,
) error {
	if binding != session.config.binding {
		return errors.New("linux AWG session binding mismatch")
	}
	operationContext, done, err := session.beginOperation(ctx)
	if err != nil {
		return err
	}
	defer done()
	return session.config.verifier.VerifyTunnelCanary(
		operationContext, session.config.probe,
	)
}

func (session *linuxTunnelSession) Commit(
	ctx context.Context,
	binding connectivity.Binding,
) error {
	if binding != session.config.binding {
		return errors.New("linux AWG session binding mismatch")
	}
	operationContext, done, err := session.beginOperation(ctx)
	if err != nil {
		return err
	}
	defer done()
	session.commitMu.Lock()
	defer session.commitMu.Unlock()
	if err := session.available(); err != nil {
		return err
	}
	if session.committed {
		return nil
	}
	if err := session.config.route.Commit(operationContext); err != nil {
		return err
	}
	if err := session.config.policy.Commit(operationContext); err != nil {
		rollbackContext, cancel := context.WithTimeout(
			context.Background(), session.config.stopTimeout,
		)
		defer cancel()
		policyError := session.config.policy.Rollback(rollbackContext)
		routeError := session.config.route.Rollback(rollbackContext)
		return errors.Join(
			fmt.Errorf("commit Linux AWG DNS/kill-switch policy: %w", err),
			policyError,
			routeError,
		)
	}
	session.committed = true
	return nil
}

func (session *linuxTunnelSession) Health() <-chan error {
	return session.health
}

// Close engages/preserves the kill switch through policy rollback before
// removing the route rule, restores DNS, deletes the interface, and stops the
// userspace process. It is synchronous and idempotent.
func (session *linuxTunnelSession) Close() error {
	return session.CloseContext(context.Background())
}

// CloseContext is ordered, retryable, and context bounded. No later teardown
// stage is attempted until policy rollback has successfully engaged the kill
// switch and restored resolver state. A failed or timed-out call leaves the
// remaining state owned by this session so a subsequent call can resume.
func (session *linuxTunnelSession) CloseContext(ctx context.Context) error {
	if ctx == nil {
		return errors.New("linux AWG close context is required")
	}
	session.closeOnce.Do(session.cancelClosing)
	bounded, cancel := context.WithTimeout(ctx, session.config.stopTimeout)
	defer cancel()

	session.stateMu.Lock()
	zero := session.zero
	session.stateMu.Unlock()
	select {
	case <-zero:
	case <-bounded.Done():
		err := context.Cause(bounded)
		session.publishTeardown(err)
		return err
	}
	select {
	case <-bounded.Done():
		err := context.Cause(bounded)
		session.publishTeardown(err)
		return err
	case <-session.closeGate:
	}
	defer func() { session.closeGate <- struct{}{} }()

	if session.fullyClosed {
		return nil
	}
	if !session.policyClosed {
		if err := session.config.policy.Rollback(bounded); err != nil {
			err = fmt.Errorf(
				"roll back Linux AWG DNS/kill-switch policy: %w", err,
			)
			session.publishTeardown(err)
			return err
		}
		session.policyClosed = true
	}
	if !session.routeClosed {
		if err := session.config.route.Rollback(bounded); err != nil {
			err = fmt.Errorf("roll back Linux AWG routes: %w", err)
			session.publishTeardown(err)
			return err
		}
		session.routeClosed = true
	}
	if !session.linkClosed {
		if _, err := session.config.runner.Run(
			bounded,
			LinuxCommand{
				Path: session.config.ipBinary,
				Args: []string{
					"link", "delete", "dev", session.config.interfaceName,
				},
			},
		); err != nil {
			absent, checkErr := session.linkAbsent(bounded)
			if checkErr != nil || !absent {
				err = errors.Join(
					fmt.Errorf("delete Linux AWG interface: %w", err),
					checkErr,
				)
				session.publishTeardown(err)
				return err
			}
		}
		session.linkClosed = true
	}
	if !session.processClosed {
		if err := session.config.process.Stop(bounded); err != nil {
			err = fmt.Errorf("stop Linux AWG process: %w", err)
			session.publishTeardown(err)
			return err
		}
		session.processClosed = true
	}
	if !session.released {
		if session.config.releasePort != nil {
			session.config.releasePort()
		}
		if session.config.releaseAddress != nil {
			session.config.releaseAddress()
		}
		session.released = true
	}
	session.fullyClosed = true
	session.healthOnce.Do(func() { close(session.health) })
	return nil
}

func (session *linuxTunnelSession) linkAbsent(ctx context.Context) (bool, error) {
	result, err := session.config.runner.Run(
		ctx,
		LinuxCommand{
			Path: session.config.ipBinary,
			Args: []string{
				"-j", "link", "show", "dev", session.config.interfaceName,
			},
		},
	)
	if err == nil {
		return false, nil
	}
	want := []byte(
		`Device "` + session.config.interfaceName + `" does not exist.`,
	)
	if len(result.Stdout) == 0 &&
		bytes.Equal(bytes.TrimSpace(result.Stderr), want) {
		return true, nil
	}
	return false, fmt.Errorf("verify deleted Linux AWG interface: %w", err)
}

func (session *linuxTunnelSession) beginOperation(
	ctx context.Context,
) (context.Context, func(), error) {
	if ctx == nil {
		return nil, nil, errors.New(
			"linux AWG session operation context is required",
		)
	}
	if cause := context.Cause(ctx); cause != nil {
		return nil, nil, cause
	}
	session.stateMu.Lock()
	if err := session.available(); err != nil {
		session.stateMu.Unlock()
		return nil, nil, err
	}
	if session.operations == 0 {
		session.zero = make(chan struct{})
	}
	session.operations++
	session.stateMu.Unlock()

	operationContext, cancel := context.WithCancel(ctx)
	stopCloseBridge := context.AfterFunc(session.closing, cancel)
	var once sync.Once
	done := func() {
		once.Do(func() {
			stopCloseBridge()
			cancel()
			session.stateMu.Lock()
			session.operations--
			if session.operations == 0 {
				close(session.zero)
			}
			session.stateMu.Unlock()
		})
	}
	return operationContext, done, nil
}

func (session *linuxTunnelSession) available() error {
	select {
	case <-session.closing.Done():
		return errors.New("linux AWG session is closed")
	default:
	}
	select {
	case <-session.config.process.Exited():
		return linuxProcessExitError(session.config.process)
	default:
		return nil
	}
}

func (session *linuxTunnelSession) publishTeardown(err error) {
	if err == nil {
		return
	}
	session.healthOnce.Do(func() {
		session.health <- fmt.Errorf("linux AWG teardown failed: %w", err)
		close(session.health)
	})
}

func (session *linuxTunnelSession) watchProcess() {
	select {
	case <-session.closing.Done():
		return
	case <-session.config.process.Exited():
		err := session.config.process.Err()
		if err == nil {
			err = errors.New("linux amneziawg-go process exited")
		}
		session.publishHealth(err)
	}
}

func (session *linuxTunnelSession) watchPolicy() {
	select {
	case <-session.closing.Done():
		return
	case err, ok := <-session.config.policy.Health():
		if !ok || err == nil {
			err = errors.New("linux AWG policy health stream terminated")
		}
		session.publishHealth(err)
	}
}

func (session *linuxTunnelSession) publishHealth(err error) {
	if err == nil {
		return
	}
	published := false
	session.healthOnce.Do(func() {
		session.health <- err
		close(session.health)
		published = true
	})
	if published {
		go func() {
			_ = session.Close()
		}()
	}
}

func linuxProcessExitError(process LinuxManagedProcess) error {
	if err := process.Err(); err != nil {
		return fmt.Errorf("linux amneziawg-go process exited: %w", err)
	}
	return errors.New("linux amneziawg-go process exited")
}
