package directawg

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
)

const (
	linuxPolicyAnchorOperationTimeout = 3 * time.Second
	linuxPolicyAnchorCleanupRetry     = 50 * time.Millisecond
)

var ErrLinuxPolicyAnchorUnsupported = errors.New(
	"linux underlay policy anchor is unsupported on this platform",
)

// LinuxUnderlayPolicyAnchorSpec binds a preparation-time lease to the exact
// fail-closed policy contract later consumed by the H3 underlay authorizer.
// The expiry is mandatory; an expired anchor cleans itself up.
type LinuxUnderlayPolicyAnchorSpec struct {
	TableFamily           string
	TableName             string
	OutputChain           string
	UnderlayInterface     string
	DirectAWGUnderlayMark uint32
	ExpiresAt             time.Time
}

// LinuxUnderlayPolicyAnchorResource owns one reference to the shared underlay
// interface and DirectAWG anchor mark. Close is synchronous, bounded,
// idempotent, concurrent-safe, and retryable after a failed cleanup.
type LinuxUnderlayPolicyAnchorResource interface {
	Close(context.Context) error
}

// LinuxUnderlayPolicyAnchorLease carries the exact policy values a preparation
// manager must pass to its H3 underlay authorizer while retaining Resource for
// at least the same lifetime.
type LinuxUnderlayPolicyAnchorLease struct {
	TableFamily           string
	TableName             string
	OutputChain           string
	UnderlayInterface     string
	DirectAWGUnderlayMark uint32
	ExpiresAt             time.Time
	Resource              LinuxUnderlayPolicyAnchorResource
}

type linuxUnderlayPolicyAnchor struct {
	factory *LinuxNftResolvedPolicyFactory
	id      uint64

	closeMu    sync.Mutex
	closed     bool
	expiry     *time.Timer
	retryTimer *time.Timer
}

var _ LinuxUnderlayPolicyAnchorResource = (*linuxUnderlayPolicyAnchor)(nil)

func (factory *LinuxNftResolvedPolicyFactory) prepareUnderlayPolicyAnchor(
	ctx context.Context,
	spec LinuxUnderlayPolicyAnchorSpec,
) (LinuxUnderlayPolicyAnchorLease, error) {
	if factory == nil {
		return LinuxUnderlayPolicyAnchorLease{},
			errors.New("linux policy factory is nil")
	}
	if ctx == nil {
		return LinuxUnderlayPolicyAnchorLease{},
			errors.New("linux underlay policy anchor context is required")
	}
	now := time.Now().UTC()
	spec.ExpiresAt = spec.ExpiresAt.UTC()
	if err := factory.validateAnchorSpec(spec, now); err != nil {
		return LinuxUnderlayPolicyAnchorLease{}, err
	}
	operationContext, cancel := boundedAnchorPrepareContext(
		ctx, spec.ExpiresAt,
	)
	defer cancel()
	if cause := context.Cause(operationContext); cause != nil {
		return LinuxUnderlayPolicyAnchorLease{}, cause
	}

	factory.mu.Lock()
	defer factory.mu.Unlock()
	if cause := context.Cause(operationContext); cause != nil {
		return LinuxUnderlayPolicyAnchorLease{}, cause
	}
	if factory.released {
		return LinuxUnderlayPolicyAnchorLease{},
			errors.New("linux policy factory was released")
	}
	installedHere := false
	if !factory.installed {
		if err := factory.batch.Run(
			operationContext, factory.installBatch(),
		); err != nil {
			return LinuxUnderlayPolicyAnchorLease{}, fmt.Errorf(
				"install anchored fail-closed nftables policy: %w", err,
			)
		}
		factory.installed = true
		installedHere = true
	}
	addedUnderlay := factory.underlayReferences == 0
	if addedUnderlay {
		if err := factory.batch.Run(
			operationContext, factory.addUnderlayBatch(),
		); err != nil {
			cleanupError := factory.cleanupFailedAnchorPrepare(
				installedHere, false,
			)
			return LinuxUnderlayPolicyAnchorLease{}, errors.Join(
				fmt.Errorf("pin Linux policy underlay anchor: %w", err),
				cleanupError,
			)
		}
	}
	if err := factory.verifyUnderlayPolicyAnchor(
		operationContext,
	); err != nil {
		cleanupError := factory.cleanupFailedAnchorPrepare(
			installedHere, addedUnderlay,
		)
		return LinuxUnderlayPolicyAnchorLease{}, errors.Join(
			err, cleanupError,
		)
	}
	if cause := context.Cause(operationContext); cause != nil {
		cleanupError := factory.cleanupFailedAnchorPrepare(
			installedHere, addedUnderlay,
		)
		return LinuxUnderlayPolicyAnchorLease{}, errors.Join(
			cause, cleanupError,
		)
	}

	factory.anchorCounter++
	anchor := &linuxUnderlayPolicyAnchor{
		factory: factory,
		id:      factory.anchorCounter,
	}
	if factory.anchors == nil {
		factory.anchors = make(map[uint64]*linuxUnderlayPolicyAnchor)
	}
	factory.anchors[anchor.id] = anchor
	factory.underlayReferences++
	anchor.expiry = time.AfterFunc(
		time.Until(spec.ExpiresAt),
		anchor.expire,
	)
	return LinuxUnderlayPolicyAnchorLease{
		TableFamily:           spec.TableFamily,
		TableName:             spec.TableName,
		OutputChain:           spec.OutputChain,
		UnderlayInterface:     spec.UnderlayInterface,
		DirectAWGUnderlayMark: spec.DirectAWGUnderlayMark,
		ExpiresAt:             spec.ExpiresAt,
		Resource:              anchor,
	}, nil
}

func (factory *LinuxNftResolvedPolicyFactory) validateAnchorSpec(
	spec LinuxUnderlayPolicyAnchorSpec,
	now time.Time,
) error {
	if spec.TableFamily != "inet" ||
		spec.TableName != factory.config.TableName ||
		spec.OutputChain != "output" ||
		spec.UnderlayInterface != factory.config.UnderlayInterface ||
		spec.DirectAWGUnderlayMark != factory.config.UnderlayMark {
		return errors.New(
			"linux underlay policy anchor differs from its factory contract",
		)
	}
	if !spec.ExpiresAt.After(now) {
		return errors.New(
			"linux underlay policy anchor expiry is invalid",
		)
	}
	return nil
}

func boundedAnchorPrepareContext(
	ctx context.Context,
	expiresAt time.Time,
) (context.Context, context.CancelFunc) {
	deadline := time.Now().Add(linuxPolicyAnchorOperationTimeout)
	if expiresAt.Before(deadline) {
		deadline = expiresAt
	}
	return context.WithDeadline(ctx, deadline)
}

func (factory *LinuxNftResolvedPolicyFactory) cleanupFailedAnchorPrepare(
	installedHere bool,
	addedUnderlay bool,
) error {
	ctx, cancel := context.WithTimeout(
		context.Background(), linuxPolicyAnchorOperationTimeout,
	)
	defer cancel()
	var cleanupError error
	if addedUnderlay {
		cleanupError = factory.batch.Run(
			ctx, factory.removeUnderlayBatch(),
		)
	}
	if installedHere && cleanupError == nil {
		tableError := factory.batch.Run(
			ctx,
			fmt.Sprintf(
				"delete table inet %s\n", factory.config.TableName,
			),
		)
		if tableError == nil {
			factory.installed = false
		}
		cleanupError = errors.Join(cleanupError, tableError)
	}
	if cleanupError != nil {
		return fmt.Errorf(
			"clean up failed Linux underlay policy anchor: %w",
			cleanupError,
		)
	}
	return nil
}

func (factory *LinuxNftResolvedPolicyFactory) verifyUnderlayPolicyAnchor(
	ctx context.Context,
) error {
	result, err := factory.config.Runner.Run(
		ctx,
		LinuxCommand{
			Path: factory.config.NftBinary,
			Args: []string{
				"list", "chain", "inet",
				factory.config.TableName, "output",
			},
		},
	)
	if err != nil {
		return fmt.Errorf(
			"read anchored Linux fail-closed chain: %w", err,
		)
	}
	chain := string(result.Stdout)
	for _, required := range []string{
		"policy drop",
		"meta mark @underlay_marks",
		"oifname @underlay_ifaces",
		"accept",
	} {
		if !strings.Contains(chain, required) {
			return fmt.Errorf(
				"anchored Linux fail-closed chain is missing %q",
				required,
			)
		}
	}
	if err := factory.verifyAnchorSet(
		ctx,
		"tunnel_ifaces",
		"type ifname",
		"",
	); err != nil {
		return err
	}
	if err := factory.verifyAnchorSet(
		ctx,
		"underlay_ifaces",
		"type ifname",
		quotedNftElement(factory.config.UnderlayInterface),
	); err != nil {
		return err
	}
	return factory.verifyAnchorSet(
		ctx,
		"underlay_marks",
		"type mark",
		linuxPolicyMark(factory.config.UnderlayMark),
	)
}

func (factory *LinuxNftResolvedPolicyFactory) verifyAnchorSet(
	ctx context.Context,
	setName string,
	dataType string,
	element string,
) error {
	result, err := factory.config.Runner.Run(
		ctx,
		LinuxCommand{
			Path: factory.config.NftBinary,
			Args: []string{
				"list", "set", "inet",
				factory.config.TableName, setName,
			},
		},
	)
	if err != nil {
		return fmt.Errorf(
			"read anchored Linux nftables set %s: %w",
			setName, err,
		)
	}
	output := string(result.Stdout)
	if !strings.Contains(output, dataType) ||
		(element != "" && !strings.Contains(output, element)) {
		return fmt.Errorf(
			"anchored Linux nftables set %s has the wrong type or membership",
			setName,
		)
	}
	return nil
}

func (anchor *linuxUnderlayPolicyAnchor) Close(
	ctx context.Context,
) error {
	if anchor == nil || anchor.factory == nil {
		return nil
	}
	if ctx == nil {
		return errors.New(
			"linux underlay policy anchor close context is required",
		)
	}
	bounded, cancel := context.WithTimeout(
		ctx, linuxPolicyAnchorOperationTimeout,
	)
	defer cancel()
	anchor.closeMu.Lock()
	defer anchor.closeMu.Unlock()
	if anchor.closed {
		return nil
	}
	if cause := context.Cause(bounded); cause != nil {
		return cause
	}

	factory := anchor.factory
	factory.mu.Lock()
	defer factory.mu.Unlock()
	current, ok := factory.anchors[anchor.id]
	if !ok || current != anchor {
		anchor.markClosedLocked()
		return nil
	}
	if factory.underlayReferences == 0 {
		return errors.New(
			"linux underlay policy anchor reference state is invalid",
		)
	}
	if factory.underlayReferences == 1 {
		if err := factory.batch.Run(
			bounded, factory.removeUnderlayBatch(),
		); err != nil {
			return fmt.Errorf(
				"remove Linux underlay policy anchor: %w", err,
			)
		}
	}
	factory.underlayReferences--
	delete(factory.anchors, anchor.id)
	anchor.markClosedLocked()
	return nil
}

func (anchor *linuxUnderlayPolicyAnchor) markClosedLocked() {
	anchor.closed = true
	if anchor.expiry != nil {
		anchor.expiry.Stop()
	}
	if anchor.retryTimer != nil {
		anchor.retryTimer.Stop()
		anchor.retryTimer = nil
	}
}

func (anchor *linuxUnderlayPolicyAnchor) expire() {
	ctx, cancel := context.WithTimeout(
		context.Background(), linuxPolicyAnchorOperationTimeout,
	)
	err := anchor.Close(ctx)
	cancel()
	if err != nil {
		anchor.scheduleCleanupRetry()
	}
}

func (anchor *linuxUnderlayPolicyAnchor) scheduleCleanupRetry() {
	anchor.closeMu.Lock()
	defer anchor.closeMu.Unlock()
	if anchor.closed || anchor.retryTimer != nil {
		return
	}
	anchor.retryTimer = time.AfterFunc(
		linuxPolicyAnchorCleanupRetry,
		func() {
			anchor.closeMu.Lock()
			anchor.retryTimer = nil
			closed := anchor.closed
			anchor.closeMu.Unlock()
			if !closed {
				anchor.expire()
			}
		},
	)
}
